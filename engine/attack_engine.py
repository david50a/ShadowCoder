"""
ShadowCoder — Attack Simulation Engine
Orchestrates payload generation, execution simulation, and attack graph building.
"""

import ast
import json
import time
import logging
from dataclasses import dataclass, field, asdict
from typing import Optional
from enum import Enum

from .static_analyzer import StaticAnalyzer, Vulnerability
from .payload_generator import PayloadGenerator
from .execution_simulator import ExecutionSimulator
from .attack_graph import AttackGraphBuilder
from .ollama_client import OllamaClient
from .reporter import Reporter

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(name)s  %(message)s")
log = logging.getLogger("shadowcoder.engine")


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class AttackResult:
    vulnerability: Vulnerability
    payloads: list[dict]
    simulation: dict
    ai_analysis: str
    severity: Severity
    exploitable: bool
    chain_ids: list[str] = field(default_factory=list)


@dataclass
class ScanReport:
    target_file: str
    source_code: str
    scan_time_ms: int
    vulnerabilities_found: int
    exploitable_count: int
    attack_results: list[AttackResult]
    attack_chains: list[dict]
    summary: str


class AttackEngine:
    """
    Top-level orchestrator for ShadowCoder's attack simulation pipeline.

    Pipeline:
        source code
            → StaticAnalyzer      (AST-based vuln detection)
            → PayloadGenerator    (exploit payload crafting)
            → ExecutionSimulator  (sandboxed execution tracing)
            → AttackGraphBuilder  (chain multi-step exploits)
            → OllamaClient        (AI enrichment via local LLM)
            → Reporter            (structured JSON + human report)
    """

    def __init__(self, model: str = "llama3", ollama_url: str = "http://localhost:11434"):
        self.analyzer = StaticAnalyzer()
        self.payload_gen = PayloadGenerator()
        self.simulator = ExecutionSimulator()
        self.graph_builder = AttackGraphBuilder()
        self.ai = OllamaClient(model=model, base_url=ollama_url)
        self.reporter = Reporter()

    def scan(self, source_code: str, filename: str = "<stdin>") -> ScanReport:
        """Run the full attack simulation pipeline on Python source code."""
        log.info(f"Starting scan of {filename}")
        t0 = time.perf_counter()

        # ── Stage 0: Parse AST ──────────────────────────────────────────────
        try:
            tree = ast.parse(source_code, filename=filename)
        except SyntaxError as e:
            log.warning(f"Syntax error in {filename}: {e}")
            tree = None

        # ── Stage 1: Static Analysis ──────────────────────────────────────────
        vulns = self.analyzer.analyze(source_code, filename, tree=tree)
        log.info(f"  Static analyzer found {len(vulns)} vulnerabilities")

        if not vulns:
            elapsed = int((time.perf_counter() - t0) * 1000)
            return ScanReport(
                target_file=filename,
                source_code=source_code,
                scan_time_ms=max(1, elapsed),
                vulnerabilities_found=0,
                exploitable_count=0,
                attack_results=[],
                attack_chains=[],
                summary="No vulnerabilities detected.",
            )

        # ── Stage 2: Payload Generation + Execution Simulation ───────────────
        attack_results: list[AttackResult] = []
        is_ai_enabled = self.ai._is_available()
        
        for vuln in vulns:
            payloads = self.payload_gen.generate(vuln)
            simulation = self.simulator.simulate(vuln, payloads, source_code, tree=tree)
            exploitable = simulation.get("exploitable", False)

            # ── Stage 3: AI Enrichment (Ollama) ──────────────────────────────
            ai_text = "[AI enrichment disabled]"
            if is_ai_enabled:
                ai_text = self.ai.enrich(vuln, payloads, simulation)

            severity = self._escalate_severity(vuln.severity, simulation)
            attack_results.append(
                AttackResult(
                    vulnerability=vuln,
                    payloads=payloads,
                    simulation=simulation,
                    ai_analysis=ai_text,
                    severity=severity,
                    exploitable=exploitable,
                )
            )

        # ── Stage 4: Attack Graph (chaining) ─────────────────────────────────
        chains = self.graph_builder.build(attack_results)
        for chain in chains:
            for node_id in chain["node_ids"]:
                for ar in attack_results:
                    if ar.vulnerability.vuln_id == node_id:
                        ar.chain_ids.append(chain["chain_id"])

        # ── Stage 5: Report ───────────────────────────────────────────────────
        elapsed = int((time.perf_counter() - t0) * 1000)
        exploitable_count = sum(1 for ar in attack_results if ar.exploitable)
        
        summary = "[AI summary disabled]"
        if is_ai_enabled:
            summary = self.ai.summarize([ar.vulnerability for ar in attack_results])

        report = ScanReport(
            target_file=filename,
            source_code=source_code,
            scan_time_ms=max(1, elapsed),
            vulnerabilities_found=len(vulns),
            exploitable_count=exploitable_count,
            attack_results=attack_results,
            attack_chains=chains,
            summary=summary,
        )
        log.info(f"  Scan complete in {elapsed}ms — {exploitable_count}/{len(vulns)} exploitable")
        return report

    def _escalate_severity(self, base: str, simulation: dict) -> Severity:
        """Escalate severity if simulation confirms active exploitation path."""
        escalation_map = {
            "LOW": Severity.MEDIUM,
            "MEDIUM": Severity.HIGH,
            "HIGH": Severity.CRITICAL,
            "CRITICAL": Severity.CRITICAL,
        }
        if simulation.get("exploitable") and simulation.get("data_exfil_possible"):
            return escalation_map.get(base, Severity.HIGH)
        return Severity[base] if base in Severity.__members__ else Severity.MEDIUM
