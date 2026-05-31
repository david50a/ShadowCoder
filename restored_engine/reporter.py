"""
Reporter — formats ScanReport into human-readable terminal output and JSON.
"""

import json
import textwrap
from datetime import datetime, timezone
from dataclasses import asdict
from typing import Any


SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪",
}

SEPARATOR = "─" * 72


class Reporter:
    def print_report(self, report) -> None:
        """Print a formatted terminal report."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        print(f"\n{'═' * 72}")
        print(f"  ⚔️  SHADOWCODER ATTACK SIMULATION REPORT")
        print(f"  File: {report.target_file}")
        print(f"  Scan: {now}  ({report.scan_time_ms}ms)")
        print(f"{'═' * 72}")

        if not report.attack_results:
            print("\n  ✅ No vulnerabilities detected.\n")
            return

        print(f"\n  Vulnerabilities:  {report.vulnerabilities_found}")
        print(f"  Exploitable:      {report.exploitable_count}")
        print(f"  Attack chains:    {len(report.attack_chains)}")
        print(f"\n  Summary: {report.summary}\n")

        # ── Findings ──────────────────────────────────────────────────────────
        print(SEPARATOR)
        print("  FINDINGS")
        print(SEPARATOR)
        for ar in report.attack_results:
            v = ar.vulnerability
            icon = SEVERITY_ICONS.get(ar.severity.value if hasattr(ar.severity, 'value') else ar.severity, "⚪")
            print(f"\n  {icon} [{ar.severity}] {v.vuln_type}")
            print(f"     Line {v.line}  ·  {v.cwe}  ·  {v.owasp}  ·  confidence {v.confidence:.0%}")
            print(f"     {v.description}")
            print(f"\n     Code:  {v.code_snippet[:120]}")
            if ar.simulation.get("taint_flow"):
                print(f"\n     Taint flow:")
                for step in ar.simulation["taint_flow"][:4]:
                    print(f"       → {step}")
            if ar.payloads:
                p = ar.payloads[0]
                print(f"\n     Top payload: {p['raw'][:100]}")
                print(f"     Impact:      {p['impact']}")
                if p.get("bypasses"):
                    print(f"     WAF bypass:  {p['bypasses'][0][:80]}")
            if ar.simulation.get("blast_radius"):
                print(f"\n     Blast radius: {ar.simulation['blast_radius']}")
            if ar.ai_analysis and not ar.ai_analysis.startswith("["):
                wrapped = textwrap.fill(ar.ai_analysis, width=65, initial_indent="     ", subsequent_indent="     ")
                print(f"\n     AI analysis:\n{wrapped}")
            if ar.chain_ids:
                print(f"\n     Part of chains: {', '.join(ar.chain_ids)}")

        # ── Attack Chains ─────────────────────────────────────────────────────
        if report.attack_chains:
            print(f"\n{SEPARATOR}")
            print("  ATTACK CHAINS")
            print(SEPARATOR)
            for chain in report.attack_chains:
                icon = SEVERITY_ICONS.get(chain["severity"], "⚪")
                print(f"\n  {icon} {chain['name']}  [{chain['chain_id']}]")
                print(f"     {chain['description'][:160]}")
                print(f"\n     Steps:")
                for i, step in enumerate(chain["steps"], 1):
                    print(f"       {i}. {step}")

        print(f"\n{'═' * 72}\n")

    def to_json(self, report) -> str:
        """Serialize report to JSON string."""
        def _serializable(obj: Any) -> Any:
            if hasattr(obj, "__dict__"):
                return {k: _serializable(v) for k, v in obj.__dict__.items()}
            if hasattr(obj, "value"):
                return obj.value
            if isinstance(obj, list):
                return [_serializable(i) for i in obj]
            if isinstance(obj, dict):
                return {k: _serializable(v) for k, v in obj.items()}
            return obj

        d = {
            "target_file": report.target_file,
            "scan_time_ms": report.scan_time_ms,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "vulnerabilities_found": report.vulnerabilities_found,
            "exploitable_count": report.exploitable_count,
            "summary": report.summary,
            "findings": [_serializable(ar) for ar in report.attack_results],
            "attack_chains": report.attack_chains,
        }
        return json.dumps(d, indent=2)

    def to_sarif(self, report) -> dict:
        """Output SARIF 2.1.0 format — compatible with GitHub Code Scanning."""
        rules = []
        results = []
        for ar in report.attack_results:
            v = ar.vulnerability
            rule = {
                "id": v.vuln_id,
                "name": v.vuln_type.replace(" ", ""),
                "shortDescription": {"text": v.vuln_type},
                "fullDescription": {"text": v.description},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{v.cwe.replace('CWE-','')}.html",
                "properties": {"security-severity": {"CRITICAL": "9.8", "HIGH": "8.0", "MEDIUM": "5.5", "LOW": "3.0"}.get(v.severity, "5.0")},
            }
            rules.append(rule)
            result = {
                "ruleId": v.vuln_id,
                "level": {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}.get(v.severity, "warning"),
                "message": {"text": v.description},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": report.target_file}, "region": {"startLine": v.line, "startColumn": v.col + 1}}}],
            }
            results.append(result)

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "ShadowCoder", "version": "1.0.0", "rules": rules}}, "results": results}],
        }
