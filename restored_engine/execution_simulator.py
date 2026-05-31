"""
Execution Simulator — traces how payloads flow through vulnerable code.

Does NOT execute untrusted code. Instead:
  1. Builds a call-flow graph from the AST
  2. Traces taint propagation from source → sink
  3. Simulates what WOULD happen if each payload were injected
  4. Reports: exploitable?, data_exfil_possible?, privilege_escalation?, blast_radius
"""

import ast
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TaintNode:
    name: str
    node_type: str   # source | propagator | sink
    line: int
    tainted: bool = False
    taint_path: list[str] = field(default_factory=list)


@dataclass
class SimResult:
    exploitable: bool
    confidence: float
    execution_path: list[str]
    taint_flow: list[str]
    data_exfil_possible: bool
    privilege_escalation: bool
    rce_possible: bool
    blast_radius: str     # LOW | MEDIUM | HIGH | CRITICAL
    notes: list[str]


class _TaintTracker(ast.NodeVisitor):
    """Tracks taint flow through AST — pure static analysis, no execution."""

    TAINT_SOURCES = {
        "input", "request", "args", "form", "json", "data",
        "params", "user_input", "body", "environ", "query",
    }
    TAINT_SINKS = {
        "execute", "executemany", "system", "popen", "Popen",
        "run", "call", "eval", "exec", "loads", "load",
        "open", "get", "post", "urlopen", "urlretrieve",
    }
    TAINT_PROPAGATORS = {
        "format", "join", "replace", "strip", "split",
        "encode", "decode", "upper", "lower", "f-string",
    }

    def __init__(self):
        self.tainted_vars: set[str] = set()
        self.flow: list[str] = []
        self.sink_hits: list[dict] = []
        self.rce_sinks = {"eval", "exec", "system", "popen", "Popen", "run", "call", "loads", "load"}
        self.exfil_sinks = {"get", "post", "urlopen", "urlretrieve", "open"}

    def visit_Assign(self, node: ast.Assign):
        """Track taint propagation through assignments."""
        value_tainted = self._is_tainted_expr(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                if value_tainted:
                    self.tainted_vars.add(target.id)
                    self.flow.append(f"L{node.lineno}: `{target.id}` receives tainted data")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = self._func_name(node.func)
        is_sink = func_name in self.TAINT_SINKS

        if is_sink:
            args_tainted = any(self._is_tainted_expr(a) for a in node.args)
            kw_tainted = any(self._is_tainted_expr(k.value) for k in node.keywords)
            if args_tainted or kw_tainted:
                self.sink_hits.append({
                    "sink": func_name,
                    "line": node.lineno,
                    "rce": func_name in self.rce_sinks,
                    "exfil": func_name in self.exfil_sinks,
                })
                self.flow.append(f"L{node.lineno}: Tainted data reaches sink `{func_name}()` ← VULNERABLE")

        self.generic_visit(node)

    def _is_tainted_expr(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.tainted_vars or node.id in self.TAINT_SOURCES
        if isinstance(node, ast.Call):
            func = self._func_name(node.func)
            if isinstance(node.func, ast.Attribute):
                obj = node.func.value
                if isinstance(obj, ast.Name) and obj.id in self.TAINT_SOURCES:
                    return True
            return func in self.TAINT_SOURCES
        if isinstance(node, ast.BinOp):
            return self._is_tainted_expr(node.left) or self._is_tainted_expr(node.right)
        if isinstance(node, ast.JoinedStr):
            return any(
                self._is_tainted_expr(v.value if isinstance(v, ast.FormattedValue) else v)
                for v in node.values
                if isinstance(v, (ast.FormattedValue, ast.Name))
            )
        if isinstance(node, ast.Subscript):
            return self._is_tainted_expr(node.value)
        if isinstance(node, ast.Attribute):
            return self._is_tainted_expr(node.value)
        return False

    def _func_name(self, func: ast.AST) -> str:
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return ""


# ── Payload impact classification ─────────────────────────────────────────────

BLAST_RADIUS_RULES = [
    # (condition, blast_radius, note)
    (lambda s: s.rce_possible,                         "CRITICAL", "RCE confirmed — full server compromise"),
    (lambda s: s.privilege_escalation,                 "CRITICAL", "Privilege escalation path detected"),
    (lambda s: s.data_exfil_possible and s.exploitable, "HIGH",    "Data exfiltration path confirmed"),
    (lambda s: s.exploitable,                          "HIGH",     "Exploitable vulnerability with taint path"),
    (lambda s: True,                                   "MEDIUM",   "Potential vulnerability — taint path unclear"),
]


class ExecutionSimulator:
    def simulate(self, vuln, payloads: list[dict], source_code: str) -> dict:
        """
        Simulate payload execution against the vulnerable code.
        Returns a dict matching SimResult fields.
        """
        tracker = _TaintTracker()
        try:
            tree = ast.parse(source_code)
            tracker.visit(tree)
        except SyntaxError:
            pass

        rce_possible = any(h["rce"] for h in tracker.sink_hits)
        exfil_possible = any(h["exfil"] for h in tracker.sink_hits)
        exploitable = bool(tracker.sink_hits)

        # Also mark RCE if vuln type is a known RCE class (eval/exec/pickle)
        rce_vuln_types = {"Code injection", "Command injection", "Unsafe deserialization"}
        if vuln.vuln_type in rce_vuln_types:
            rce_possible = True
            exploitable = True

        # Privilege escalation heuristic: command injection + running as root indicator
        priv_esc = rce_possible and any(
            kw in source_code for kw in ["sudo", "setuid", "SUID", "root", "chmod 777"]
        )

        # Build execution path narrative
        exec_path = []
        if payloads:
            exec_path.append(f"Attacker crafts payload: {payloads[0]['raw'][:80]}")
        exec_path.append(f"Payload reaches {vuln.taint_sink or vuln.vuln_type} at line {vuln.line}")
        if rce_possible:
            exec_path.append("→ OS command executed as application user")
        if exfil_possible:
            exec_path.append("→ Data sent to attacker-controlled endpoint")

        # Determine blast radius
        result_stub = type("R", (), {
            "rce_possible": rce_possible,
            "privilege_escalation": priv_esc,
            "data_exfil_possible": exfil_possible,
            "exploitable": exploitable,
        })()
        blast_radius = "LOW"
        notes = []
        for condition, radius, note in BLAST_RADIUS_RULES:
            if condition(result_stub):
                blast_radius = radius
                notes.append(note)
                break

        # Add bypass notes from payloads
        for p in payloads[:2]:
            if p.get("bypasses"):
                notes.append(f"WAF bypasses available: {p['bypasses'][0]}")

        # Confidence: higher if taint flow is fully traced
        confidence = 0.95 if (exploitable and tracker.flow) else 0.6 if exploitable else 0.3

        return {
            "exploitable": exploitable,
            "confidence": round(confidence, 2),
            "execution_path": exec_path,
            "taint_flow": tracker.flow,
            "data_exfil_possible": exfil_possible,
            "privilege_escalation": priv_esc,
            "rce_possible": rce_possible,
            "blast_radius": blast_radius,
            "notes": notes,
            "sink_hits": tracker.sink_hits,
        }
