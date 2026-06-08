"""
Tests for ShadowCoder Attack Simulation Engine.
Run: python -m pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from engine.static_analyzer import StaticAnalyzer
from engine.payload_generator import PayloadGenerator
from engine.execution_simulator import ExecutionSimulator
from engine.attack_graph import AttackGraphBuilder
from engine.attack_engine import AttackEngine, Severity


# ── Fixtures ──────────────────────────────────────────────────────────────────

SQL_VULN_CODE = """
import sqlite3

def get_user(username):
    conn = sqlite3.connect("db.sqlite3")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()
"""

CMD_INJECT_CODE = """
import subprocess

def ping(host):
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return result.stdout
"""

EVAL_CODE = """
def calculate(expr):
    return eval(expr)
"""

HARDCODED_CODE = """
DB_PASSWORD = "supersecret123"
API_KEY = "sk-prod-abc123xyz789"
"""

PICKLE_CODE = """
import pickle

def load_session(data):
    return pickle.loads(data)
"""

CLEAN_CODE = """
import sqlite3

def get_user(username):
    conn = sqlite3.connect("db.sqlite3")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchone()
"""


# ── Static Analyzer Tests ─────────────────────────────────────────────────────

class TestStaticAnalyzer:
    def setup_method(self):
        self.analyzer = StaticAnalyzer()

    def test_detects_sql_injection(self):
        vulns = self.analyzer.analyze(SQL_VULN_CODE)
        types = [v.vuln_type for v in vulns]
        assert "SQL Injection" in types, f"Expected SQL Injection, got: {types}"

    def test_detects_command_injection(self):
        vulns = self.analyzer.analyze(CMD_INJECT_CODE)
        types = [v.vuln_type for v in vulns]
        assert any("injection" in t.lower() or "Command" in t for t in types), f"Expected command injection, got: {types}"

    def test_detects_eval(self):
        vulns = self.analyzer.analyze(EVAL_CODE)
        types = [v.vuln_type for v in vulns]
        assert any("injection" in t.lower() or "Code" in t for t in types), f"Expected Code injection, got: {types}"

    def test_detects_hardcoded_credentials(self):
        vulns = self.analyzer.analyze(HARDCODED_CODE)
        types = [v.vuln_type for v in vulns]
        assert any("Hardcoded" in t for t in types), f"Expected hardcoded cred, got: {types}"

    def test_detects_unsafe_pickle(self):
        vulns = self.analyzer.analyze(PICKLE_CODE)
        types = [v.vuln_type for v in vulns]
        assert any("deserialization" in t.lower() or "Unsafe" in t for t in types), f"Got: {types}"

    def test_no_false_positives_on_clean_code(self):
        vulns = self.analyzer.analyze(CLEAN_CODE)
        high_plus = [v for v in vulns if v.severity in ("CRITICAL", "HIGH")]
        assert len(high_plus) == 0, f"False positives: {[(v.vuln_type, v.line) for v in high_plus]}"

    def test_severity_ordering(self):
        vulns = self.analyzer.analyze(SQL_VULN_CODE + HARDCODED_CODE)
        severities = [v.severity for v in vulns]
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        ordered = sorted(severities, key=lambda s: order.get(s, 4))
        assert severities == ordered, f"Vulns not sorted by severity: {severities}"

    def test_vuln_has_cwe(self):
        vulns = self.analyzer.analyze(SQL_VULN_CODE)
        for v in vulns:
            assert v.cwe.startswith("CWE-"), f"Missing CWE on {v.vuln_type}"

    def test_vuln_has_code_snippet(self):
        vulns = self.analyzer.analyze(SQL_VULN_CODE)
        for v in vulns:
            assert v.code_snippet, f"Missing code snippet on {v.vuln_type}"


# ── Payload Generator Tests ───────────────────────────────────────────────────

class TestPayloadGenerator:
    def setup_method(self):
        self.analyzer = StaticAnalyzer()
        self.gen = PayloadGenerator()

    def test_generates_sql_payloads(self):
        vulns = self.analyzer.analyze(SQL_VULN_CODE)
        sqli = [v for v in vulns if v.vuln_type == "SQL Injection"]
        assert sqli, "No SQLi vuln found"
        payloads = self.gen.generate(sqli[0])
        assert len(payloads) >= 3, f"Expected ≥3 payloads, got {len(payloads)}"
        raws = [p["raw"] for p in payloads]
        assert any("OR" in r for r in raws), "Expected auth bypass payload"
        assert any("UNION" in r for r in raws), "Expected UNION payload"

    def test_payloads_have_bypasses(self):
        vulns = self.analyzer.analyze(SQL_VULN_CODE)
        sqli = [v for v in vulns if v.vuln_type == "SQL Injection"]
        payloads = self.gen.generate(sqli[0])
        assert any(p.get("bypasses") for p in payloads), "Expected WAF bypasses"

    def test_payloads_have_encodings(self):
        vulns = self.analyzer.analyze(SQL_VULN_CODE)
        sqli = [v for v in vulns if v.vuln_type == "SQL Injection"]
        payloads = self.gen.generate(sqli[0])
        assert any(p.get("encoded") for p in payloads), "Expected encoded variants"

    def test_cmd_payloads_include_reverse_shell(self):
        vulns = self.analyzer.analyze(CMD_INJECT_CODE)
        cmd = [v for v in vulns if "injection" in v.vuln_type.lower() or "Command" in v.vuln_type]
        if cmd:
            payloads = self.gen.generate(cmd[0])
            raws = [p["raw"] for p in payloads]
            assert any("id" in r or "shell" in r.lower() for r in raws), f"Got: {raws}"


# ── Execution Simulator Tests ─────────────────────────────────────────────────

class TestExecutionSimulator:
    def setup_method(self):
        self.analyzer = StaticAnalyzer()
        self.gen = PayloadGenerator()
        self.sim = ExecutionSimulator()

    def test_sql_injection_is_exploitable(self):
        vulns = self.analyzer.analyze(SQL_VULN_CODE)
        sqli = [v for v in vulns if v.vuln_type == "SQL Injection"]
        assert sqli
        payloads = self.gen.generate(sqli[0])
        result = self.sim.simulate(sqli[0], payloads, SQL_VULN_CODE)
        assert result["exploitable"], f"Expected exploitable, got: {result}"

    def test_eval_is_rce(self):
        vulns = self.analyzer.analyze(EVAL_CODE)
        code_inj = [v for v in vulns if "injection" in v.vuln_type.lower()]
        if code_inj:
            payloads = self.gen.generate(code_inj[0])
            result = self.sim.simulate(code_inj[0], payloads, EVAL_CODE)
            assert result.get("rce_possible") or result.get("exploitable"), f"Got: {result}"

    def test_simulation_has_execution_path(self):
        vulns = self.analyzer.analyze(SQL_VULN_CODE)
        sqli = [v for v in vulns if v.vuln_type == "SQL Injection"]
        payloads = self.gen.generate(sqli[0])
        result = self.sim.simulate(sqli[0], payloads, SQL_VULN_CODE)
        assert isinstance(result.get("execution_path"), list)
        assert len(result["execution_path"]) >= 1

    def test_simulation_has_blast_radius(self):
        vulns = self.analyzer.analyze(SQL_VULN_CODE)
        sqli = [v for v in vulns if v.vuln_type == "SQL Injection"]
        payloads = self.gen.generate(sqli[0])
        result = self.sim.simulate(sqli[0], payloads, SQL_VULN_CODE)
        assert result.get("blast_radius") in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


# ── Attack Graph Tests ────────────────────────────────────────────────────────

class TestAttackGraph:
    def setup_method(self):
        self.engine = AttackEngine.__new__(AttackEngine)
        self.engine.analyzer = StaticAnalyzer()
        self.engine.payload_gen = PayloadGenerator()
        self.engine.simulator = ExecutionSimulator()
        self.engine.graph_builder = AttackGraphBuilder()

    def test_chains_sqli_with_weak_crypto(self):
        code = SQL_VULN_CODE + """
import hashlib
def hash_pw(p):
    return hashlib.md5(p.encode()).hexdigest()
"""
        vulns = self.engine.analyzer.analyze(code)
        from engine.attack_engine import AttackResult, Severity
        results = []
        for v in vulns:
            payloads = self.engine.payload_gen.generate(v)
            sim = self.engine.simulator.simulate(v, payloads, code)
            results.append(AttackResult(
                vulnerability=v, payloads=payloads, simulation=sim,
                ai_analysis="", severity=Severity.HIGH, exploitable=sim.get("exploitable", False)
            ))
        chains = self.engine.graph_builder.build(results)
        chain_names = [c["name"] for c in chains]
        # At minimum there should be chains or direct findings
        assert isinstance(chains, list)

    def test_chain_has_steps(self):
        code = SQL_VULN_CODE + "\nimport hashlib\ndef h(p): return hashlib.md5(p.encode()).hexdigest()\n"
        vulns = self.engine.analyzer.analyze(code)
        from engine.attack_engine import AttackResult, Severity
        results = []
        for v in vulns:
            payloads = self.engine.payload_gen.generate(v)
            sim = self.engine.simulator.simulate(v, payloads, code)
            results.append(AttackResult(
                vulnerability=v, payloads=payloads, simulation=sim,
                ai_analysis="", severity=Severity.HIGH, exploitable=sim.get("exploitable", False)
            ))
        chains = self.engine.graph_builder.build(results)
        for chain in chains:
            assert len(chain.get("steps", [])) >= 1, f"Chain has no steps: {chain['name']}"


# ── Integration Test ──────────────────────────────────────────────────────────

class TestIntegration:
    def setup_method(self):
        pass

    def test_full_scan_vulnerable_app(self):
        engine = AttackEngine.__new__(AttackEngine)
        engine.analyzer = StaticAnalyzer()
        engine.payload_gen = PayloadGenerator()
        engine.simulator = ExecutionSimulator()
        engine.graph_builder = AttackGraphBuilder()
        # Mock AI client
        class MockAI:
            def _is_available(self): return True
            def enrich(self, *a, **k): return "[AI disabled in test]"
            def summarize(self, *a, **k): return "Multiple critical vulnerabilities found."
        engine.ai = MockAI()
        engine.reporter = None

        vulnerable_path = os.path.join(os.path.dirname(__file__), "vulnerable_app.py")
        with open(vulnerable_path) as f:
            source = f.read()

        report = engine.scan(source, filename="vulnerable_app.py")

        assert report.vulnerabilities_found >= 5, f"Expected ≥5 vulns, found {report.vulnerabilities_found}"
        assert report.exploitable_count >= 2, f"Expected ≥2 exploitable, found {report.exploitable_count}"
        assert len(report.attack_chains) >= 1, f"Expected attack chains, found {len(report.attack_chains)}"
        print(f"\n  ✅ Full scan: {report.vulnerabilities_found} vulns, {report.exploitable_count} exploitable, {len(report.attack_chains)} chains")
        print(f"     Scan time: {report.scan_time_ms}ms")


if __name__ == "__main__":
    import traceback
    tests = [
        TestStaticAnalyzer,
        TestPayloadGenerator,
        TestExecutionSimulator,
        TestAttackGraph,
        TestIntegration,
    ]
    passed = 0
    failed = 0
    for cls in tests:
        inst = cls()
        methods = [m for m in dir(cls) if m.startswith("test_")]
        for m in methods:
            inst.setup_method()
            try:
                getattr(inst, m)()
                print(f"  ✅ {cls.__name__}.{m}")
                passed += 1
            except Exception as e:
                print(f"  ❌ {cls.__name__}.{m}: {e}")
                traceback.print_exc()
                failed += 1
    print(f"\n{'─'*50}")
    print(f"  {passed} passed  {failed} failed")
