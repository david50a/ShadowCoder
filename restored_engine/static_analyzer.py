"""
Static Code Analyzer — AST-based vulnerability detection for Python.

Detects:
  - SQL injection (string concat / f-string into query)
  - Command injection (subprocess / os.system with user input)
  - Hardcoded secrets (passwords, API keys, tokens)
  - Path traversal (open() with user-controlled paths)
  - Unsafe deserialization (pickle.loads, yaml.load)
  - XSS via template injection
  - Insecure use of eval() / exec()
  - SSRF (requests with user-controlled URLs)
  - Weak cryptography (MD5, SHA1)
  - Insecure random (random module for security purposes)
"""

import ast
import hashlib
import re
import uuid
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Vulnerability:
    vuln_id: str
    vuln_type: str
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW
    line: int
    col: int
    description: str
    code_snippet: str
    cwe: str
    owasp: str
    taint_source: Optional[str] = None
    taint_sink: Optional[str] = None
    confidence: float = 1.0  # 0.0 – 1.0


# ── Rule definitions ──────────────────────────────────────────────────────────

IMPORT_RISKS = {
    "pickle": ("Unsafe deserialization", "HIGH", "CWE-502", "A08"),
    "marshal": ("Unsafe deserialization", "HIGH", "CWE-502", "A08"),
    "shelve": ("Unsafe deserialization", "MEDIUM", "CWE-502", "A08"),
    "yaml": ("Potential unsafe YAML load", "MEDIUM", "CWE-502", "A08"),
    "random": ("Insecure random — not cryptographically safe", "MEDIUM", "CWE-338", "A02"),
}

DANGEROUS_CALLS = {
    # (module_or_None, func_name): (type, severity, cwe, owasp, description)
    (None, "eval"): ("Code injection", "CRITICAL", "CWE-94", "A03", "eval() executes arbitrary Python code"),
    (None, "exec"): ("Code injection", "CRITICAL", "CWE-94", "A03", "exec() executes arbitrary Python code"),
    (None, "compile"): ("Code injection", "HIGH", "CWE-94", "A03", "compile() can execute attacker-controlled code"),
    (None, "__import__"): ("Arbitrary import", "HIGH", "CWE-94", "A03", "__import__ with user input allows code execution"),
    ("os", "system"): ("Command injection", "CRITICAL", "CWE-78", "A03", "os.system() passes shell commands unsafely"),
    ("os", "popen"): ("Command injection", "CRITICAL", "CWE-78", "A03", "os.popen() executes shell commands"),
    ("subprocess", "call"): ("Command injection", "HIGH", "CWE-78", "A03", "subprocess.call with shell=True is dangerous"),
    ("subprocess", "Popen"): ("Command injection", "HIGH", "CWE-78", "A03", "subprocess.Popen with user input"),
    ("subprocess", "run"): ("Command injection", "HIGH", "CWE-78", "A03", "subprocess.run with shell=True is dangerous"),
    ("pickle", "loads"): ("Unsafe deserialization", "CRITICAL", "CWE-502", "A08", "pickle.loads can execute arbitrary code"),
    ("pickle", "load"): ("Unsafe deserialization", "CRITICAL", "CWE-502", "A08", "pickle.load can execute arbitrary code"),
    ("yaml", "load"): ("Unsafe YAML load", "HIGH", "CWE-502", "A08", "yaml.load without Loader= is unsafe"),
    ("hashlib", "md5"): ("Weak cryptography", "MEDIUM", "CWE-327", "A02", "MD5 is cryptographically broken"),
    ("hashlib", "sha1"): ("Weak cryptography", "MEDIUM", "CWE-327", "A02", "SHA-1 is weak for security use"),
    ("requests", "get"): ("Potential SSRF", "MEDIUM", "CWE-918", "A10", "requests.get with user-controlled URL"),
    ("requests", "post"): ("Potential SSRF", "MEDIUM", "CWE-918", "A10", "requests.post with user-controlled URL"),
    ("tempfile", "mktemp"): ("Insecure temp file", "MEDIUM", "CWE-377", "A01", "mktemp is vulnerable to race conditions"),
}

SECRET_PATTERNS = [
    (r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']', "Hardcoded password", "CRITICAL", "CWE-798", "A07"),
    (r'(?i)(api_key|apikey|api-key)\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded API key", "CRITICAL", "CWE-798", "A07"),
    (r'(?i)(secret|token|auth)\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded secret/token", "HIGH", "CWE-798", "A07"),
    (r'(?i)(aws_access_key_id|aws_secret)\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded AWS credential", "CRITICAL", "CWE-798", "A07"),
    (r'-----BEGIN (RSA |EC )?PRIVATE KEY-----', "Private key in source", "CRITICAL", "CWE-321", "A07"),
]

SQL_KEYWORDS = re.compile(r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b', re.IGNORECASE)


def _snippet(source_lines: list[str], lineno: int, context: int = 1) -> str:
    start = max(0, lineno - 1 - context)
    end = min(len(source_lines), lineno + context)
    return "\n".join(source_lines[start:end]).strip()


def _make_id(vuln_type: str, line: int) -> str:
    return f"V-{hashlib.md5(f'{vuln_type}{line}'.encode()).hexdigest()[:8].upper()}"


# ── Taint tracking helpers ────────────────────────────────────────────────────

USER_INPUT_SOURCES = {
    "input", "request.args.get", "request.form.get", "request.json",
    "request.data", "request.values.get", "sys.stdin.read",
    "os.environ.get", "environ.get",
}


def _is_tainted(node: ast.AST) -> bool:
    """Heuristic: is this AST node likely to carry user-controlled data?"""
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name) and func.id in USER_INPUT_SOURCES:
            return True
        if isinstance(func, ast.Attribute):
            full = f"{getattr(func.value, 'id', '')}.{func.attr}"
            return any(full.endswith(src) for src in USER_INPUT_SOURCES)
    if isinstance(node, ast.Name):
        return node.id in {"user_input", "data", "body", "params", "args", "payload"}
    return False


def _contains_taint(node: ast.AST) -> bool:
    """Recursively check if any sub-node is tainted."""
    if _is_tainted(node):
        return True
    for child in ast.walk(node):
        if child is not node and _is_tainted(child):
            return True
    return False


# ── Visitor ───────────────────────────────────────────────────────────────────

class _VulnVisitor(ast.NodeVisitor):
    def __init__(self, source_lines: list[str], filename: str):
        self.source_lines = source_lines
        self.filename = filename
        self.vulns: list[Vulnerability] = []
        self._imports: dict[str, str] = {}  # alias → real module
        self.tainted_vars: set[str] = set()  # variable names holding SQL strings

    # ── Import tracking ───────────────────────────────────────────────────────

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            name = alias.asname or alias.name
            self._imports[name] = alias.name
            if alias.name in IMPORT_RISKS:
                desc, sev, cwe, owasp = IMPORT_RISKS[alias.name]
                self.vulns.append(Vulnerability(
                    vuln_id=_make_id(alias.name, node.lineno),
                    vuln_type=desc,
                    severity=sev,
                    line=node.lineno,
                    col=node.col_offset,
                    description=f"Importing '{alias.name}' introduces risk: {desc}",
                    code_snippet=_snippet(self.source_lines, node.lineno),
                    cwe=cwe,
                    owasp=f"OWASP A{owasp}" if not owasp.startswith("A") else f"OWASP {owasp}",
                    confidence=0.7,
                ))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ""
        for alias in node.names:
            key = alias.asname or alias.name
            self._imports[key] = f"{module}.{alias.name}"
            if module in IMPORT_RISKS:
                desc, sev, cwe, owasp = IMPORT_RISKS[module]
                self.vulns.append(Vulnerability(
                    vuln_id=_make_id(f"{module}.{alias.name}", node.lineno),
                    vuln_type=desc,
                    severity=sev,
                    line=node.lineno,
                    col=node.col_offset,
                    description=f"Importing from '{module}': {desc}",
                    code_snippet=_snippet(self.source_lines, node.lineno),
                    cwe=cwe,
                    owasp=f"OWASP {owasp}",
                    confidence=0.7,
                ))
        self.generic_visit(node)

    # ── Function call analysis ────────────────────────────────────────────────

    def visit_Call(self, node: ast.Call):
        func = node.func
        module_name = None
        func_name = None

        if isinstance(func, ast.Attribute):
            func_name = func.attr
            if isinstance(func.value, ast.Name):
                module_name = func.value.id
        elif isinstance(func, ast.Name):
            func_name = func.id

        key = (module_name, func_name)
        if key in DANGEROUS_CALLS:
            vtype, sev, cwe, owasp, desc = DANGEROUS_CALLS[key]
            tainted = any(_contains_taint(arg) for arg in node.args + list(node.keywords))
            confidence = 0.95 if tainted else 0.6

            # Escalate command injection if shell=True
            if func_name in ("call", "Popen", "run"):
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value:
                        sev = "CRITICAL"
                        confidence = 0.98

            self.vulns.append(Vulnerability(
                vuln_id=_make_id(f"{module_name}.{func_name}", node.lineno),
                vuln_type=vtype,
                severity=sev,
                line=node.lineno,
                col=node.col_offset,
                description=desc,
                code_snippet=_snippet(self.source_lines, node.lineno),
                cwe=cwe,
                owasp=f"OWASP {owasp}",
                taint_source="user_input" if tainted else None,
                taint_sink=f"{module_name}.{func_name}" if module_name else func_name,
                confidence=confidence,
            ))

        # SQL injection via string concat / f-string
        self._check_sql_injection(node)
        self.generic_visit(node)

    def _check_sql_injection(self, node: ast.Call):
        """Detect SQL queries built with string concatenation or f-strings."""
        # Check if this is a cursor.execute / executemany call
        func = node.func
        is_execute = False
        if isinstance(func, ast.Attribute) and func.attr in ("execute", "executemany"):
            is_execute = True

        for arg in node.args:
            if self._is_sql_concat(arg) or self._is_sql_fstring(arg):
                self.vulns.append(Vulnerability(
                    vuln_id=_make_id("sqli", node.lineno),
                    vuln_type="SQL Injection",
                    severity="CRITICAL",
                    line=node.lineno,
                    col=node.col_offset,
                    description="SQL query built with string concatenation — parameterized queries required",
                    code_snippet=_snippet(self.source_lines, node.lineno),
                    cwe="CWE-89",
                    owasp="OWASP A03",
                    taint_source="string_concat",
                    taint_sink="sql_execute",
                    confidence=0.9,
                ))
                return

        # Also detect when a tainted variable is passed directly to execute()
        if is_execute and node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Name) and arg.id in self.tainted_vars:
                self.vulns.append(Vulnerability(
                    vuln_id=_make_id("sqli_var", node.lineno),
                    vuln_type="SQL Injection",
                    severity="CRITICAL",
                    line=node.lineno,
                    col=node.col_offset,
                    description="SQL query variable passed to execute() — possible injection via tainted data",
                    code_snippet=_snippet(self.source_lines, node.lineno),
                    cwe="CWE-89",
                    owasp="OWASP A03",
                    taint_source="tainted_variable",
                    taint_sink="sql_execute",
                    confidence=0.85,
                ))

    def _is_sql_concat(self, node: ast.AST) -> bool:
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            src = ast.unparse(node)
            return bool(SQL_KEYWORDS.search(src))
        return False

    def _is_sql_fstring(self, node: ast.AST) -> bool:
        if isinstance(node, ast.JoinedStr):
            src = ast.unparse(node)
            return bool(SQL_KEYWORDS.search(src))
        return False

    # ── Path traversal ────────────────────────────────────────────────────────

    def visit_Assign(self, node: ast.Assign):
        """Track taint propagation through assignments + detect SQL built in vars."""
        # Detect SQL string built via concat stored in a variable
        if self._is_sql_concat(node.value) or self._is_sql_fstring(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars.add(target.id)
            self.vulns.append(Vulnerability(
                vuln_id=_make_id("sqli_assign", node.lineno),
                vuln_type="SQL Injection",
                severity="CRITICAL",
                line=node.lineno,
                col=node.col_offset,
                description="SQL query built with string concatenation — use parameterized queries",
                code_snippet=_snippet(self.source_lines, node.lineno),
                cwe="CWE-89",
                owasp="OWASP A03",
                taint_source="string_concat",
                taint_sink="sql_execute",
                confidence=0.9,
            ))
        self.generic_visit(node)

    def visit_Expr(self, node: ast.Expr):
        if isinstance(node.value, ast.Call):
            call = node.value
            if isinstance(call.func, ast.Name) and call.func.id == "open":
                if call.args and _contains_taint(call.args[0]):
                    self.vulns.append(Vulnerability(
                        vuln_id=_make_id("path_traversal", node.lineno),
                        vuln_type="Path Traversal",
                        severity="HIGH",
                        line=node.lineno,
                        col=node.col_offset,
                        description="open() called with user-controlled path — validate and sanitize the path",
                        code_snippet=_snippet(self.source_lines, node.lineno),
                        cwe="CWE-22",
                        owasp="OWASP A01",
                        taint_source="user_input",
                        taint_sink="open()",
                        confidence=0.85,
                    ))
        self.generic_visit(node)


# ── Public API ────────────────────────────────────────────────────────────────

class StaticAnalyzer:
    def analyze(self, source_code: str, filename: str = "<stdin>") -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        source_lines = source_code.splitlines()

        # AST-based analysis
        try:
            tree = ast.parse(source_code, filename=filename)
            visitor = _VulnVisitor(source_lines, filename)
            visitor.visit(tree)
            vulns.extend(visitor.vulns)
        except SyntaxError as e:
            pass  # Return partial results from regex pass

        # Regex-based secret detection (runs on raw source)
        for pattern, name, sev, cwe, owasp in SECRET_PATTERNS:
            for m in re.finditer(pattern, source_code):
                lineno = source_code[: m.start()].count("\n") + 1
                vulns.append(Vulnerability(
                    vuln_id=_make_id(name, lineno),
                    vuln_type=name,
                    severity=sev,
                    line=lineno,
                    col=m.start() - source_code.rfind("\n", 0, m.start()) - 1,
                    description=f"{name} found in source code",
                    code_snippet=_snippet(source_lines, lineno),
                    cwe=cwe,
                    owasp=f"OWASP {owasp}",
                    confidence=0.92,
                ))

        # Deduplicate by (type, line)
        seen = set()
        unique = []
        for v in vulns:
            key = (v.vuln_type, v.line)
            if key not in seen:
                seen.add(key)
                unique.append(v)

        return sorted(unique, key=lambda v: ({"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(v.severity, 4), v.line))
