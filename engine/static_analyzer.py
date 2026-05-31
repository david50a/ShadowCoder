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
    context_metadata: dict = field(default_factory=dict)


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

    # ── Code execution ────────────────────────────────────────────────────
    (None, "eval"):      ("Code Injection (eval)", "CRITICAL", "CWE-94",  "A03", "eval() executes arbitrary Python code from user input — full RCE risk"),
    (None, "exec"):      ("Code Injection (exec)", "CRITICAL", "CWE-94",  "A03", "exec() executes arbitrary Python code — arbitrary command execution"),
    (None, "compile"):   ("Code Injection (compile)", "HIGH",   "CWE-94",  "A03", "compile() can compile and execute attacker-controlled bytecode"),
    (None, "__import__"):("Arbitrary Module Import",  "HIGH",   "CWE-94",  "A03", "__import__ with user input allows loading of arbitrary modules"),

    # ── Command injection ──────────────────────────────────────────────────
    ("os", "system"):         ("Command Injection (os.system)",   "CRITICAL", "CWE-78", "A03", "os.system() passes unsanitized shell commands — full RCE"),
    ("os", "popen"):          ("Command Injection (os.popen)",    "CRITICAL", "CWE-78", "A03", "os.popen() executes shell commands and returns output stream"),
    ("os", "execve"):         ("Command Injection (os.execve)",   "CRITICAL", "CWE-78", "A03", "os.execve() replaces process image — direct OS command execution"),
    ("os", "execvp"):         ("Command Injection (os.execvp)",   "CRITICAL", "CWE-78", "A03", "os.execvp() executes a new program in the current process"),
    ("os", "spawnl"):         ("Command Injection (os.spawnl)",   "HIGH",     "CWE-78", "A03", "os.spawnl() spawns a child process with supplied arguments"),
    ("subprocess", "call"):   ("Command Injection (subprocess)",  "HIGH",     "CWE-78", "A03", "subprocess.call with shell=True is dangerously exploitable"),
    ("subprocess", "Popen"):  ("Command Injection (Popen)",       "HIGH",     "CWE-78", "A03", "subprocess.Popen with user input enables command injection"),
    ("subprocess", "run"):    ("Command Injection (subprocess)",  "HIGH",     "CWE-78", "A03", "subprocess.run with shell=True is dangerous"),
    ("subprocess", "check_output"): ("Command Injection (subprocess)", "HIGH", "CWE-78", "A03", "subprocess.check_output with shell=True allows command injection"),

    # ── Deserialization ───────────────────────────────────────────────────
    ("pickle",  "loads"): ("Unsafe Deserialization (pickle)", "CRITICAL", "CWE-502", "A08", "pickle.loads() can execute arbitrary code during deserialization"),
    ("pickle",  "load"):  ("Unsafe Deserialization (pickle)", "CRITICAL", "CWE-502", "A08", "pickle.load() deserializes untrusted data — RCE via __reduce__"),
    ("marshal", "loads"): ("Unsafe Deserialization (marshal)","CRITICAL", "CWE-502", "A08", "marshal.loads() can be exploited to execute arbitrary bytecode"),
    ("yaml",    "load"):  ("Unsafe YAML Deserialization",     "HIGH",     "CWE-502", "A08", "yaml.load() without Loader=SafeLoader allows arbitrary code execution"),
    ("json",    "loads"): ("Potential JSON Injection",        "LOW",      "CWE-502", "A08", "json.loads on unvalidated input may enable prototype pollution or injection"),
    ("shelve",  "open"):  ("Unsafe Shelve Deserialization",   "HIGH",     "CWE-502", "A08", "shelve.open() uses pickle internally — do not open untrusted shelf files"),
    ("dill",    "loads"): ("Unsafe Deserialization (dill)",   "CRITICAL", "CWE-502", "A08", "dill.loads() is more powerful than pickle — arbitrary code execution"),
    ("joblib",  "load"):  ("Unsafe Deserialization (joblib)", "HIGH",     "CWE-502", "A08", "joblib.load() uses pickle — unsafe with untrusted data"),

    # ── Cryptography ──────────────────────────────────────────────────────
    ("hashlib", "md5"):    ("Weak Cryptography (MD5)",   "MEDIUM", "CWE-327", "A02", "MD5 is cryptographically broken — collision attacks are trivial"),
    ("hashlib", "sha1"):   ("Weak Cryptography (SHA-1)", "MEDIUM", "CWE-327", "A02", "SHA-1 is deprecated for security use — vulnerable to SHAttered attack"),
    ("hashlib", "sha224"): ("Weak Cryptography (SHA-224)","LOW",   "CWE-327", "A02", "SHA-224 provides insufficient security margin for long-term use"),
    ("Crypto",  "DES"):    ("Weak Cryptography (DES)",   "HIGH",   "CWE-327", "A02", "DES uses 56-bit key — brute force feasible in hours"),
    ("Crypto",  "ARC4"):   ("Weak Cryptography (RC4)",   "HIGH",   "CWE-327", "A02", "RC4 stream cipher has known biases and is cryptographically broken"),

    # ── Insecure random ────────────────────────────────────────────────────
    ("random", "random"):     ("Insecure Randomness", "MEDIUM", "CWE-338", "A02", "random.random() is not cryptographically secure — use secrets module"),
    ("random", "randint"):    ("Insecure Randomness", "MEDIUM", "CWE-338", "A02", "random.randint() is predictable — attackers can guess tokens/nonces"),
    ("random", "choice"):     ("Insecure Randomness", "MEDIUM", "CWE-338", "A02", "random.choice() is not cryptographically safe for security tokens"),
    ("random", "randrange"):  ("Insecure Randomness", "MEDIUM", "CWE-338", "A02", "random.randrange() uses Mersenne Twister — state is recoverable"),
    ("random", "shuffle"):    ("Insecure Randomness", "LOW",    "CWE-338", "A02", "random.shuffle() is not cryptographically secure"),

    # ── SSRF / Network ────────────────────────────────────────────────────
    ("requests",  "get"):     ("Server-Side Request Forgery (SSRF)", "HIGH",   "CWE-918", "A10", "requests.get with user URL enables SSRF — cloud metadata access risk"),
    ("requests",  "post"):    ("Server-Side Request Forgery (SSRF)", "HIGH",   "CWE-918", "A10", "requests.post with user URL — potential SSRF to internal services"),
    ("requests",  "put"):     ("Server-Side Request Forgery (SSRF)", "HIGH",   "CWE-918", "A10", "requests.put with user-controlled URL enables SSRF attacks"),
    ("urllib",    "urlopen"): ("Server-Side Request Forgery (SSRF)", "HIGH",   "CWE-918", "A10", "urllib.urlopen with user input — SSRF to internal resources"),
    ("urllib3",   "request"): ("Server-Side Request Forgery (SSRF)", "MEDIUM", "CWE-918", "A10", "urllib3 request with unvalidated URL — potential SSRF"),
    ("httpx",     "get"):     ("Server-Side Request Forgery (SSRF)", "HIGH",   "CWE-918", "A10", "httpx.get with user-controlled URL — SSRF risk"),

    # ── Template injection ────────────────────────────────────────────────
    ("jinja2",    "Template"):         ("Server-Side Template Injection (SSTI)", "CRITICAL", "CWE-94", "A03", "jinja2.Template() with user input enables SSTI — full RCE via {{7*7}} style payloads"),
    ("mako",      "Template"):         ("Server-Side Template Injection (SSTI)", "CRITICAL", "CWE-94", "A03", "Mako Template with user content — SSTI allows OS command execution"),
    ("string",    "Template"):         ("Template Injection",                    "MEDIUM",   "CWE-94", "A03", "string.Template with user-controlled template — limited injection risk"),

    # ── XML / XXE ─────────────────────────────────────────────────────────
    ("xml.etree.ElementTree", "parse"):  ("XML External Entity (XXE)", "HIGH", "CWE-611", "A05", "ElementTree.parse() does not disable external entity processing"),
    ("lxml.etree", "parse"):             ("XML External Entity (XXE)", "HIGH", "CWE-611", "A05", "lxml.etree.parse() may process external XML entities"),
    ("xml.sax", "parseString"):          ("XML External Entity (XXE)", "HIGH", "CWE-611", "A05", "xml.sax.parseString processes external entities by default"),

    # ── Path traversal ────────────────────────────────────────────────────
    ("pathlib", "Path"):  ("Path Traversal (pathlib)", "HIGH", "CWE-22", "A01", "pathlib.Path constructed with user input — path traversal via ../../../"),
    ("shutil",  "copy"):  ("Path Traversal (shutil)",  "HIGH", "CWE-22", "A01", "shutil.copy with user-controlled paths — arbitrary file write"),
    ("shutil",  "move"):  ("Path Traversal (shutil)",  "HIGH", "CWE-22", "A01", "shutil.move with user input — file manipulation outside root"),

    # ── Race conditions / misc ────────────────────────────────────────────
    ("tempfile", "mktemp"):   ("Insecure Temp File (TOCTOU)", "MEDIUM", "CWE-377", "A01", "mktemp() has a TOCTOU race condition — use mkstemp() instead"),
    ("os",       "chmod"):    ("Insecure File Permissions",   "MEDIUM", "CWE-732", "A01", "os.chmod with user-controlled mode — may grant world-writable perms"),
    ("os",       "chown"):    ("Insecure File Ownership",     "MEDIUM", "CWE-732", "A01", "os.chown with user input — privilege escalation via ownership change"),

    # ── LDAP injection ────────────────────────────────────────────────────
    ("ldap3", "Connection"):  ("LDAP Injection",  "HIGH", "CWE-90",  "A03", "LDAP query built from user input — enables authentication bypass"),

    # ── NoSQL injection ───────────────────────────────────────────────────
    ("pymongo", "find"):      ("NoSQL Injection (MongoDB)", "HIGH", "CWE-943", "A03", "MongoDB .find() with unvalidated dict input — NoSQL injection risk"),
    ("pymongo", "find_one"):  ("NoSQL Injection (MongoDB)", "HIGH", "CWE-943", "A03", "MongoDB .find_one() with user input — authentication bypass possible"),
}

SECRET_PATTERNS = [
    (r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']', "Hardcoded Password", "CRITICAL", "CWE-798", "A07"),
    (r'(?i)(api_key|apikey|api-key)\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded API Key", "CRITICAL", "CWE-798", "A07"),
    (r'(?i)(secret|token|auth_token|access_token)\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded Secret / Token", "HIGH", "CWE-798", "A07"),
    (r'(?i)(aws_access_key_id|aws_secret_access_key|aws_secret)\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded AWS Credential", "CRITICAL", "CWE-798", "A07"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID Pattern Exposed", "CRITICAL", "CWE-798", "A07"),
    (r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', "Private Key in Source", "CRITICAL", "CWE-321", "A07"),
    (r'(?i)(jwt_secret|jwt_key|signing_key)\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded JWT Secret", "CRITICAL", "CWE-798", "A07"),
    (r'(?i)(db_password|database_password|db_pass|db_pwd)\s*=\s*["\'][^"\']{4,}["\']', "Hardcoded DB Password", "CRITICAL", "CWE-798", "A07"),
    (r'(?i)(client_secret|oauth_secret|app_secret)\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded OAuth Secret", "HIGH", "CWE-798", "A07"),
    (r'xox[baprs]-[0-9A-Za-z\-]{10,}', "Slack Token Exposed", "CRITICAL", "CWE-798", "A07"),
    (r'ghp_[A-Za-z0-9]{36}', "GitHub Personal Access Token Exposed", "CRITICAL", "CWE-798", "A07"),
    (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key Exposed", "CRITICAL", "CWE-798", "A07"),
    (r'sk_live_[0-9a-zA-Z]{24,}', "Stripe Live Secret Key Exposed", "CRITICAL", "CWE-798", "A07"),
    (r'(?i)DEBUG\s*=\s*True', "Debug Mode Enabled in Production", "MEDIUM", "CWE-215", "A05"),
    (r'(?i)VERIFY\s*=\s*False', "SSL Certificate Verification Disabled", "HIGH", "CWE-295", "A05"),
    (r'(?i)verify\s*=\s*False', "TLS Verification Bypass", "HIGH", "CWE-295", "A02"),
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
    def analyze(self, source_code: str, filename: str = "<stdin>", tree: Optional[ast.AST] = None) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        source_lines = source_code.splitlines()

        # AST-based analysis
        if tree is None:
            try:
                tree = ast.parse(source_code, filename=filename)
            except SyntaxError:
                pass

        if tree:
            try:
                visitor = _VulnVisitor(source_lines, filename)
                visitor.visit(tree)
                vulns.extend(visitor.vulns)
            except Exception as e:
                import logging
                logging.getLogger("shadowcoder.analyzer").error(f"AST visit failed: {e}")

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
