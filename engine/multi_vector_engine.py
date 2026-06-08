"""
Multi-Vector Attack Simulation Engine

Orchestrates 6 parallel attack vectors against a target codebase:

  1. InputVector      — SQLi, XSS, CMDi, template injection
  2. AuthVector       — JWT manipulation, weak auth, session flaws, IDOR
  3. APIVector        — Rate limiting, admin exposure, parameter tampering
  4. DataFlowVector   — Input→log→exec, deserialization, file upload chains
  5. ConfigVector     — Debug mode, secrets, unsafe env vars
  6. DependencyVector — Vulnerable packages, supply chain risks

All vectors run concurrently in a ThreadPoolExecutor.
Results feed into an upgraded AttackGraphBuilder that builds a proper
directed graph with probability-weighted edges for vis-network rendering.
"""

import ast
import re
import time
import uuid
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .static_analyzer import StaticAnalyzer, Vulnerability
from .payload_generator import PayloadGenerator
from .execution_simulator import ExecutionSimulator

log = logging.getLogger("shadowcoder.multi_vector")


# ── Result model ──────────────────────────────────────────────────────────────

@dataclass
class AttackPath:
    path_id: str
    title: str
    steps: list[str]
    entry_point: str
    impact: str
    severity: str       # CRITICAL | HIGH | MEDIUM | LOW
    probability: float  # 0.0 – 1.0


@dataclass
class VectorResult:
    vector_type: str          # "input" | "auth" | "api" | "dataflow" | "config" | "dependency"
    vector_label: str         # Human-readable
    attack_surface: str       # Brief description of what was tested
    findings: list[dict]      # Serialized vulnerability dicts
    payloads: list[dict]      # Generated payloads for key findings
    severity: str             # Worst severity found
    exploitable: bool
    attack_paths: list[AttackPath]
    scan_time_ms: int
    entry_points: list[str]   # What entry points were identified
    error: Optional[str] = None


@dataclass
class MultiVectorReport:
    scan_id: str
    target_file: str
    source_code: str
    scanned_at: str
    total_time_ms: int
    vector_results: list[VectorResult]      # One per vector
    all_findings: list[dict]                # Deduplicated union
    attack_graph: dict                      # vis-network compatible graph
    architecture: dict                      # From ArchitectureMapper
    overall_severity: str
    total_vulnerabilities: int
    exploitable_count: int
    vector_summary: dict                    # {vector_type: count}
    ai_enrichment: dict = field(default_factory=dict)



# ── Severity helpers ─────────────────────────────────────────────────────────

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _worst_severity(findings: list[dict]) -> str:
    if not findings:
        return "INFO"
    return min(
        (f.get("severity", "INFO") for f in findings),
        key=lambda s: _SEV_ORDER.get(s, 99),
    )


# ── Base Vector ───────────────────────────────────────────────────────────────

class _BaseVector:
    """Base class for all attack vectors."""

    vector_type: str = "base"
    vector_label: str = "Base Vector"
    attack_surface: str = ""

    def __init__(
        self,
        source_code: str,
        filename: str,
        tree: Optional[ast.AST],
        source_lines: list[str],
    ):
        self.source_code = source_code
        self.filename = filename
        self.tree = tree
        self.source_lines = source_lines
        self._analyzer = StaticAnalyzer()
        self._payload_gen = PayloadGenerator()
        self._simulator = ExecutionSimulator()

    def _filter_vulns(self, vulns: list[Vulnerability]) -> list[Vulnerability]:
        """Override in subclasses to filter to relevant vulnerability types."""
        return vulns

    def _build_paths(self, vulns: list[Vulnerability], payloads_map: dict) -> list[AttackPath]:
        """Override in subclasses to build specific attack paths."""
        paths = []
        for v in vulns[:3]:  # Top 3
            paths.append(AttackPath(
                path_id=f"PATH-{uuid.uuid4().hex[:6].upper()}",
                title=f"{v.vuln_type} via {v.taint_sink or 'direct call'}",
                steps=[
                    f"Identify {v.vuln_type} at line {v.line}",
                    f"Craft payload: {payloads_map.get(v.vuln_id, [{}])[0].get('raw', '[payload]')[:60]}",
                    f"Submit via entry point → reaches {v.taint_sink or v.vuln_type}",
                    "Achieve unauthorized access or data exposure",
                ],
                entry_point=v.taint_source or "user_input",
                impact=v.description,
                severity=v.severity,
                probability=v.confidence,
            ))
        return paths

    def run(self) -> VectorResult:
        t0 = time.perf_counter()
        try:
            all_vulns = self._analyzer.analyze(self.source_code, self.filename, tree=self.tree)
            vulns = self._filter_vulns(all_vulns)

            payloads_map: dict[str, list[dict]] = {}
            all_payloads: list[dict] = []
            for v in vulns[:5]:  # Limit payloads to top 5
                p = self._payload_gen.generate(v)
                payloads_map[v.vuln_id] = p
                all_payloads.extend(p)

            exploitable = any(
                self._simulator.simulate(v, payloads_map.get(v.vuln_id, []), self.source_code, tree=self.tree).get("exploitable")
                for v in vulns[:3]
            ) if vulns else False

            findings = [_vuln_to_dict(v) for v in vulns]
            paths = self._build_paths(vulns, payloads_map)
            severity = _worst_severity(findings)

            elapsed = int((time.perf_counter() - t0) * 1000)
            return VectorResult(
                vector_type=self.vector_type,
                vector_label=self.vector_label,
                attack_surface=self.attack_surface,
                findings=findings,
                payloads=all_payloads[:10],
                severity=severity,
                exploitable=exploitable,
                attack_paths=paths,
                scan_time_ms=elapsed,
                entry_points=self._discover_entry_points(),
            )
        except Exception as e:
            log.error(f"Vector {self.vector_type} failed: {e}", exc_info=True)
            elapsed = int((time.perf_counter() - t0) * 1000)
            return VectorResult(
                vector_type=self.vector_type,
                vector_label=self.vector_label,
                attack_surface=self.attack_surface,
                findings=[],
                payloads=[],
                severity="INFO",
                exploitable=False,
                attack_paths=[],
                scan_time_ms=elapsed,
                entry_points=[],
                error=str(e),
            )

    def _discover_entry_points(self) -> list[str]:
        eps = []
        if re.search(r'@app\.(get|post|put|delete|route|patch)', self.source_code):
            eps.append("HTTP API endpoints")
        if "input(" in self.source_code:
            eps.append("stdin / interactive input")
        if "sys.argv" in self.source_code or "argparse" in self.source_code:
            eps.append("CLI arguments")
        if re.search(r'request\.(args|form|json|data)', self.source_code):
            eps.append("HTTP request parameters")
        if "os.environ" in self.source_code or "os.getenv" in self.source_code:
            eps.append("Environment variables")
        return eps or ["source-level inputs"]


# ── Vector 1: Input-Based ─────────────────────────────────────────────────────

class InputVector(_BaseVector):
    vector_type = "input"
    vector_label = "Input-Based Attacks"
    attack_surface = "User-controlled data flowing into query/command/template sinks"

    _RELEVANT = {
        "SQL Injection", "Command Injection (os.system)", "Command Injection (os.popen)",
        "Command Injection (subprocess)", "Command Injection (Popen)", "Command injection",
        "Code Injection (eval)", "Code Injection (exec)", "Code injection",
        "Server-Side Template Injection (SSTI)", "Template Injection",
        "Path Traversal", "Path Traversal (pathlib)", "Path Traversal (shutil)",
        "XSS", "LDAP Injection", "NoSQL Injection (MongoDB)",
        "XML External Entity (XXE)",
    }

    def _filter_vulns(self, vulns):
        return [v for v in vulns if v.vuln_type in self._RELEVANT]

    def _build_paths(self, vulns, payloads_map):
        paths = []
        sql = [v for v in vulns if "SQL" in v.vuln_type]
        cmd = [v for v in vulns if "Command" in v.vuln_type or "Code" in v.vuln_type]
        ssti = [v for v in vulns if "Template" in v.vuln_type]

        if sql:
            v = sql[0]
            raw = payloads_map.get(v.vuln_id, [{}])[0].get("raw", "' OR '1'='1' --")
            paths.append(AttackPath(
                path_id=f"PATH-{uuid.uuid4().hex[:6].upper()}",
                title="SQL Injection → Database Dump",
                steps=[
                    f"Identify SQL sink at line {v.line} (taint: {v.taint_source or 'string concat'})",
                    f"Craft payload: {raw[:60]}",
                    "Submit via HTTP parameter or form field",
                    "Bypass authentication / dump user credentials table",
                    "Crack password hashes → full account takeover",
                ],
                entry_point="HTTP request parameter",
                impact="Full database read, authentication bypass, credential theft",
                severity="CRITICAL",
                probability=0.92,
            ))

        if cmd:
            v = cmd[0]
            raw = payloads_map.get(v.vuln_id, [{}])[0].get("raw", "; id")
            paths.append(AttackPath(
                path_id=f"PATH-{uuid.uuid4().hex[:6].upper()}",
                title="Command Injection → Remote Code Execution",
                steps=[
                    f"Identify command sink at line {v.line}",
                    f"Craft payload: {raw[:60]}",
                    "Inject via user-controlled parameter",
                    "Execute arbitrary OS commands as application user",
                    "Install reverse shell for persistent access",
                ],
                entry_point="Any user-controlled string parameter",
                impact="Full server compromise, persistent backdoor installation",
                severity="CRITICAL",
                probability=0.95,
            ))

        if ssti:
            v = ssti[0]
            paths.append(AttackPath(
                path_id=f"PATH-{uuid.uuid4().hex[:6].upper()}",
                title="SSTI → Full RCE via Python MRO",
                steps=[
                    f"Locate template rendering at line {v.line}",
                    "Probe with {{7*7}} → response '49' confirms Jinja2 SSTI",
                    "Escalate via MRO class enumeration: {{''.__class__.__mro__[1].__subclasses__()}}",
                    "Execute OS commands via subprocess class",
                    "Achieve RCE — install persistent reverse shell",
                ],
                entry_point="Template string parameter",
                impact="Remote code execution — full server compromise",
                severity="CRITICAL",
                probability=0.88,
            ))

        return paths or super()._build_paths(vulns, payloads_map)


# ── Vector 2: Authentication ──────────────────────────────────────────────────

class AuthVector(_BaseVector):
    vector_type = "auth"
    vector_label = "Authentication Attacks"
    attack_surface = "Auth logic, JWT tokens, session management, access control"

    _RELEVANT = {
        "Hardcoded Password", "Hardcoded JWT Secret", "Hardcoded Secret / Token",
        "Hardcoded API Key", "Hardcoded DB Password", "Hardcoded OAuth Secret",
        "Hardcoded password", "Hardcoded API key", "Hardcoded secret/token",
        "Insecure Randomness", "Insecure random — not cryptographically safe",
        "Weak Cryptography (MD5)", "Weak Cryptography (SHA-1)",
        "Weak cryptography", "Debug Mode Enabled in Production",
        # Auth-specific rules added by the extended static analyzer
        "Weak Default Credentials", "JWT Without Verification",
        "Missing Authentication", "Session Fixation Risk",
        "Insecure Direct Object Reference (IDOR)",
    }

    def _filter_vulns(self, vulns):
        return [v for v in vulns if v.vuln_type in self._RELEVANT]

    def _build_paths(self, vulns, payloads_map):
        paths = []
        jwt = [v for v in vulns if "JWT" in v.vuln_type]
        weak_crypto = [v for v in vulns if "Cryptography" in v.vuln_type or "Weak" in v.vuln_type]
        hardcoded = [v for v in vulns if "Hardcoded" in v.vuln_type]

        if jwt:
            v = jwt[0]
            paths.append(AttackPath(
                path_id=f"PATH-{uuid.uuid4().hex[:6].upper()}",
                title="Hardcoded JWT Secret → Admin Privilege Forgery",
                steps=[
                    f"Extract hardcoded JWT secret from source at line {v.line}",
                    "Forge token: {sub: 'admin', role: 'superuser', exp: 9999999999}",
                    "Sign with extracted secret using HS256 algorithm",
                    "Replace session cookie / Authorization header",
                    "Access all admin-only endpoints with forged identity",
                ],
                entry_point="Authorization header / cookie",
                impact="Full privilege escalation — admin account takeover",
                severity="CRITICAL",
                probability=0.97,
            ))

        if weak_crypto:
            v = weak_crypto[0]
            paths.append(AttackPath(
                path_id=f"PATH-{uuid.uuid4().hex[:6].upper()}",
                title="Weak Password Hashing → Credential Dump + Crack",
                steps=[
                    f"Password hashing uses {v.vuln_type} at line {v.line}",
                    "Dump hashes via SQL injection or database exposure",
                    "Run hashcat with rockyou.txt wordlist against MD5/SHA1",
                    "Recover plaintext passwords within minutes on GPU",
                    "Authenticate as recovered users + try credential stuffing",
                ],
                entry_point="Any database read vector",
                impact="Mass account compromise, credential reuse across services",
                severity="HIGH",
                probability=0.85,
            ))

        if hardcoded:
            v = hardcoded[0]
            paths.append(AttackPath(
                path_id=f"PATH-{uuid.uuid4().hex[:6].upper()}",
                title="Hardcoded Credential → Direct Service Authentication",
                steps=[
                    f"Credential exposed in source at line {v.line}",
                    "Credential already in git history — permanently compromised",
                    "Authenticate to the target service directly",
                    "Enumerate accessible resources with leaked identity",
                ],
                entry_point="Version control / source code access",
                impact="Direct service authentication without brute force",
                severity="CRITICAL",
                probability=0.99,
            ))

        return paths or super()._build_paths(vulns, payloads_map)


# ── Vector 3: API Abuse ───────────────────────────────────────────────────────

class APIVector(_BaseVector):
    vector_type = "api"
    vector_label = "API Abuse Paths"
    attack_surface = "API endpoints, rate limiting, admin exposure, parameter tampering"

    _RELEVANT = {
        "Server-Side Request Forgery (SSRF)", "Potential SSRF",
        "Debug Mode Enabled in Production",
        "SSL Certificate Verification Disabled", "TLS Verification Bypass",
        # Extended analyzer rules
        "Missing Rate Limiting", "Exposed Admin Endpoint",
        "Unvalidated Redirect", "Mass Assignment",
        "Insecure Direct Object Reference (IDOR)",
    }

    def _filter_vulns(self, vulns):
        return [v for v in vulns if v.vuln_type in self._RELEVANT]

    def _build_paths(self, vulns, payloads_map):
        paths = []
        ssrf = [v for v in vulns if "SSRF" in v.vuln_type]
        debug = [v for v in vulns if "Debug" in v.vuln_type]
        ssl_bypass = [v for v in vulns if "SSL" in v.vuln_type or "TLS" in v.vuln_type]

        if ssrf:
            v = ssrf[0]
            paths.append(AttackPath(
                path_id=f"PATH-{uuid.uuid4().hex[:6].upper()}",
                title="SSRF → Cloud Metadata → IAM Credential Theft",
                steps=[
                    f"Identify SSRF sink at line {v.line}: server fetches user-supplied URL",
                    "Send: http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                    "Server returns AWS IAM temporary credentials (key + secret + session token)",
                    "Use credentials with AWS CLI: aws sts get-caller-identity",
                    "Enumerate S3, RDS, Lambda — lateral movement across cloud",
                ],
                entry_point="URL parameter / API request body",
                impact="Full AWS account compromise, cloud infrastructure access",
                severity="CRITICAL",
                probability=0.88,
            ))

        if debug:
            v = debug[0]
            paths.append(AttackPath(
                path_id=f"PATH-{uuid.uuid4().hex[:6].upper()}",
                title="Debug Mode → Interactive Console RCE",
                steps=[
                    f"Debug mode enabled at line {v.line}",
                    "Trigger an exception at any endpoint: GET /nonexistent",
                    "Werkzeug debug console accessible in browser",
                    "Click 'interactive console' — execute Python code in browser",
                    "No authentication required — instant RCE",
                ],
                entry_point="Any HTTP endpoint that triggers an error",
                impact="Unauthenticated remote code execution via debug console",
                severity="CRITICAL",
                probability=0.95,
            ))

        if ssl_bypass:
            v = ssl_bypass[0]
            paths.append(AttackPath(
                path_id=f"PATH-{uuid.uuid4().hex[:6].upper()}",
                title="SSL Bypass → Man-in-the-Middle → Credential Interception",
                steps=[
                    f"TLS verification disabled at line {v.line} (verify=False)",
                    "Position between app and target server (ARP spoofing / rogue AP)",
                    "Present self-signed certificate — accepted without verification",
                    "Decrypt and modify HTTPS traffic in real time",
                    "Steal API keys, session tokens, and sensitive data in transit",
                ],
                entry_point="Network-level attacker position",
                impact="Full HTTPS traffic interception, credential theft",
                severity="HIGH",
                probability=0.75,
            ))

        return paths or super()._build_paths(vulns, payloads_map)


# ── Vector 4: Data Flow ───────────────────────────────────────────────────────

class DataFlowVector(_BaseVector):
    vector_type = "dataflow"
    vector_label = "Data Flow Attacks"
    attack_surface = "Input→log→exec chains, deserialization, file upload pipelines"

    _RELEVANT = {
        "Unsafe Deserialization (pickle)", "Unsafe Deserialization (marshal)",
        "Unsafe Deserialization (dill)", "Unsafe Deserialization (joblib)",
        "Unsafe YAML Deserialization", "Unsafe YAML load",
        "Unsafe deserialization", "Path Traversal", "Path Traversal (pathlib)",
        # Extended analyzer
        "Log Injection", "File Upload Execution Chain",
        "Unsafe Temp File (TOCTOU)", "Insecure File Permissions",
    }

    def _filter_vulns(self, vulns):
        return [v for v in vulns if v.vuln_type in self._RELEVANT]

    def _build_paths(self, vulns, payloads_map):
        paths = []
        deser = [v for v in vulns if "Deserializ" in v.vuln_type or "YAML" in v.vuln_type]
        path_trav = [v for v in vulns if "Path Traversal" in v.vuln_type]

        if deser:
            v = deser[0]
            paths.append(AttackPath(
                path_id=f"PATH-{uuid.uuid4().hex[:6].upper()}",
                title="Unsafe Deserialization → RCE via __reduce__",
                steps=[
                    f"Deserialization sink at line {v.line}: {v.vuln_type}",
                    "Craft malicious pickle with __reduce__ override:",
                    "  class Exploit: __reduce__ = lambda s: (os.system, ('id',))",
                    "Encode payload: base64(pickle.dumps(Exploit()))",
                    "Submit to any endpoint accepting serialized data",
                    "Code executes on pickle.loads() — instant RCE",
                ],
                entry_point="Any endpoint accepting binary/serialized data",
                impact="Remote code execution — OS command runs on deserialize",
                severity="CRITICAL",
                probability=0.93,
            ))

        if path_trav:
            v = path_trav[0]
            paths.append(AttackPath(
                path_id=f"PATH-{uuid.uuid4().hex[:6].upper()}",
                title="Path Traversal → Config File Leak → Auth Bypass",
                steps=[
                    f"File path constructed from user input at line {v.line}",
                    "Inject: ../../config.py  (or ../../.env)",
                    "Read SECRET_KEY, DATABASE_URL, API credentials",
                    "Use SECRET_KEY to forge Flask/Django session cookies",
                    "Authenticate as any user without credentials",
                ],
                entry_point="File download / read endpoint with user-controlled path",
                impact="Configuration secrets leaked, session forgery possible",
                severity="CRITICAL",
                probability=0.87,
            ))

        # Check for file-upload → execution pattern via regex
        if re.search(r'(save|write|upload).{0,200}(exec|system|popen|subprocess)', self.source_code, re.DOTALL):
            paths.append(AttackPath(
                path_id=f"PATH-{uuid.uuid4().hex[:6].upper()}",
                title="File Upload → Web Server Directory → Script Execution",
                steps=[
                    "Upload a .py / .php / .sh file via the upload endpoint",
                    "Server stores file in a web-accessible or executable directory",
                    "Request the uploaded file via HTTP or trigger execution",
                    "Uploaded script runs in server context → RCE",
                ],
                entry_point="File upload API endpoint",
                impact="Remote code execution via malicious uploaded file",
                severity="CRITICAL",
                probability=0.80,
            ))

        return paths or super()._build_paths(vulns, payloads_map)


# ── Vector 5: Configuration ───────────────────────────────────────────────────

class ConfigVector(_BaseVector):
    vector_type = "config"
    vector_label = "Configuration Attacks"
    attack_surface = "Debug settings, hardcoded secrets, environment variable exposure"

    _RELEVANT = {
        "Debug Mode Enabled in Production",
        "SSL Certificate Verification Disabled", "TLS Verification Bypass",
        "Hardcoded Password", "Hardcoded API Key", "Hardcoded Secret / Token",
        "Hardcoded JWT Secret", "Hardcoded DB Password", "Hardcoded OAuth Secret",
        "Hardcoded AWS Credential", "AWS Access Key ID Pattern Exposed",
        "Private Key in Source", "Slack Token Exposed",
        "GitHub Personal Access Token Exposed", "Google API Key Exposed",
        "Stripe Live Secret Key Exposed",
        "Hardcoded password", "Hardcoded API key", "Hardcoded secret/token",
        "Hardcoded AWS credential",
        # Extended analyzer
        "Insecure Default Configuration", "Exposed Environment Secret",
    }

    def _filter_vulns(self, vulns):
        return [v for v in vulns if v.vuln_type in self._RELEVANT]

    def _build_paths(self, vulns, payloads_map):
        paths = []
        aws = [v for v in vulns if "AWS" in v.vuln_type]
        secrets = [v for v in vulns if "Hardcoded" in v.vuln_type and "AWS" not in v.vuln_type]
        private_key = [v for v in vulns if "Private Key" in v.vuln_type]

        if aws:
            v = aws[0]
            paths.append(AttackPath(
                path_id=f"PATH-{uuid.uuid4().hex[:6].upper()}",
                title="AWS Credential Exposure → Full Cloud Account Takeover",
                steps=[
                    f"AWS credential found in source at line {v.line}",
                    "Run: aws sts get-caller-identity (confirm key validity)",
                    "Run: aws s3 ls --recursive (enumerate all S3 buckets)",
                    "Run: aws iam list-users && aws iam list-roles",
                    "Escalate via IAM privilege escalation techniques",
                    "Full cloud account takeover — stop instances, delete data, mine crypto",
                ],
                entry_point="Source code / git history access",
                impact="Complete AWS cloud account compromise",
                severity="CRITICAL",
                probability=0.99,
            ))

        if private_key:
            v = private_key[0]
            paths.append(AttackPath(
                path_id=f"PATH-{uuid.uuid4().hex[:6].upper()}",
                title="Private Key in Source → Certificate Spoofing / SSH Access",
                steps=[
                    f"Private key exposed in source at line {v.line}",
                    "Extract RSA/EC private key bytes",
                    "Use for SSH authentication: ssh -i stolen_key user@server",
                    "Or spoof TLS certificates for MITM attacks",
                    "Persist access — key remains valid until rotated",
                ],
                entry_point="Source code / git repository",
                impact="Cryptographic identity theft, SSH access, TLS spoofing",
                severity="CRITICAL",
                probability=0.98,
            ))

        if secrets:
            v = secrets[0]
            paths.append(AttackPath(
                path_id=f"PATH-{uuid.uuid4().hex[:6].upper()}",
                title="Hardcoded Secret → Service Authentication Bypass",
                steps=[
                    f"{v.vuln_type} found at line {v.line}",
                    "Credential in git history — cannot be fully revoked without rotation",
                    "Authenticate directly to dependent service",
                    "Exfiltrate data or perform privileged actions",
                ],
                entry_point="Source code repository",
                impact="Direct authenticated access to dependent service",
                severity=v.severity,
                probability=0.95,
            ))

        return paths or super()._build_paths(vulns, payloads_map)


# ── Vector 6: Dependency ──────────────────────────────────────────────────────

class DependencyVector(_BaseVector):
    vector_type = "dependency"
    vector_label = "Dependency Attacks"
    attack_surface = "Third-party packages, supply chain risks, vulnerable imports"

    # Known vulnerable package patterns (simplified — in production, use pip-audit / safety DB)
    _KNOWN_RISKY_IMPORTS = {
        "pickle": ("Unsafe Deserialization", "CRITICAL", "Pickle allows arbitrary code execution"),
        "yaml": ("Potential Unsafe YAML", "HIGH", "yaml.load() without SafeLoader enables RCE"),
        "marshal": ("Unsafe Deserialization", "HIGH", "marshal.loads executes arbitrary bytecode"),
        "dill": ("Unsafe Deserialization", "CRITICAL", "dill extends pickle — arbitrary code execution"),
        "xmlrpc": ("XML-RPC Attack Surface", "MEDIUM", "XML-RPC is a common target for injection attacks"),
        "telnetlib": ("Insecure Protocol", "HIGH", "Telnet transmits data in plaintext"),
        "ftplib": ("Insecure Protocol", "MEDIUM", "FTP lacks encryption — credentials sent in plaintext"),
        "cgi": ("CGI Injection Risk", "HIGH", "Python cgi module is deprecated and vulnerable to injection"),
    }

    def _filter_vulns(self, vulns):
        # Dependency vector looks at import-level risks
        import_risk_types = {
            "Unsafe deserialization", "Potential unsafe YAML load",
            "Insecure random — not cryptographically safe",
        }
        return [v for v in vulns if v.vuln_type in import_risk_types or "import" in v.description.lower()]

    def _find_risky_imports(self) -> list[dict]:
        """Identify risky imports in the source."""
        findings = []
        if self.tree:
            for node in ast.walk(self.tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    for alias in node.names:
                        mod = alias.name.split(".")[0]
                        if mod in self._KNOWN_RISKY_IMPORTS:
                            vtype, sev, desc = self._KNOWN_RISKY_IMPORTS[mod]
                            findings.append({
                                "vuln_id": f"DEP-{mod.upper()}",
                                "vuln_type": vtype,
                                "severity": sev,
                                "line": node.lineno,
                                "description": f"Risky dependency '{mod}': {desc}",
                                "package": mod,
                                "cwe": "CWE-1104",
                                "owasp": "OWASP A06",
                            })
        return findings

    def run(self) -> VectorResult:
        t0 = time.perf_counter()
        try:
            all_vulns = self._analyzer.analyze(self.source_code, self.filename, tree=self.tree)
            vulns = self._filter_vulns(all_vulns)
            dep_findings = self._find_risky_imports()

            findings = [_vuln_to_dict(v) for v in vulns] + dep_findings

            paths = []
            if dep_findings:
                worst = min(dep_findings, key=lambda f: _SEV_ORDER.get(f["severity"], 99))
                paths.append(AttackPath(
                    path_id=f"PATH-{uuid.uuid4().hex[:6].upper()}",
                    title=f"Risky Dependency '{worst['package']}' → {worst['vuln_type']}",
                    steps=[
                        f"Package '{worst['package']}' imported at line {worst['line']}",
                        worst["description"],
                        "Attacker crafts malicious payload targeting this library",
                        "Submit via any endpoint that processes untrusted data through this lib",
                        "Achieve code execution / data exfiltration",
                    ],
                    entry_point="Any endpoint using this library",
                    impact=worst["description"],
                    severity=worst["severity"],
                    probability=0.80,
                ))

            # Supply chain risk note
            if re.search(r'pip install|requirements\.txt|setup\.py', self.source_code):
                findings.append({
                    "vuln_type": "Supply Chain Risk",
                    "severity": "MEDIUM",
                    "description": "Dependencies installed at runtime — typosquatting and dependency confusion risks apply",
                    "line": 0,
                    "cwe": "CWE-1104",
                    "owasp": "OWASP A06",
                })

            severity = _worst_severity(findings)
            elapsed = int((time.perf_counter() - t0) * 1000)
            return VectorResult(
                vector_type=self.vector_type,
                vector_label=self.vector_label,
                attack_surface=self.attack_surface,
                findings=findings,
                payloads=[],
                severity=severity,
                exploitable=any(f.get("severity") == "CRITICAL" for f in findings),
                attack_paths=paths,
                scan_time_ms=elapsed,
                entry_points=["Package import", "pip install pipeline"],
            )
        except Exception as e:
            log.error(f"DependencyVector failed: {e}", exc_info=True)
            elapsed = int((time.perf_counter() - t0) * 1000)
            return VectorResult(
                vector_type=self.vector_type,
                vector_label=self.vector_label,
                attack_surface=self.attack_surface,
                findings=[], payloads=[], severity="INFO",
                exploitable=False, attack_paths=[], scan_time_ms=elapsed,
                entry_points=[], error=str(e),
            )


# ── Attack Graph Builder ──────────────────────────────────────────────────────

def build_attack_graph(
    vector_results: list[VectorResult],
    arch_map: Optional[dict] = None,
) -> dict:
    """
    Build a vis-network compatible directed attack graph.

    Node types:
      - entry_point   (cyan)  — where attacker gets input in
      - vuln          (red/orange/yellow) — vulnerability nodes
      - pivot         (purple) — intermediate access gained
      - impact        (dark red) — final impact

    Edge:  source_id → target_id with label + probability
    """
    nodes = []
    edges = []
    node_ids_seen: set[str] = set()

    def add_node(node_id, label, node_type, severity="INFO", vector="", metadata=None):
        if node_id in node_ids_seen:
            return
        node_ids_seen.add(node_id)
        color = _node_color(node_type, severity)
        nodes.append({
            "id": node_id,
            "label": label,
            "type": node_type,
            "severity": severity,
            "vector": vector,
            "color": color,
            "metadata": metadata or {},
        })

    def add_edge(source, target, label="", probability=1.0, steps=None):
        edges.append({
            "id": f"E-{uuid.uuid4().hex[:6]}",
            "from": source,
            "to": target,
            "label": label,
            "probability": round(probability, 2),
            "steps": steps or [],
            "width": max(1, int(probability * 4)),
            "arrows": "to",
        })

    # ── Entry point nodes (from architecture map or discovered) ──────────────
    ep_node_map: dict[str, str] = {}  # label → node_id

    if arch_map and arch_map.get("entry_points"):
        for ep in arch_map["entry_points"]:
            nid = ep["ep_id"]
            add_node(nid, ep["label"], "entry_point", ep["risk_level"], metadata=ep)
            ep_node_map[ep["kind"]] = nid
    else:
        # Auto-discover from vector results
        all_eps = set()
        for vr in vector_results:
            all_eps.update(vr.entry_points)
        for i, ep_label in enumerate(all_eps):
            nid = f"EP-AUTO-{i:03d}"
            add_node(nid, ep_label, "entry_point", "MEDIUM")
            ep_node_map[ep_label] = nid

    # ── Vulnerability nodes + attack path edges ───────────────────────────────
    for vr in vector_results:
        vector_node_id = f"VECTOR-{vr.vector_type.upper()}"
        add_node(vector_node_id, vr.vector_label, "vector_class", vr.severity, vr.vector_type)

        # Connect entry points to this vector
        for ep_label, ep_id in ep_node_map.items():
            add_edge(ep_id, vector_node_id, "feeds into", probability=0.7)

        # Add findings as vuln nodes
        for finding in vr.findings[:5]:  # Cap per vector
            f_id = finding.get("vuln_id") or f"F-{uuid.uuid4().hex[:8]}"
            f_sev = finding.get("severity", "MEDIUM")
            f_type = finding.get("vuln_type", "Unknown")
            f_line = finding.get("line", 0)
            add_node(
                f_id,
                f"{f_type}\nL{f_line}",
                "vuln",
                f_sev,
                vr.vector_type,
                metadata=finding,
            )
            add_edge(vector_node_id, f_id, f_type, probability=0.85)

        # Add attack paths as impact nodes
        for path in vr.attack_paths:
            pivot_id = f"PIVOT-{path.path_id}"
            add_node(pivot_id, path.title, "pivot", path.severity, vr.vector_type,
                     metadata={"steps": path.steps, "impact": path.impact})

            # Connect findings that are part of this path to the pivot
            for finding in vr.findings[:2]:
                f_id = finding.get("vuln_id") or "F-unknown"
                if f_id in node_ids_seen:
                    add_edge(f_id, pivot_id, "exploits", probability=path.probability,
                             steps=path.steps[:2])

            # Impact node
            impact_id = f"IMPACT-{path.path_id}"
            impact_label = path.impact[:40] + ("…" if len(path.impact) > 40 else "")
            add_node(impact_id, impact_label, "impact", path.severity, vr.vector_type)
            add_edge(pivot_id, impact_id, "achieves", probability=path.probability,
                     steps=path.steps[-2:])

    # ── Cross-vector chain edges (e.g. SQLi → AuthBypass) ────────────────────
    _add_cross_vector_edges(vector_results, nodes, edges, node_ids_seen)

    return {
        "nodes": nodes,
        "edges": edges,
        "summary": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "entry_points": len(ep_node_map),
            "critical_paths": sum(
                1 for p in (path for vr in vector_results for path in vr.attack_paths)
                if p.severity == "CRITICAL"
            ),
        },
    }


def _add_cross_vector_edges(vector_results, nodes, edges, node_ids_seen):
    """Add edges that connect findings across different vectors (exploit chains)."""
    vr_by_type = {vr.vector_type: vr for vr in vector_results}

    # Pattern: SQLi (input) → Auth Bypass → API Escalation
    if "input" in vr_by_type and "auth" in vr_by_type:
        input_vulns = vr_by_type["input"].findings
        auth_vulns = vr_by_type["auth"].findings
        if input_vulns and auth_vulns:
            sql_finding = next((f for f in input_vulns if "SQL" in f.get("vuln_type", "")), None)
            auth_finding = next((f for f in auth_vulns if "Hardcoded" in f.get("vuln_type", "")
                                 or "Weak" in f.get("vuln_type", "")), None)
            if sql_finding and auth_finding:
                cross_id = f"CROSS-SQLI-AUTH"
                if cross_id not in node_ids_seen:
                    node_ids_seen.add(cross_id)
                    nodes.append({
                        "id": cross_id, "label": "SQLi + Weak Auth\nChained Attack",
                        "type": "pivot", "severity": "CRITICAL", "vector": "cross",
                        "color": {"background": "#ff2d55", "border": "#ff6b9d"},
                        "metadata": {
                            "description": "SQL injection extracts password hashes; weak hashing allows rapid crack → full account takeover"
                        },
                    })
                    sql_id = sql_finding.get("vuln_id", "")
                    auth_id = auth_finding.get("vuln_id", "")
                    if sql_id in node_ids_seen:
                        edges.append({
                            "id": f"E-{uuid.uuid4().hex[:6]}",
                            "from": sql_id, "to": cross_id,
                            "label": "dump hashes", "probability": 0.90,
                            "width": 3, "arrows": "to",
                            "steps": ["Inject UNION SELECT payload", "Extract MD5/SHA1 hashes"],
                        })
                    if auth_id in node_ids_seen:
                        edges.append({
                            "id": f"E-{uuid.uuid4().hex[:6]}",
                            "from": auth_id, "to": cross_id,
                            "label": "crack hashes", "probability": 0.88,
                            "width": 3, "arrows": "to",
                            "steps": ["Run hashcat with rockyou.txt", "Recover plaintext passwords"],
                        })

    # Pattern: Config leak → API escalation
    if "config" in vr_by_type and "api" in vr_by_type:
        cfg_findings = vr_by_type["config"].findings
        api_findings = vr_by_type["api"].findings
        if cfg_findings and api_findings:
            cross_id = "CROSS-CONFIG-API"
            if cross_id not in node_ids_seen:
                node_ids_seen.add(cross_id)
                nodes.append({
                    "id": cross_id, "label": "Config Leak\n→ API Escalation",
                    "type": "impact", "severity": "CRITICAL", "vector": "cross",
                    "color": {"background": "#8b00ff", "border": "#b94fff"},
                    "metadata": {"description": "Leaked secrets enable authenticated API abuse"},
                })
                cfg_id = cfg_findings[0].get("vuln_id", "")
                if cfg_id and cfg_id in {n["id"] for n in nodes}:
                    edges.append({
                        "id": f"E-{uuid.uuid4().hex[:6]}",
                        "from": cfg_id, "to": cross_id,
                        "label": "provides auth", "probability": 0.92,
                        "width": 3, "arrows": "to",
                        "steps": ["Extract leaked secret", "Authenticate to API"],
                    })


def _node_color(node_type: str, severity: str) -> dict:
    if node_type == "entry_point":
        return {"background": "#0088cc", "border": "#00bfff", "highlight": {"background": "#00aaff"}}
    if node_type == "vector_class":
        return {"background": "#1a1a2e", "border": "#4a4a8a", "highlight": {"background": "#2a2a4e"}}
    if node_type == "vuln":
        sev_colors = {
            "CRITICAL": {"background": "#ff2d55", "border": "#ff6b9d", "highlight": {"background": "#ff5577"}},
            "HIGH":     {"background": "#ff9500", "border": "#ffb84d", "highlight": {"background": "#ffaa33"}},
            "MEDIUM":   {"background": "#ffd60a", "border": "#ffe566", "highlight": {"background": "#ffe033"}},
            "LOW":      {"background": "#30d158", "border": "#6ee090", "highlight": {"background": "#50e078"}},
        }
        return sev_colors.get(severity, sev_colors["MEDIUM"])
    if node_type == "pivot":
        return {"background": "#bf5af2", "border": "#d084f7", "highlight": {"background": "#cc66ff"}}
    if node_type == "impact":
        return {"background": "#8b0000", "border": "#cc0000", "highlight": {"background": "#aa0000"}}
    return {"background": "#2c2c2e", "border": "#555"}


# ── Main Engine ───────────────────────────────────────────────────────────────

class MultiVectorEngine:
    """
    Orchestrates parallel execution of all attack vectors.

    Usage:
        engine = MultiVectorEngine()
        report = engine.scan(source_code, filename="app.py")
        # report.attack_graph  → vis-network compatible dict
        # report.vector_results → per-vector findings
    """

    _VECTOR_CLASSES = {
        "input":      InputVector,
        "auth":       AuthVector,
        "api":        APIVector,
        "dataflow":   DataFlowVector,
        "config":     ConfigVector,
        "dependency": DependencyVector,
    }

    def __init__(self, max_workers: int = 6):
        self._max_workers = max_workers

    def scan(
        self,
        source_code: str,
        filename: str = "<stdin>",
        vectors: Optional[list[str]] = None,
        progress_callback=None,  # Optional callable(vector_type, result)
        use_ai: bool = False,
    ) -> MultiVectorReport:
        """
        Run multi-vector scan. Returns MultiVectorReport.

        Args:
            source_code: Python source to analyze
            filename: source file name (for display)
            vectors: subset of vectors to run; None = all 6
            progress_callback: called when each vector completes (thread-safe)
        """
        from datetime import datetime, timezone
        t0 = time.perf_counter()

        # Parse AST once, share across all vectors
        tree: Optional[ast.AST] = None
        try:
            tree = ast.parse(source_code, filename=filename)
        except SyntaxError:
            pass

        source_lines = source_code.splitlines()
        active_vectors = vectors or list(self._VECTOR_CLASSES.keys())

        # ── Architecture mapping ──────────────────────────────────────────────
        arch_map: dict = {}
        try:
            from .architecture_mapper import ArchitectureMapper, arch_map_to_dict
            mapper = ArchitectureMapper()
            arch = mapper.map(source_code, filename)
            arch_map = arch_map_to_dict(arch)
        except Exception as e:
            log.warning(f"Architecture mapping failed: {e}")

        # ── Parallel vector execution ─────────────────────────────────────────
        vector_results: list[VectorResult] = []

        with ThreadPoolExecutor(max_workers=min(self._max_workers, len(active_vectors)),
                                thread_name_prefix="mvector") as executor:
            futures = {}
            for vtype in active_vectors:
                cls = self._VECTOR_CLASSES.get(vtype)
                if cls:
                    vector = cls(source_code, filename, tree, source_lines)
                    futures[executor.submit(vector.run)] = vtype

            for future in as_completed(futures):
                vtype = futures[future]
                try:
                    result = future.result()
                except Exception as e:
                    log.error(f"Vector {vtype} raised: {e}")
                    result = VectorResult(
                        vector_type=vtype,
                        vector_label=self._VECTOR_CLASSES[vtype].vector_label,
                        attack_surface="",
                        findings=[], payloads=[], severity="INFO",
                        exploitable=False, attack_paths=[], scan_time_ms=0,
                        entry_points=[], error=str(e),
                    )
                vector_results.append(result)
                if progress_callback:
                    try:
                        progress_callback(vtype, result)
                    except Exception:
                        pass

        # Sort results by vector order for consistent display
        order = list(self._VECTOR_CLASSES.keys())
        vector_results.sort(key=lambda r: order.index(r.vector_type) if r.vector_type in order else 99)

        # ── Aggregate all findings ────────────────────────────────────────────
        all_findings: list[dict] = []
        seen_ids: set[str] = set()
        for vr in vector_results:
            for f in vr.findings:
                fid = f.get("vuln_id", "")
                if fid and fid not in seen_ids:
                    seen_ids.add(fid)
                    f["vector_type"] = vr.vector_type
                    all_findings.append(f)

        # ── Build attack graph ────────────────────────────────────────────────
        attack_graph = build_attack_graph(vector_results, arch_map)

        # ── Summary stats ────────────────────────────────────────────────────
        overall_sev = _worst_severity(all_findings)
        exploitable_count = sum(1 for vr in vector_results if vr.exploitable)
        vector_summary = {vr.vector_type: len(vr.findings) for vr in vector_results}

        # ── AI Enrichment ─────────────────────────────────────────────────────
        ai_enrichment = {}
        if use_ai:
            try:
                from .ai_service import AIServiceSync
                ai_service = AIServiceSync()
                
                # 1. Per-vector narratives
                vector_narratives = {}
                for vr in vector_results:
                    findings_summary = ", ".join(set(f.get("vuln_type", "") for f in vr.findings))
                    paths_list = [p.title for p in vr.attack_paths]
                    
                    narrative = ai_service.mv_vector_narrative(
                        vector_type=vr.vector_label,
                        findings_summary=findings_summary,
                        attack_paths=paths_list
                    )
                    vector_narratives[vr.vector_type] = narrative
                
                # 2. Attack graph executive summary
                top_chains = []
                for vr in vector_results:
                    for p in vr.attack_paths[:2]:
                        top_chains.append(f"{vr.vector_label}: {p.title} (Severity: {p.severity})")
                
                graph_summary = ai_service.mv_graph_summary(
                    total_vulns=len(all_findings),
                    exploitable=exploitable_count,
                    overall_sev=overall_sev,
                    top_chains=top_chains[:5]
                )
                
                # 3. Path fixes
                path_fixes = {}
                for vr in vector_results:
                    for p in vr.attack_paths:
                        fix_text = ai_service.mv_path_fix(
                            path_title=p.title,
                            steps=p.steps,
                            impact=p.impact
                        )
                        path_fixes[p.path_id] = fix_text
                
                ai_enrichment = {
                    "vector_narratives": vector_narratives,
                    "graph_summary": graph_summary,
                    "path_fixes": path_fixes
                }
            except Exception as e:
                log.warning(f"AI enrichment failed: {e}")

        total_time_ms = int((time.perf_counter() - t0) * 1000)

        return MultiVectorReport(
            scan_id=f"MV-{uuid.uuid4().hex[:8].upper()}",
            target_file=filename,
            source_code=source_code,
            scanned_at=datetime.now(timezone.utc).isoformat(),
            total_time_ms=total_time_ms,
            vector_results=vector_results,
            all_findings=all_findings,
            attack_graph=attack_graph,
            architecture=arch_map,
            overall_severity=overall_sev,
            total_vulnerabilities=len(all_findings),
            exploitable_count=exploitable_count,
            vector_summary=vector_summary,
            ai_enrichment=ai_enrichment,
        )


# ── Serialization ─────────────────────────────────────────────────────────────

def _vuln_to_dict(v: Vulnerability) -> dict:
    return {
        "vuln_id": v.vuln_id,
        "vuln_type": v.vuln_type,
        "severity": v.severity,
        "line": v.line,
        "col": v.col,
        "description": v.description,
        "code_snippet": v.code_snippet,
        "cwe": v.cwe,
        "owasp": v.owasp,
        "taint_source": v.taint_source,
        "taint_sink": v.taint_sink,
        "confidence": v.confidence,
    }


def multi_vector_report_to_dict(report: MultiVectorReport) -> dict:
    """Serialize MultiVectorReport to JSON-compatible dict for API responses."""
    return {
        "scan_id": report.scan_id,
        "target_file": report.target_file,
        "scanned_at": report.scanned_at,
        "total_time_ms": report.total_time_ms,
        "overall_severity": report.overall_severity,
        "total_vulnerabilities": report.total_vulnerabilities,
        "exploitable_count": report.exploitable_count,
        "vector_summary": report.vector_summary,
        "vector_results": [
            {
                "vector_type": vr.vector_type,
                "vector_label": vr.vector_label,
                "attack_surface": vr.attack_surface,
                "severity": vr.severity,
                "exploitable": vr.exploitable,
                "finding_count": len(vr.findings),
                "findings": vr.findings,
                "payloads": vr.payloads,
                "attack_paths": [
                    {
                        "path_id": p.path_id, "title": p.title, "steps": p.steps,
                        "entry_point": p.entry_point, "impact": p.impact,
                        "severity": p.severity, "probability": p.probability,
                    }
                    for p in vr.attack_paths
                ],
                "entry_points": vr.entry_points,
                "scan_time_ms": vr.scan_time_ms,
                "error": vr.error,
            }
            for vr in report.vector_results
        ],
        "all_findings": report.all_findings,
        "attack_graph": report.attack_graph,
        "architecture": report.architecture,
        "ai_enrichment": report.ai_enrichment,
    }
