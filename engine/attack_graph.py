"""
Attack Graph Builder — chains individual vulnerabilities into multi-step exploit sequences.
"""

import uuid
from itertools import combinations

CHAIN_RULES = [
    {
        "triggers": {"Server-Side Request Forgery (SSRF)", "Potential SSRF"},
        "targets": {"Hardcoded AWS Credential", "Hardcoded API key", "Hardcoded AWS credential"},
        "name": "SSRF → Cloud Credential Theft",
        "description": "SSRF attack reaches cloud metadata endpoint and retrieves IAM credentials. Combined with hardcoded fallback keys, attacker achieves full cloud account access.",
        "steps": [
            "Craft SSRF payload targeting http://169.254.169.254/latest/meta-data/",
            "Retrieve IAM security credentials from instance metadata",
            "Combine with hardcoded credentials found in source",
            "Authenticate to AWS APIs — full account takeover",
        ],
        "severity": "CRITICAL",
    },
    {
        "triggers": {"SQL Injection"},
        "targets": {"Weak Cryptography (MD5)", "Weak Cryptography (SHA-1)", "Weak cryptography", "Hardcoded password", "Hardcoded Password"},
        "name": "SQLi → Password Dump → Account Takeover",
        "description": "SQL injection extracts password hashes. Weak hashing (MD5/SHA1) allows rapid cracking. Recovered credentials enable account takeover.",
        "steps": [
            "Inject UNION SELECT payload to dump users table",
            "Extract MD5/SHA1 password hashes",
            "Crack hashes offline in minutes using GPU + rainbow tables",
            "Authenticate with recovered plaintext passwords",
        ],
        "severity": "CRITICAL",
    },
    {
        "triggers": {"Path Traversal", "Path Traversal (pathlib)", "Path Traversal (shutil)"},
        "targets": {"Hardcoded Secret / Token", "Hardcoded API Key", "Hardcoded Password", "Hardcoded secret/token", "Hardcoded API key", "Hardcoded password"},
        "name": "Path Traversal → Config Leak → Auth Bypass",
        "description": "Path traversal reads config files containing hardcoded credentials. Attacker authenticates directly with exfiltrated secrets.",
        "steps": [
            "Use ../../ traversal to read /settings.py or /.env",
            "Extract DATABASE_URL, SECRET_KEY, API credentials",
            "Authenticate to internal services using leaked credentials",
            "Escalate to admin access if secret key enables session forgery",
        ],
        "severity": "CRITICAL",
    },
    {
        "triggers": {"Command injection", "Code injection", "Unsafe deserialization",
                     "Command Injection (os.system)", "Command Injection (os.popen)",
                     "Command Injection (subprocess)", "Code Injection (eval)",
                     "Unsafe Deserialization (pickle)"},
        "targets": {"Command injection", "Code injection",
                    "Command Injection (os.system)", "Command Injection (os.popen)"},
        "name": "RCE → Persistence → Privilege Escalation",
        "description": "Remote code execution used to install a persistent backdoor. If the application runs with elevated privileges, attacker escalates to root.",
        "steps": [
            "Exploit RCE vulnerability to execute OS commands",
            "Write cron job or systemd service for persistence",
            "Enumerate SUID binaries and writable cron directories",
            "Escalate to root via misconfigured sudo or SUID exploit",
        ],
        "severity": "CRITICAL",
    },
    {
        "triggers": {"Unsafe Deserialization (pickle)", "Unsafe deserialization"},
        "targets": {"Command injection", "Code injection", "Command Injection (os.system)"},
        "name": "Deserialization → RCE Chain",
        "description": "Unsafe deserialization (pickle/yaml) executes arbitrary code on load. Chained with other injection points for multi-vector attack.",
        "steps": [
            "Craft malicious pickle payload with __reduce__ override",
            "Submit via any endpoint accepting serialized data",
            "Payload executes on deserialize — instant RCE",
            "Chain with command injection for persistent access",
        ],
        "severity": "CRITICAL",
    },
    {
        "triggers": {"Weak Cryptography (MD5)", "Weak Cryptography (SHA-1)", "Weak cryptography"},
        "targets": {"SQL Injection", "Hardcoded password", "Hardcoded Password"},
        "name": "Weak Crypto → Credential Brute Force",
        "description": "MD5/SHA1 password hashes are trivially crackable. Combined with SQL injection to dump hashes, attacker recovers all passwords.",
        "steps": [
            "Dump password hashes via SQL injection",
            "Feed MD5/SHA1 hashes into hashcat with rockyou.txt",
            "Recover plaintext passwords within minutes",
            "Authenticate to application and any service reusing the password",
        ],
        "severity": "HIGH",
    },
    {
        "triggers": {"Server-Side Template Injection (SSTI)"},
        "targets": {"Command injection", "Command Injection (os.system)"},
        "name": "SSTI → Full RCE Chain",
        "description": "Server-Side Template Injection in Jinja2/Mako enables full OS command execution via Python MRO class enumeration.",
        "steps": [
            "Identify template input — test with {{7*7}} probe",
            "Confirm SSTI: response contains 49 → Jinja2 confirmed",
            "Escalate via MRO chain to enumerate subprocess classes",
            "Execute OS commands: id, whoami, cat /etc/shadow",
            "Install reverse shell for persistent access",
        ],
        "severity": "CRITICAL",
    },
    {
        "triggers": {"XML External Entity (XXE)"},
        "targets": {"Server-Side Request Forgery (SSRF)", "Potential SSRF", "Hardcoded AWS Credential"},
        "name": "XXE → SSRF → Cloud Credential Theft",
        "description": "XXE injection issues server-side HTTP requests to cloud metadata endpoints, bypassing network-layer SSRF protections.",
        "steps": [
            "Submit XXE payload: <!ENTITY xxe SYSTEM 'http://169.254.169.254/latest/meta-data/'>",
            "Server fetches AWS metadata — retrieves IAM security credentials",
            "Combine with hardcoded credentials for full account access",
            "Enumerate S3 buckets, RDS instances, Lambda functions",
            "Lateral movement across cloud infrastructure",
        ],
        "severity": "CRITICAL",
    },
    {
        "triggers": {"NoSQL Injection (MongoDB)"},
        "targets": {"Hardcoded Password", "Hardcoded DB Password", "Weak Cryptography (MD5)"},
        "name": "NoSQL Auth Bypass → Full Database Exfiltration",
        "description": "MongoDB $ne operator injection bypasses login. Once authenticated, attacker enumerates all collections and exfiltrates user data.",
        "steps": [
            "Inject {username: {$ne: null}, password: {$ne: null}} as login payload",
            "Authentication bypassed — logged in as first user in collection",
            "Enumerate all collections: db.getCollectionNames()",
            "Dump all user records including hashed passwords",
            "Crack MD5/SHA1 hashes offline — recover plaintext credentials",
        ],
        "severity": "CRITICAL",
    },
    {
        "triggers": {"Insecure Randomness", "Insecure random — not cryptographically safe"},
        "targets": {"SQL Injection", "Hardcoded Password", "Hardcoded secret/token", "Hardcoded Secret / Token"},
        "name": "Predictable Token → Account Takeover",
        "description": "Mersenne Twister PRNG used for security tokens is fully predictable after observing 624 outputs. Attacker recovers state and predicts future tokens.",
        "steps": [
            "Observe 624 consecutive random outputs from the application",
            "Reconstruct full Mersenne Twister internal state",
            "Predict next N values — including password reset tokens",
            "Request password reset for admin@target.com",
            "Predict the reset token and take over admin account",
        ],
        "severity": "HIGH",
    },
    {
        "triggers": {"Hardcoded JWT Secret", "Hardcoded Secret / Token", "Hardcoded secret/token"},
        "targets": {"SQL Injection", "Command injection", "Command Injection (os.system)"},
        "name": "Hardcoded JWT Secret → Admin Privilege Escalation",
        "description": "Hardcoded JWT signing secret allows forging arbitrary tokens. Attacker mints an admin JWT and exploits injection vulnerabilities with elevated privileges.",
        "steps": [
            "Extract hardcoded JWT secret from source code",
            "Forge JWT: {sub: 'admin', role: 'superuser', exp: 9999999999}",
            "Authenticate to all protected endpoints with forged token",
            "Access admin panel — trigger SQL injection / RCE in privileged context",
            "Full application compromise with admin database access",
        ],
        "severity": "CRITICAL",
    },
]


class AttackGraphBuilder:
    def build(self, attack_results: list) -> list[dict]:
        """Build attack chains from AttackResult objects. Returns sorted chain dicts."""
        if not attack_results:
            return []

        chains = []

        # ── Dynamic artifact-based chaining ──────────────────────────────────
        all_artifacts = []
        for ar in attack_results:
            all_artifacts.extend(ar.simulation.get("harvested_artifacts", []))

        injection_types = {
            "SQL Injection", "Command injection", "Code injection",
            "Command Injection (os.system)", "Command Injection (os.popen)",
            "Command Injection (subprocess)", "Code Injection (eval)",
        }
        for ar in attack_results:
            v = ar.vulnerability
            if v.vuln_type in injection_types:
                creds = [a for a in all_artifacts if a["type"] == "credential"]
                if creds:
                    chains.append({
                        "chain_id": f"CHAIN-{uuid.uuid4().hex[:6].upper()}",
                        "name": f"Leaked Credentials → {v.vuln_type} Escalation",
                        "description": f"Attacker uses credentials from {creds[0]['vuln_id']} to authenticate and trigger {v.vuln_type} in a protected context.",
                        "steps": [
                            f"Identify {v.vuln_type} at line {v.line}",
                            f"Harvest credentials from {creds[0]['vuln_id']}",
                            "Authenticate to management console",
                            f"Trigger {v.vuln_type} with administrative privileges",
                        ],
                        "severity": "CRITICAL",
                        "node_ids": [creds[0]["vuln_id"], v.vuln_id],
                        "vulnerability_count": 2,
                    })

        # ── Rule-based chaining ───────────────────────────────────────────────
        for rule in CHAIN_RULES:
            triggers = rule["triggers"]
            targets  = rule["targets"]
            trigger_vulns = [ar for ar in attack_results if ar.vulnerability.vuln_type in triggers]
            target_vulns  = [ar for ar in attack_results
                             if ar.vulnerability.vuln_type in targets
                             and ar.vulnerability.vuln_type not in triggers]
            if trigger_vulns and target_vulns:
                node_ids = (
                    [tv.vulnerability.vuln_id for tv in trigger_vulns[:2]] +
                    [tv.vulnerability.vuln_id for tv in target_vulns[:2]]
                )
                chains.append({
                    "chain_id": f"CHAIN-{uuid.uuid4().hex[:6].upper()}",
                    "name": rule["name"],
                    "description": rule["description"],
                    "steps": rule["steps"],
                    "severity": rule["severity"],
                    "node_ids": list(dict.fromkeys(node_ids)),
                    "trigger_types": list(triggers),
                    "target_types": list(targets),
                    "vulnerability_count": len(node_ids),
                })

        # ── Direct RCE chains ─────────────────────────────────────────────────
        rce_results = [ar for ar in attack_results if ar.simulation.get("rce_possible") and ar.exploitable]
        for ar in rce_results:
            chains.append({
                "chain_id": f"CHAIN-{uuid.uuid4().hex[:6].upper()}",
                "name": f"Direct RCE via {ar.vulnerability.vuln_type}",
                "description": (
                    f"Direct exploitation of {ar.vulnerability.vuln_type} at line "
                    f"{ar.vulnerability.line} achieves remote code execution."
                ),
                "steps": ar.simulation.get("execution_path", [
                    f"Identify {ar.vulnerability.vuln_type} sink at line {ar.vulnerability.line}",
                    "Craft exploit payload targeting the vulnerable parameter",
                    "Achieve remote code execution on the server",
                    "Establish persistent reverse shell",
                ]),
                "severity": "CRITICAL",
                "node_ids": [ar.vulnerability.vuln_id],
                "trigger_types": [ar.vulnerability.vuln_type],
                "target_types": [],
                "vulnerability_count": 1,
            })

        # ── Deduplicate + sort ────────────────────────────────────────────────
        seen = set()
        unique = []
        for c in chains:
            if c["name"] not in seen:
                seen.add(c["name"])
                unique.append(c)

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        return sorted(unique, key=lambda c: (sev_order.get(c["severity"], 4), -c["vulnerability_count"]))
