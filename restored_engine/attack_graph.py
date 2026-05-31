"""
Attack Graph Builder — chains individual vulnerabilities into multi-step exploit sequences.

A chain is formed when:
  - Vuln A produces an artifact (credential, shell, file access) that enables Vuln B
  - The combined severity exceeds any individual finding
  - A realistic attacker would chain them in sequence

Example chains:
  SSRF → Metadata Endpoint → AWS Credential Theft → Lateral Movement
  SQLi → Password Hash Dump → Credential Stuffing → Account Takeover
  Path Traversal → .env File Read → Hardcoded Secret → Admin Access
  RCE → Persistence Backdoor → Privilege Escalation → Full Compromise
"""

import uuid
from dataclasses import dataclass, field
from itertools import combinations


# ── Chain definitions ─────────────────────────────────────────────────────────
# Each rule: (trigger_types, target_types, chain_name, description, severity_boost)

CHAIN_RULES = [
    # SSRF chains
    {
        "triggers": {"Potential SSRF"},
        "targets": {"Hardcoded AWS credential", "Hardcoded API key"},
        "name": "SSRF → Cloud Credential Theft",
        "description": (
            "SSRF attack reaches cloud metadata endpoint (169.254.169.254) "
            "and retrieves IAM credentials. Combined with hardcoded fallback keys, "
            "attacker achieves full cloud account access."
        ),
        "steps": [
            "Craft SSRF payload targeting http://169.254.169.254/latest/meta-data/",
            "Retrieve IAM security credentials from instance metadata",
            "Combine with hardcoded credentials found in source",
            "Authenticate to AWS APIs — full account takeover",
        ],
        "severity": "CRITICAL",
    },
    # SQLi → credential dump → account takeover
    {
        "triggers": {"SQL Injection"},
        "targets": {"Weak cryptography", "Hardcoded password"},
        "name": "SQLi → Password Dump → Account Takeover",
        "description": (
            "SQL injection extracts password hashes from the database. "
            "Weak hashing (MD5/SHA1) allows rapid cracking. "
            "Recovered credentials enable account takeover."
        ),
        "steps": [
            "Inject UNION SELECT payload to dump users table",
            "Extract MD5/SHA1 password hashes",
            "Crack hashes offline in minutes using GPU + rainbow tables",
            "Authenticate with recovered plaintext passwords",
        ],
        "severity": "CRITICAL",
    },
    # Path traversal → secret leak → auth bypass
    {
        "triggers": {"Path Traversal"},
        "targets": {"Hardcoded secret/token", "Hardcoded API key", "Hardcoded password"},
        "name": "Path Traversal → Config Leak → Auth Bypass",
        "description": (
            "Path traversal reads config files (settings.py, .env, config.ini) "
            "containing hardcoded credentials or API keys. "
            "Attacker authenticates directly with exfiltrated secrets."
        ),
        "steps": [
            "Use ../../ traversal to read /settings.py or /.env",
            "Extract DATABASE_URL, SECRET_KEY, API credentials",
            "Authenticate to internal services using leaked credentials",
            "Escalate to admin access if secret key enables session forgery",
        ],
        "severity": "CRITICAL",
    },
    # RCE → persistence → privilege escalation
    {
        "triggers": {"Command injection", "Code injection", "Unsafe deserialization"},
        "targets": {"Command injection", "Code injection"},
        "name": "RCE → Persistence → Privilege Escalation",
        "description": (
            "Remote code execution used to install a persistent backdoor. "
            "If the application runs with elevated privileges or SUID bits exist, "
            "attacker escalates to root."
        ),
        "steps": [
            "Exploit RCE vulnerability to execute OS commands",
            "Write cron job or systemd service for persistence",
            "Enumerate SUID binaries and writable cron directories",
            "Escalate to root via misconfigured sudo or SUID exploit",
        ],
        "severity": "CRITICAL",
    },
    # Deserialization → RCE
    {
        "triggers": {"Unsafe deserialization"},
        "targets": {"Command injection", "Code injection"},
        "name": "Deserialization → RCE Chain",
        "description": (
            "Unsafe deserialization (pickle/yaml) executes arbitrary code on load. "
            "Chained with other injection points for multi-vector attack."
        ),
        "steps": [
            "Craft malicious pickle/YAML payload with __reduce__ override",
            "Submit via any endpoint accepting serialized data",
            "Payload executes on deserialize — instant RCE",
            "Chain with command injection for persistent access",
        ],
        "severity": "CRITICAL",
    },
    # Weak crypto → brute force
    {
        "triggers": {"Weak cryptography"},
        "targets": {"SQL Injection", "Hardcoded password"},
        "name": "Weak Crypto → Credential Brute Force",
        "description": (
            "MD5/SHA1 password hashes are trivially crackable. "
            "Combined with SQL injection to dump hashes, attacker recovers all passwords."
        ),
        "steps": [
            "Dump password hashes via SQL injection",
            "Feed MD5/SHA1 hashes into hashcat with rockyou.txt",
            "Recover plaintext passwords within minutes",
            "Authenticate to application and any service reusing the password",
        ],
        "severity": "HIGH",
    },
]


class AttackGraphBuilder:
    def build(self, attack_results: list) -> list[dict]:
        """
        Build attack chains from a list of AttackResult objects.
        Returns a list of chain dicts, sorted by severity.
        """
        if len(attack_results) < 2:
            return []

        chains = []
        vuln_types = {ar.vulnerability.vuln_type for ar in attack_results}

        for rule in CHAIN_RULES:
            triggers = rule["triggers"]
            targets = rule["targets"]

            # Find matching trigger vulns and target vulns
            trigger_vulns = [
                ar for ar in attack_results
                if ar.vulnerability.vuln_type in triggers
            ]
            target_vulns = [
                ar for ar in attack_results
                if ar.vulnerability.vuln_type in targets
                and ar.vulnerability.vuln_type not in triggers  # avoid self-chain
            ]

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
                    "node_ids": list(dict.fromkeys(node_ids)),  # deduplicate, preserve order
                    "trigger_types": list(triggers),
                    "target_types": list(targets),
                    "vulnerability_count": len(node_ids),
                })

        # Also generate linear chains for RCE findings that are exploitable
        rce_results = [
            ar for ar in attack_results
            if ar.simulation.get("rce_possible") and ar.exploitable
        ]
        for ar in rce_results:
            chains.append({
                "chain_id": f"CHAIN-{uuid.uuid4().hex[:6].upper()}",
                "name": f"Direct RCE via {ar.vulnerability.vuln_type}",
                "description": (
                    f"Direct exploitation of {ar.vulnerability.vuln_type} at line {ar.vulnerability.line} "
                    f"achieves remote code execution. No chaining required."
                ),
                "steps": ar.simulation.get("execution_path", []),
                "severity": "CRITICAL",
                "node_ids": [ar.vulnerability.vuln_id],
                "trigger_types": [ar.vulnerability.vuln_type],
                "target_types": [],
                "vulnerability_count": 1,
            })

        # Deduplicate chains by name
        seen_names = set()
        unique_chains = []
        for c in chains:
            if c["name"] not in seen_names:
                seen_names.add(c["name"])
                unique_chains.append(c)

        # Sort: CRITICAL first, then by vuln count descending
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        return sorted(unique_chains, key=lambda c: (sev_order.get(c["severity"], 4), -c["vulnerability_count"]))
