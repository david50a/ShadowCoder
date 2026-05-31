"""
ShadowCoder — AI Service (Phase 5)
Uses local Ollama (llama3) for intelligent analysis, not just rule-based detection.

Provides:
  - explain()       → plain-English vulnerability explanation
  - fix()           → specific, copy-paste fix with reasoning
  - chain_narrative() → story-mode attack chain explanation
  - triage()        → prioritize which findings matter most
  - project_summary() → high-level security posture report
"""

import asyncio
import json
import logging
import os
from typing import Optional

from .ollama_client import OllamaClient

log = logging.getLogger("shadowcoder.ai")


class AIService:
    """
    AI analysis using local Ollama.
    Falls back gracefully if Ollama is not running or model not found.
    """

    MODEL = os.environ.get("OLLAMA_MODEL", "llama3")

    SYSTEM_PROMPT = """You are ShadowCoder, an elite offensive security AI and coding mentor.
Your role is to analyze Python code vulnerabilities, understand developer intent, and explain exploits like a human.

CORE DIRECTIVES:
1. Understand Intent: Don't just flag keywords. Analyze context (Is this debug code? Sandboxed? A compiler?). Reduce false positives.
2. Architectural Reasoning: Think across boundaries (frontend → API → DB). Look for business logic flaws and IDORs.
3. Secure Code Generation: Write perfect, drop-in replacement code (e.g., strictly parameterized SQL, safe deserialization).
4. Attack Chaining: Recognize how low-level bugs combine into full admin takeovers.
5. Teach & Mentor: Explain the OWASP context, real-world impacts, and the "why" behind the fix. Be concise but educational."""

    def __init__(self):
        self._client = OllamaClient(model=self.MODEL)
        self._available = False
        self._check_availability()

    def _check_availability(self):
        if self._client._is_available():
            self._available = True
            log.info(f"AI service initialized with Ollama ({self.MODEL})")
        else:
            log.info("AI service disabled — Ollama not reachable")

    @property
    def is_available(self) -> bool:
        return self._available

    # ── Core AI call ─────────────────────────────────────────────────────────

    async def _ask(self, prompt: str, max_tokens: int = 600) -> Optional[str]:
        if not self._available:
            return None
        try:
            # OllamaClient is synchronous, run in thread pool
            result = await asyncio.to_thread(self._client._chat, prompt, system=self.SYSTEM_PROMPT)
            return result
        except Exception as e:
            log.warning(f"Ollama call failed: {e}")
            return None

    # ── Public analysis methods ───────────────────────────────────────────────

    async def sabotage_code(self, source_code: str) -> dict:
        """Inject realistic vulnerabilities and return both the code and a summary of changes."""
        prompt = f"""Target Python code:
```python
{source_code}
```

REWRITE this code to INTRODUCE 2-3 realistic security vulnerabilities (e.g., SQL injection, Command injection, Path traversal, Unsafe deserialization).

GUIDELINES:
1. Maintain Original Functionality.
2. Be Subtle (look like common dev mistakes).
3. Diversity of vuln types.
4. COMPLETE CODE must be returned.

OUTPUT FORMAT (JSON):
{{
  "new_code": "The full source code goes here",
  "summary": [
    {{"vuln_type": "Type", "line": 12, "explanation": "Why it is vulnerable"}},
    ...
  ]
}}

Return ONLY the JSON object."""
        result = await self._ask(prompt, max_tokens=2000)
        
        # Fallback if AI fails JSON
        default_response = {"new_code": source_code, "summary": []}
        
        if result:
            try:
                import json
                # Strip markdown fences if present
                clean = result.strip()
                if clean.startswith("```json"):
                    clean = clean[7:]
                if clean.endswith("```"):
                    clean = clean[:-3]
                clean = clean.strip()
                
                data = json.loads(clean)
                if "new_code" in data:
                    return data
            except Exception:
                # If JSON fails, try to extract code using the old regex logic
                import re
                match = re.search(r"```(?:python|py)?\s*\n?(.*?)\n?```", result, re.DOTALL | re.IGNORECASE)
                if match:
                    return {"new_code": match.group(1).strip(), "summary": [{"vuln_type": "AI Injection", "line": 0, "explanation": "Vulnerabilities injected but summary failed to parse."}]}
        
        return default_response

    async def explain(self, vuln: dict, code_context: str = "") -> str:
        """Human-like, intent-aware explanation with attack simulation."""
        prompt = f"""Vulnerability: {vuln.get('vuln_type')} ({vuln.get('cwe')})
Severity: {vuln.get('severity')}
Line: {vuln.get('line')}
Code snippet:
```python
{vuln.get('code_snippet', '')}
```
{f'Surrounding context:{chr(10)}{code_context}' if code_context else ''}

Provide a response in this exact structure:
1. 🚨 The Vulnerability: Explain it like a human. Why did the developer make this mistake? Assess intent (e.g., is this likely debug code?).
2. 💀 Attack Simulation: Provide a realistic example payload the attacker would send based on the context.
3. 💥 The Impact: What happens? (e.g., "The attacker gains remote command execution").
4. 📚 Mentor Note: Briefly relate this to real-world attacks and its OWASP category."""
        result = await self._ask(prompt, max_tokens=400)
        return result or _fallback_explanation(vuln)

    async def fix(self, vuln: dict, source_code: str = "") -> str:
        """Secure code generation and teaching."""
        prompt = f"""Vulnerability: {vuln.get('vuln_type')} at line {vuln.get('line')}
Severity: {vuln.get('severity')}

Vulnerable code:
```python
{vuln.get('code_snippet', '')}
```

Provide a response in this structure:
1. 🛠️ The Fix: Provide the EXACT, complete secure rewrite (e.g., parameterized queries instead of f-strings, safe YAML loaders).
2. 🛡️ Why it works: Explain briefly how this specific code prevents the simulated attack payload."""
        result = await self._ask(prompt, max_tokens=500)
        return result or _fallback_fix(vuln)

    async def chain_narrative(self, chain: dict, findings: list[dict]) -> str:
        """Advanced attack chaining and multi-file reasoning."""
        chain_name = chain.get("name", "Unknown Chain")
        steps = chain.get("steps", [])
        involved_vulns = [
            f for f in findings 
            if f.get("vulnerability", {}).get("vuln_id") in chain.get("node_ids", [])
        ]
        vuln_summary = "\n".join(
            f"- {f['vulnerability']['vuln_type']} (line {f['vulnerability']['line']})"
            for f in involved_vulns
        )
        prompt = f"""Attack chain: {chain_name}
Vulnerabilities chained together:
{vuln_summary}

Execution steps:
{chr(10).join(f'{i+1}. {s}' for i, s in enumerate(steps))}

This is an advanced multi-step exploit. Write a detailed red-team attack simulation connecting these flaws:
1. 🔗 The Chain: Explain how connecting these specific weaknesses (e.g., missing auth + path traversal) creates a catastrophic path that traditional scanners miss.
2. 🕵️ Attacker Scenario: Describe the attack step-by-step with realistic payloads, showing how architectural trust boundaries are broken."""
        result = await self._ask(prompt, max_tokens=500)
        return result or chain.get("description", "")

    async def triage(self, findings: list[dict]) -> list[dict]:
        """AI-ranked priority list with business impact reasoning."""
        if not findings:
            return []

        summary = "\n".join(
            f"{i+1}. [{f['severity']}] {f['vulnerability']['vuln_type']} (line {f['vulnerability']['line']}) — exploitable={f['exploitable']}"
            for i, f in enumerate(findings[:15])
        )
        prompt = f"""Security findings from a Python application scan:
{summary}

Rank these by TRUE risk priority (not just severity label). Consider:
- Exploitability (is it actually reachable?)
- Business impact (RCE > data leak > weak crypto)
- Chaining potential (can this enable other attacks?)

Return ONLY a JSON array like:
[{{"rank": 1, "vuln_type": "...", "reason": "one sentence", "priority": "IMMEDIATE|HIGH|MEDIUM|LOW"}}]
No other text."""
        result = await self._ask(prompt, max_tokens=800)
        if result:
            try:
                # Strip any markdown fences
                clean = result.strip().strip("```json").strip("```").strip()
                return json.loads(clean)
            except json.JSONDecodeError:
                pass
        return _fallback_triage(findings)

    async def project_summary(self, report: dict) -> str:
        """Executive summary of the overall security posture."""
        n = report.get("vulnerabilities_found", 0)
        exploitable = report.get("exploitable_count", 0)
        chains = len(report.get("attack_chains", []))
        top_vulns = [
            f"{f['vulnerability']['vuln_type']} ({f['severity']})"
            for f in report.get("findings", [])[:5]
        ]
        prompt = f"""Python codebase security scan results:
- Total vulnerabilities: {n}
- Exploitable: {exploitable}
- Attack chains: {chains}
- Top issues: {', '.join(top_vulns)}

Write a 3-sentence executive summary:
1. Overall risk verdict (Critical/High/Medium/Low risk codebase)
2. The single most dangerous finding and why
3. The top priority action to take immediately

Be direct. No hedging."""
        result = await self._ask(prompt, max_tokens=250)
        return result or f"Found {n} vulnerabilities ({exploitable} exploitable) across {chains} attack chains. Immediate review required."

    async def enrich_finding(self, finding: dict) -> dict:
        """Add AI fields to a finding dict in-place."""
        vuln = finding.get("vulnerability", {})
        finding["ai_explanation"] = await self.explain(vuln)
        finding["ai_fix"] = await self.fix(vuln)
        return finding


# ── Sync wrapper for non-async contexts ───────────────────────────────────────

class AIServiceSync:
    """Synchronous wrapper around AIService for use in threads."""

    def __init__(self):
        self._service = AIService()

    def explain(self, vuln: dict) -> str:
        if not self._service.is_available:
            return _fallback_explanation(vuln)
        try:
            loop = asyncio.new_event_loop()
            return loop.run_until_complete(self._service.explain(vuln))
        except Exception:
            return _fallback_explanation(vuln)
        finally:
            loop.close()

    def sabotage_code(self, source_code: str) -> dict:
        if not self._service.is_available:
            return {"new_code": source_code, "summary": []}
        try:
            loop = asyncio.new_event_loop()
            return loop.run_until_complete(self._service.sabotage_code(source_code))
        except Exception:
            return {"new_code": source_code, "summary": []}
        finally:
            loop.close()


# ── Static fallbacks (no API key needed) ─────────────────────────────────────

def _fallback_explanation(vuln: dict) -> str:
    vtype = vuln.get("vuln_type", "Unknown")
    explanations = {
        "SQL Injection": "Attacker injects SQL syntax (e.g. ' OR 1=1--) into a query built by string concatenation, bypassing authentication or dumping the entire database.",
        "Command Injection (os.system)": "Attacker passes shell metacharacters (e.g. ; cat /etc/passwd) in user input that reaches os.system(), executing arbitrary OS commands with app privileges.",
        "Unsafe Deserialization (pickle)": "Attacker sends a malicious pickle payload with a custom __reduce__ method that executes OS commands the moment pickle.loads() is called.",
        "Server-Side Request Forgery (SSRF)": "Attacker supplies http://169.254.169.254/latest/meta-data/ as the URL, causing the server to fetch AWS instance credentials on their behalf.",
        "Server-Side Template Injection (SSTI)": "Attacker injects {{7*7}} or {{config}} into a template string, confirming execution. Full RCE follows via Python's MRO chain: {{''.__class__.__mro__[1].__subclasses__()}}.",
        "Weak Cryptography (MD5)": "MD5 hashes are trivially reversed via GPU-accelerated rainbow tables (hashcat). An attacker who dumps the DB recovers all passwords in minutes.",
        "Insecure Randomness": "random.randint() uses Mersenne Twister, which is not cryptographically secure. An attacker who observes enough outputs can reconstruct the full internal state and predict future values.",
    }
    for key, expl in explanations.items():
        if key in vtype or vtype in key:
            return expl
    return vuln.get("description", "Manual analysis required for this vulnerability type.")

def _fallback_fix(vuln: dict) -> str:
    vtype = vuln.get("vuln_type", "")
    fixes = {
        "SQL Injection": "Use parameterized queries:\n```python\ncursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))\n```",
        "Command Injection": "Use subprocess with a list (no shell=True):\n```python\nsubprocess.run(['ping', '-c', '1', ip_address], capture_output=True)\n```",
        "Unsafe Deserialization": "Replace pickle with json for data exchange. If pickle is required, verify HMAC signature before loading:\n```python\nimport hmac, hashlib\nif not hmac.compare_digest(sig, expected): raise ValueError('Invalid signature')\n```",
        "Weak Cryptography": "Use bcrypt or Argon2 for passwords, SHA-256+ for data integrity:\n```python\nimport bcrypt\nhashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())\n```",
        "Insecure Randomness": "Use the secrets module:\n```python\nimport secrets\ntoken = secrets.token_urlsafe(32)\n```",
        "Server-Side Request Forgery": "Validate URL against an allowlist:\n```python\nfrom urllib.parse import urlparse\nallowed = {'api.example.com'}\nif urlparse(url).hostname not in allowed:\n    raise ValueError('Blocked host')\n```",
    }
    for key, fix in fixes.items():
        if key in vtype:
            return fix
    return "Sanitize and validate all user-controlled input before passing to sensitive functions. Apply the principle of least privilege."

def _fallback_triage(findings: list[dict]) -> list[dict]:
    priority_map = {"CRITICAL": "IMMEDIATE", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
    sorted_findings = sorted(findings, key=lambda f: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(f.get("severity", "LOW"), 3))
    return [
        {"rank": i+1, "vuln_type": f["vulnerability"]["vuln_type"], "reason": f["vulnerability"]["description"][:80], "priority": priority_map.get(f["severity"], "MEDIUM")}
        for i, f in enumerate(sorted_findings[:10])
    ]
