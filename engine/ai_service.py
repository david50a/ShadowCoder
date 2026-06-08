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

OUTPUT FORMAT:
Provide the list of injected vulnerabilities followed by the complete code block. Format exactly as follows:

[VULNERABILITY]
Type: <vuln_type>
Line: <line_number>
Explanation: <why_it_is_vulnerable>
[/VULNERABILITY]

[CODE]
```python
<complete_rewritten_code>
```
[/CODE]"""
        result = await self._ask(prompt, max_tokens=2000)
        
        # Fallback if AI fails
        default_response = {"new_code": source_code, "summary": []}
        
        if result:
            try:
                import re
                summary = []
                # Parse vulnerabilities
                vuln_blocks = re.findall(r"\[VULNERABILITY(?:\s+\d+)?\](.*?)\[/VULNERABILITY(?:\s+\d+)?\]", result, re.DOTALL | re.IGNORECASE)
                for block in vuln_blocks:
                    vtype_match = re.search(r"Type:\s*(.*)", block, re.IGNORECASE)
                    line_match = re.search(r"Line:\s*(\d+)", block, re.IGNORECASE)
                    expl_match = re.search(r"Explanation:\s*(.*)", block, re.IGNORECASE)
                    if vtype_match and expl_match:
                        line_no = int(line_match.group(1)) if line_match else 0
                        summary.append({
                            "vuln_type": vtype_match.group(1).strip(),
                            "line": line_no,
                            "explanation": expl_match.group(1).strip()
                        })
                
                # Parse code block
                code_match = re.search(r"\[CODE\]\s*```(?:python|py)?\n(.*?)\n```\s*\[/CODE\]", result, re.DOTALL | re.IGNORECASE)
                if not code_match:
                    # Fallback to standard python block search
                    code_match = re.search(r"```(?:python|py)?\n(.*?)\n```", result, re.DOTALL | re.IGNORECASE)
                
                if code_match:
                    new_code = code_match.group(1).strip()
                    if new_code and new_code != source_code:
                        return {"new_code": new_code, "summary": summary}
            except Exception as e:
                log.warning(f"Failed to parse sabotage output: {e}")
        
        return default_response

    async def explain(self, vuln: dict, code_context: str = "") -> str:
        """Human-like, intent-aware explanation with attack simulation."""
        vuln_name = vuln.get('vuln_type') or vuln.get('title') or 'Unknown Vulnerability'
        cwe_str = f" ({vuln.get('cwe')})" if vuln.get('cwe') else ""
        prompt = f"""Vulnerability: {vuln_name}{cwe_str}
Severity: {vuln.get('severity')}
Line: {vuln.get('line', 'N/A')}
Endpoint: {vuln.get('endpoint', 'N/A')}
Code snippet / Description:
```python
{vuln.get('code_snippet') or vuln.get('description', '')}
```
{f'Surrounding context:{chr(10)}{code_context}' if code_context else ''}

Provide a response in this exact structure:
1. 🚨 The Vulnerability: Explain it like a human. Why did the developer make this mistake? Assess intent.
2. 💀 Attack Simulation: Provide a realistic example payload the attacker would send based on the context.
3. 💥 The Impact: What happens? (e.g., "The attacker gains remote command execution").
4. 📚 Mentor Note: Briefly relate this to real-world attacks and its OWASP category."""
        result = await self._ask(prompt, max_tokens=400)
        return result or _fallback_explanation(vuln)

    async def fix(self, vuln: dict, source_code: str = "") -> str:
        """Secure code generation and teaching."""
        vuln_name = vuln.get('vuln_type') or vuln.get('title') or 'Unknown Vulnerability'
        prompt = f"""Vulnerability: {vuln_name} at endpoint/line {vuln.get('endpoint') or vuln.get('line')}
Severity: {vuln.get('severity')}

Vulnerable context:
```python
{vuln.get('code_snippet') or vuln.get('description', '')}
```

Provide a response in this structure:
1. 🛠️ The Fix: Provide the EXACT, complete secure rewrite or remediation configuration steps.
2. 🛡️ Why it works: Explain briefly how this prevents the simulated attack payload."""
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

    async def mv_vector_narrative(self, vector_type: str, findings_summary: str, attack_paths: list[str]) -> str:
        """Provide a 2-3 sentence AI narrative about what a vector found and why it matters."""
        paths_str = "\n".join(f"- {p}" for p in attack_paths)
        prompt = f"""Attack Vector: {vector_type}
Findings summary: {findings_summary}
Attack paths simulated:
{paths_str}

Provide a 2-3 sentence executive narrative explaining the real-world security significance of these findings. Be concise, direct, and realistic."""
        result = await self._ask(prompt, max_tokens=250)
        return result or _fallback_mv_vector_narrative(vector_type, findings_summary, attack_paths)

    async def mv_graph_summary(self, total_vulns: int, exploitable: int, overall_sev: str, top_chains: list[str]) -> str:
        """Provide a 3-sentence executive risk verdict synthesizing all findings."""
        chains_str = "\n".join(f"- {c}" for c in top_chains)
        prompt = f"""Application security profile:
- Total vulnerabilities: {total_vulns}
- Exploitable findings: {exploitable}
- Overall Severity: {overall_sev}
- Key attack pathways:
{chains_str}

Write a 3-sentence executive risk verdict synthesizing all findings:
1. Overall risk rating (e.g. Critical, High) and why.
2. The most dangerous attack sequence (chain) from entry to execution.
3. Top remediation advice."""
        result = await self._ask(prompt, max_tokens=300)
        return result or _fallback_mv_graph_summary(total_vulns, exploitable, overall_sev, top_chains)

    async def mv_path_fix(self, path_title: str, steps: list[str], impact: str) -> str:
        """Provide a concise AI fix recommendation for an attack path."""
        steps_str = "\n".join(f"- {s}" for s in steps)
        prompt = f"""Attack Path: {path_title}
Impact: {impact}
Exploit steps:
{steps_str}

Provide a concise, 1-2 sentence secure-coding remediation recommendation specifically addressing this attack path. Avoid generic advice; specify the exact mechanism to use."""
        result = await self._ask(prompt, max_tokens=250)
        return result or _fallback_mv_path_fix(path_title, steps, impact)



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

    def mv_vector_narrative(self, vector_type: str, findings_summary: str, attack_paths: list[str]) -> str:
        if not self._service.is_available:
            return _fallback_mv_vector_narrative(vector_type, findings_summary, attack_paths)
        try:
            loop = asyncio.new_event_loop()
            return loop.run_until_complete(self._service.mv_vector_narrative(vector_type, findings_summary, attack_paths))
        except Exception:
            return _fallback_mv_vector_narrative(vector_type, findings_summary, attack_paths)
        finally:
            loop.close()

    def mv_graph_summary(self, total_vulns: int, exploitable: int, overall_sev: str, top_chains: list[str]) -> str:
        if not self._service.is_available:
            return _fallback_mv_graph_summary(total_vulns, exploitable, overall_sev, top_chains)
        try:
            loop = asyncio.new_event_loop()
            return loop.run_until_complete(self._service.mv_graph_summary(total_vulns, exploitable, overall_sev, top_chains))
        except Exception:
            return _fallback_mv_graph_summary(total_vulns, exploitable, overall_sev, top_chains)
        finally:
            loop.close()

    def mv_path_fix(self, path_title: str, steps: list[str], impact: str) -> str:
        if not self._service.is_available:
            return _fallback_mv_path_fix(path_title, steps, impact)
        try:
            loop = asyncio.new_event_loop()
            return loop.run_until_complete(self._service.mv_path_fix(path_title, steps, impact))
        except Exception:
            return _fallback_mv_path_fix(path_title, steps, impact)
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

def _fallback_mv_vector_narrative(vector_type: str, findings_summary: str, attack_paths: list[str]) -> str:
    if not findings_summary and not attack_paths:
        return f"No significant vulnerabilities were identified within the {vector_type} attack surface."
    return f"The {vector_type} scan detected vulnerability patterns: {findings_summary or 'potential flaws'}. Attackers could exploit these pathways ({', '.join(attack_paths[:2])}) to target system endpoints."

def _fallback_mv_graph_summary(total_vulns: int, exploitable: int, overall_sev: str, top_chains: list[str]) -> str:
    chains_desc = f" ({len(top_chains)} chains mapped)" if top_chains else ""
    return f"Security posture is rated as {overall_sev} with {total_vulns} findings ({exploitable} exploitable){chains_desc}. Immediate review of identified entry points and configuration files is recommended. Focus remediation on patching input validation and access controls."

def _fallback_mv_path_fix(path_title: str, steps: list[str], impact: str) -> str:
    title_lower = path_title.lower()
    if "sql" in title_lower:
        return "Implement strictly parameterized database queries or use a secure ORM to prevent malicious SQL command insertion."
    elif "command" in title_lower or "os.system" in title_lower:
        return "Avoid running commands via OS shell. Use subprocess with argument lists instead of shell=True, and sanitize inputs."
    elif "pickle" in title_lower or "deserialization" in title_lower:
        return "Avoid deserializing untrusted data with pickle. Use safer serialization formats such as JSON or Protocol Buffers."
    elif "xss" in title_lower:
        return "Sanitize and escape all user inputs before rendering them in HTML templates or API responses."
    elif "auth" in title_lower or "session" in title_lower:
        return "Enforce strong server-side authentication, validate all JWT tokens, and verify user permissions before processing requests."
    return f"Remediate the entry point step in the {path_title} flow to break the exploit chain and secure the downstream functions."

