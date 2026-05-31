"""
Ollama Client — enriches vulnerability findings using a local LLM.

Responsibilities:
  - Explain vulnerabilities in developer-friendly language
  - Generate context-aware fix suggestions
  - Summarize scan results
  - Assess real-world attack likelihood

Requires Ollama running locally: https://ollama.ai
Default model: llama3 (change via model param)
"""

import json
import logging
import urllib.request
import urllib.error
from typing import Optional

log = logging.getLogger("shadowcoder.ollama")

SYSTEM_PROMPT = """You are ShadowCoder, an elite offensive security AI assistant.
You analyze Python code vulnerabilities and explain them clearly to developers.
Be specific, technical, and actionable. Keep responses under 200 words.
Focus on: what the vulnerability is, how it's exploited, and the exact fix."""


ENRICH_TEMPLATE = """Vulnerability detected in Python code:

Type: {vuln_type}
Severity: {severity}
Location: Line {line}
Code: {code_snippet}
CWE: {cwe}
OWASP: {owasp}

Top payload that would exploit this:
{payload}

Simulation result: {sim_summary}

Provide:
1. One-sentence impact summary
2. Realistic attack scenario (2-3 sentences)
3. Exact code fix with example
4. Any additional mitigations"""

SUMMARY_TEMPLATE = """Security scan found {count} vulnerabilities in Python code:
{vuln_list}

Provide a 3-sentence executive summary covering:
- Overall risk level
- Most critical finding
- Immediate action required"""


class OllamaClient:
    def __init__(self, model: str = "llama3", base_url: str = "http://localhost:11434"):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self._available = None  # lazy check

    def _is_available(self) -> bool:
        if self._available is not None:
            return self._available
        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=2):
                self._available = True
        except Exception:
            self._available = False
            log.warning("Ollama not reachable at %s — AI enrichment disabled", self.base_url)
        return self._available

    def _chat(self, prompt: str, system: Optional[str] = None) -> str:
        if not self._is_available():
            return "[Ollama not available — run: ollama serve && ollama pull llama3]"

        full_prompt = f"{system}\n\nUser: {prompt}\n\nAssistant:" if system else prompt

        payload = {
            "model": self.model,
            "prompt": full_prompt,
            "stream": False,
            "options": {"temperature": 0.3, "num_predict": 400},
        }

        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            f"{self.base_url}/api/generate",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                result = json.loads(resp.read())
                return result.get("response", "").strip()
        except urllib.error.URLError as e:
            log.error("Ollama request failed: %s", e)
            return f"[AI analysis unavailable: {e}]"
        except Exception as e:
            log.error("Unexpected Ollama error: %s", e)
            return f"[AI analysis error: {e}]"

    def enrich(self, vuln, payloads: list[dict], simulation: dict) -> str:
        """Generate AI-powered explanation and fix suggestion for a vulnerability."""
        payload_str = ""
        if payloads:
            p = payloads[0]
            payload_str = f"  Name: {p['name']}\n  Payload: {p['raw']}\n  Impact: {p['impact']}"

        sim_summary = (
            f"Exploitable: {simulation.get('exploitable')}, "
            f"RCE: {simulation.get('rce_possible')}, "
            f"Blast radius: {simulation.get('blast_radius')}"
        )

        prompt = ENRICH_TEMPLATE.format(
            vuln_type=vuln.vuln_type,
            severity=vuln.severity,
            line=vuln.line,
            code_snippet=vuln.code_snippet,
            cwe=vuln.cwe,
            owasp=vuln.owasp,
            payload=payload_str or "N/A",
            sim_summary=sim_summary,
        )
        return self._chat(prompt, system=SYSTEM_PROMPT)

    def summarize(self, vulns: list) -> str:
        """Generate executive summary of all findings."""
        if not vulns:
            return "No vulnerabilities found."

        vuln_list = "\n".join(
            f"  - [{v.severity}] {v.vuln_type} at line {v.line}"
            for v in vulns
        )
        prompt = SUMMARY_TEMPLATE.format(count=len(vulns), vuln_list=vuln_list)
        return self._chat(prompt, system=SYSTEM_PROMPT)
