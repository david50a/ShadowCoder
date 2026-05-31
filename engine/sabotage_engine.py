"""
Sabotage Engine — Active vulnerability injection into target projects.

Two-tier strategy:
  1. AI-powered (Ollama) — when available, for subtle realistic injections.
  2. Rule-based fallback — deterministic AST/regex transforms, no AI required.
"""

import ast
import logging
import re
import shutil
from pathlib import Path

from .ai_service import AIServiceSync

log = logging.getLogger("shadowcoder.sabotage")


# ── Rule-based sabotage transforms ───────────────────────────────────────────

class _RuleBasedSaboteur:
    """
    Applies a battery of deterministic code transforms that introduce
    realistic, subtle security vulnerabilities without requiring any AI.
    """

    def sabotage(self, source: str) -> dict:
        """
        Returns {"new_code": str, "summary": list[dict]}.
        Applies as many transforms as applicable; stops when 3 vulns injected.
        """
        code = source
        summary = []

        transforms = [
            self._inject_sql_injection,
            self._inject_command_injection,
            self._harden_to_weak_crypto,
            self._inject_hardcoded_secret,
            self._pickle_deserialization,
            self._disable_ssl_verify,
        ]

        for transform in transforms:
            if len(summary) >= 3:
                break
            new_code, vuln = transform(code)
            if vuln:
                code = new_code
                summary.append(vuln)

        return {"new_code": code, "summary": summary}

    # ── Individual transforms ─────────────────────────────────────────────────

    def _inject_sql_injection(self, source: str) -> tuple[str, dict | None]:
        """Replace parameterized SQL with string concatenation."""
        # Pattern: cursor.execute("...", (param,))  →  cursor.execute("..." + param)
        pattern = re.compile(
            r'(cursor\.execute\s*\(\s*)(f?["\'])(.+?)\2\s*,\s*\(([^)]+),?\)\s*\)',
            re.DOTALL,
        )
        match = pattern.search(source)
        if match:
            param_name = match.group(4).strip().rstrip(",").strip()
            safe_query = match.group(3)
            # Replace ? / %s placeholder with concatenation
            vuln_query = re.sub(r"[?]|%s", "' + " + param_name + " + '", safe_query, count=1)
            replacement = f'{match.group(1)}"{vuln_query}")'
            new_source = source[: match.start()] + replacement + source[match.end() :]
            return new_source, {
                "vuln_type": "SQL Injection",
                "line": source[: match.start()].count("\n") + 1,
                "explanation": (
                    "Parameterized query replaced with unsafe string concatenation. "
                    "An attacker can inject ' OR '1'='1 to bypass authentication."
                ),
            }
        return source, None

    def _inject_command_injection(self, source: str) -> tuple[str, dict | None]:
        """Add shell=True to subprocess calls or inject f-string into os.system."""
        # subprocess.run([...], ...) → subprocess.run(f"...", shell=True, ...)
        pattern = re.compile(
            r"(subprocess\.(run|call|Popen)\s*\(\s*)\[([^\]]+)\]",
        )
        match = pattern.search(source)
        if match:
            cmd_parts = match.group(3)
            # Convert list to f-string shell command
            first_arg = cmd_parts.split(",")[0].strip().strip("\"'")
            replacement = f'{match.group(1)}f"{first_arg} {{input_data}}", shell=True'
            new_source = source[: match.start()] + replacement + source[match.end() :]
            return new_source, {
                "vuln_type": "Command Injection",
                "line": source[: match.start()].count("\n") + 1,
                "explanation": (
                    "subprocess list-form (safe) replaced with shell=True f-string. "
                    "An attacker controlling input_data can append ; rm -rf / or inject a reverse shell."
                ),
            }

        # Fallback: wrap os.system calls to use user input directly
        pattern2 = re.compile(r'os\.system\s*\(\s*f?"([^"]+)"\s*\)')
        match2 = pattern2.search(source)
        if match2:
            new_source = source[: match2.start()] + f'os.system(f"{match2.group(1)} {{user_input}}")' + source[match2.end() :]
            return new_source, {
                "vuln_type": "Command Injection",
                "line": source[: match2.start()].count("\n") + 1,
                "explanation": "User input appended unsanitized to os.system() shell command.",
            }
        return source, None

    def _harden_to_weak_crypto(self, source: str) -> tuple[str, dict | None]:
        """Replace hashlib.sha256 / bcrypt with MD5."""
        for strong in ["sha256", "sha512", "sha3_256", "sha3_512", "blake2b"]:
            if f"hashlib.{strong}" in source:
                new_source = source.replace(f"hashlib.{strong}", "hashlib.md5", 1)
                return new_source, {
                    "vuln_type": "Weak Cryptography (MD5)",
                    "line": next(
                        i + 1
                        for i, l in enumerate(source.splitlines())
                        if f"hashlib.{strong}" in l
                    ),
                    "explanation": (
                        f"hashlib.{strong} (secure) downgraded to MD5 (broken). "
                        "MD5 collisions are trivial; password hashes are crackable via GPU rainbow tables in minutes."
                    ),
                }
        return source, None

    def _inject_hardcoded_secret(self, source: str) -> tuple[str, dict | None]:
        """Replace os.environ.get(...) secret lookups with hardcoded strings."""
        pattern = re.compile(
            r'((?:SECRET|API_KEY|PASSWORD|TOKEN|KEY)\s*=\s*)os\.environ\.get\s*\([^)]+\)',
            re.IGNORECASE,
        )
        match = pattern.search(source)
        if match:
            var_name = match.group(1).strip().rstrip("=").strip().lower()
            fake_secrets = {
                "secret": "hardcoded-secret-key-do-not-use",
                "api_key": "sk-prod-abc123xyz789hardcoded",
                "password": "supersecret123",
                "token": "eyJhbGciOiJub25lIn0.hardcoded.token",
                "key": "hardcoded-key-32bytes-padding!!!",
            }
            secret_val = next(
                (v for k, v in fake_secrets.items() if k in var_name), "hardcoded-secret"
            )
            new_source = source[: match.start()] + f'{match.group(1)}"{secret_val}"' + source[match.end() :]
            return new_source, {
                "vuln_type": "Hardcoded Secret / Token",
                "line": source[: match.start()].count("\n") + 1,
                "explanation": (
                    "Environment-variable secret lookup replaced with a hardcoded string. "
                    "Anyone with repo access now has the credential; it will appear in git history."
                ),
            }
        return source, None

    def _pickle_deserialization(self, source: str) -> tuple[str, dict | None]:
        """Replace json.loads with pickle.loads."""
        if "json.loads" in source and "import pickle" not in source:
            # Add pickle import and replace first json.loads
            new_source = source.replace(
                "import json", "import json\nimport pickle", 1
            ).replace(
                "json.loads(", "pickle.loads(", 1
            )
            if new_source != source:
                line_no = next(
                    (i + 1 for i, l in enumerate(source.splitlines()) if "json.loads" in l), 1
                )
                return new_source, {
                    "vuln_type": "Unsafe Deserialization (pickle)",
                    "line": line_no,
                    "explanation": (
                        "Safe json.loads replaced with pickle.loads. "
                        "An attacker who controls the input can craft a pickle payload with __reduce__ "
                        "to execute arbitrary OS commands on deserialization."
                    ),
                }
        return source, None

    def _disable_ssl_verify(self, source: str) -> tuple[str, dict | None]:
        """Add verify=False to requests calls."""
        pattern = re.compile(r'(requests\.(get|post|put|patch|delete)\s*\([^)]+)(\))')
        match = pattern.search(source)
        if match and "verify=" not in match.group(0):
            replacement = match.group(1) + ", verify=False" + match.group(3)
            new_source = source[: match.start()] + replacement + source[match.end() :]
            return new_source, {
                "vuln_type": "TLS Verification Bypass",
                "line": source[: match.start()].count("\n") + 1,
                "explanation": (
                    "verify=False added to requests call, disabling TLS certificate validation. "
                    "An attacker in a MITM position can intercept all HTTPS traffic."
                ),
            }
        return source, None


# ── Public engine ─────────────────────────────────────────────────────────────

_rule_saboteur = _RuleBasedSaboteur()


def sabotage_source(source_code: str, use_ai: bool = True) -> dict:
    """
    Inject vulnerabilities into source_code string.

    Args:
        source_code: The Python source to sabotage.
        use_ai:      Try Ollama AI first if True (falls back to rules on failure).

    Returns:
        {"new_code": str, "summary": list[dict], "method": "ai"|"rules"}
    """
    if use_ai:
        ai = AIServiceSync()
        if ai._service.is_available:
            result = ai.sabotage_code(source_code)
            if result.get("new_code") and result["new_code"] != source_code:
                result["method"] = "ai"
                return result

    # Rule-based fallback
    result = _rule_saboteur.sabotage(source_code)
    result["method"] = "rules"
    return result


class SabotageEngine:
    """
    Orchestrates vulnerability injection into a target file.
    Creates a .bak backup before modification.
    """

    def sabotage_file(self, file_path: str) -> bool:
        target = Path(file_path)
        if not target.exists():
            log.error(f"File not found: {file_path}")
            return False

        log.info(f"Sabotaging {file_path}...")

        # 1. Create backup
        backup_path = target.with_suffix(target.suffix + ".bak")
        shutil.copy2(target, backup_path)
        log.info(f"Backup created at {backup_path}")

        # 2. Read source
        try:
            source = target.read_text(encoding="utf-8")
        except Exception as e:
            log.error(f"Failed to read file: {e}")
            return False

        # 3. Sabotage (AI → rules fallback)
        result = sabotage_source(source)
        modified_source = result.get("new_code", source)

        if not modified_source or modified_source == source:
            log.warning("No transforms applied — code may already be vulnerable or unsupported pattern.")
            return False

        # 4. Write back
        try:
            target.write_text(modified_source, encoding="utf-8")
            log.info(f"Sabotaged {file_path} via {result.get('method', '?')} ({len(result.get('summary', []))} vulns injected)")
            return True
        except Exception as e:
            log.error(f"Failed to write sabotaged file: {e}")
            shutil.move(str(backup_path), str(target))
            return False
