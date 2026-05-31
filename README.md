# ⚔️ ShadowCoder — Attack Simulation Engine

AI-powered offensive security scanner for Python code. Detects vulnerabilities, generates real exploit payloads, simulates execution paths, and chains multi-step attacks — all running locally with Ollama.

---

## Architecture

```
source code
    → StaticAnalyzer      AST-based vulnerability detection
    → PayloadGenerator    Realistic exploit payload crafting
    → ExecutionSimulator  Taint flow tracing (no code execution)
    → AttackGraphBuilder  Multi-step exploit chain building
    → OllamaClient        Local LLM enrichment (llama3)
    → Reporter            Terminal / JSON / SARIF output
```

## Quick Start

### 1. Install dependencies

```bash
pip install pyyaml requests
```

### 2. Start Ollama (optional — for AI enrichment)

```bash
ollama serve
ollama pull llama3
```

### 3. Scan a file

```bash
# Terminal report (default)
python shadowcoder.py scan myapp.py

# JSON output
python shadowcoder.py scan myapp.py --json

# SARIF (GitHub Code Scanning compatible)
python shadowcoder.py scan myapp.py --sarif

# Fast scan — no AI enrichment
python shadowcoder.py scan myapp.py --no-ai

# Use a different Ollama model
python shadowcoder.py scan myapp.py --model codellama
```

### 4. Use as a library

```python
from engine import AttackEngine, Reporter

engine = AttackEngine(model="llama3")
report = engine.scan(open("myapp.py").read(), filename="myapp.py")

reporter = Reporter()
reporter.print_report(report)          # terminal
print(reporter.to_json(report))        # JSON string
sarif = reporter.to_sarif(report)      # SARIF dict
```

---

## What It Detects

| Vulnerability | Severity | CWE |
|---|---|---|
| SQL Injection (concat + f-string) | CRITICAL | CWE-89 |
| Command Injection (os.system, subprocess) | CRITICAL | CWE-78 |
| Code Injection (eval, exec) | CRITICAL | CWE-94 |
| Unsafe Deserialization (pickle, yaml) | CRITICAL | CWE-502 |
| Hardcoded Credentials / API Keys | CRITICAL | CWE-798 |
| Path Traversal | HIGH | CWE-22 |
| SSRF | MEDIUM | CWE-918 |
| Weak Cryptography (MD5, SHA1) | MEDIUM | CWE-327 |
| Insecure Random | MEDIUM | CWE-338 |

## Attack Chains Detected

- **SSRF → Cloud Credential Theft** — metadata endpoint → IAM key exfil
- **SQLi → Password Dump → Account Takeover** — UNION dump → MD5 crack
- **Path Traversal → Config Leak → Auth Bypass** — .env read → key reuse
- **RCE → Persistence → Privilege Escalation** — shell → cron → root
- **Deserialization → RCE Chain** — pickle/yaml → code exec
- **Weak Crypto → Credential Brute Force** — MD5 dump → hashcat

---

## Running Tests

```bash
python -m pytest tests/ -v
# or
python tests/test_engine.py
```

Expected: **20 tests, 0 failures**

---

## Roadmap

- **V2**: VS Code extension with WebSocket real-time scanning
- **V2**: FastAPI gateway for multi-language support
- **V3**: JavaScript/TypeScript analyzer (tree-sitter)
- **V3**: Attack chain visualization graph
- **V3**: CI/CD GitHub Actions integration

---

## ⚠️ Legal Notice

This tool is for authorized security testing and educational purposes only.
Do not use against systems you do not own or have explicit written permission to test.
