# ⚔️ ShadowCoder

**ShadowCoder** is an AI-powered offensive security scanner and attack simulation engine designed specifically for Python code. By leveraging local LLMs (like Ollama), ShadowCoder detects vulnerabilities, constructs realistic exploit payloads, traces taint flows, and chains multi-step attacks without actual code execution.

---

## 🚀 Features

- **Static Analysis**: AST-based vulnerability detection across your Python codebases.
- **Payload Generation**: Automatically crafts realistic exploit payloads tailored to the discovered vulnerabilities.
- **Execution Simulation**: Safely traces taint flows to understand how data moves through your application.
- **Attack Graph Building**: Identifies and constructs multi-step exploit chains (e.g., SSRF to Cloud Credential Theft, SQLi to Account Takeover).
- **Local AI Enrichment**: Uses local LLMs via Ollama (e.g., Llama 3) for deep code understanding without leaking data.
- **Flexible Reporting**: Output reports in Terminal, JSON, or SARIF formats (compatible with GitHub Code Scanning).

---

## 🏗 Architecture

ShadowCoder's architecture is composed of several independent but tightly integrated modules:

```mermaid
flowchart TD
    A[Source Code] --> B[StaticAnalyzer]
    B --> C[PayloadGenerator]
    C --> D[ExecutionSimulator]
    D --> E[AttackGraphBuilder]
    E --> F[OllamaClient (Local LLM)]
    F --> G[Reporter]
    
    B -. AST Detection .-> B
    C -. Exploit Crafting .-> C
    D -. Taint Tracing .-> D
    E -. Chain Building .-> E
    F -. AI Enrichment .-> F
```

---

## 🛠 Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```
*(Dependencies generally include `pyyaml`, `requests`, etc.)*

### 2. Setup Ollama (Optional but Recommended)

For AI enrichment, install and start Ollama locally:

```bash
ollama serve
ollama pull llama3
```

### 3. Run a Scan

ShadowCoder can be invoked from the CLI to scan your Python files:

```bash
# Standard terminal report
python shadowcoder.py scan myapp.py

# Output as JSON
python shadowcoder.py scan myapp.py --json

# Output as SARIF (for CI/CD integration)
python shadowcoder.py scan myapp.py --sarif

# Fast scan mode (Disables AI enrichment)
python shadowcoder.py scan myapp.py --no-ai

# Specify a different Ollama model
python shadowcoder.py scan myapp.py --model codellama
```

### 4. Library Usage

You can also use ShadowCoder programmatically within your own Python tools:

```python
from engine import AttackEngine, Reporter

# Initialize the engine
engine = AttackEngine(model="llama3")

# Scan a specific file
with open("myapp.py", "r") as f:
    code = f.read()
    
report = engine.scan(code, filename="myapp.py")

# Output the results
reporter = Reporter()
reporter.print_report(report)          # Terminal output
print(reporter.to_json(report))        # JSON format
sarif = reporter.to_sarif(report)      # SARIF dictionary
```

---

## 🛡️ Vulnerabilities Detected

| Vulnerability | Severity | CWE |
|---|---|---|
| **SQL Injection** (concat + f-string) | CRITICAL | CWE-89 |
| **Command Injection** (`os.system`, `subprocess`) | CRITICAL | CWE-78 |
| **Code Injection** (`eval`, `exec`) | CRITICAL | CWE-94 |
| **Unsafe Deserialization** (`pickle`, `yaml`) | CRITICAL | CWE-502 |
| **Hardcoded Credentials / API Keys** | CRITICAL | CWE-798 |
| **Path Traversal** | HIGH | CWE-22 |
| **SSRF** | MEDIUM | CWE-918 |
| **Weak Cryptography** (MD5, SHA1) | MEDIUM | CWE-327 |
| **Insecure Random** | MEDIUM | CWE-338 |

---

## 🧪 Testing

To run the test suite, ensure you have `pytest` installed, then execute:

```bash
python -m pytest tests/ -v
# OR run the engine tests directly
python tests/test_engine.py
```

*Expected output should show all tests passing successfully.*

---

## ⚠️ Legal Notice

**ShadowCoder is built for authorized security testing and educational purposes only.** 
Do not use this tool against systems you do not own or do not have explicit written permission to test. The developers assume no liability and are not responsible for any misuse or damage caused by this program.
