#!/usr/bin/env python3
"""
ShadowCoder CLI — Attack Simulation Engine
Usage:
  shadowcoder scan <file.py>
  shadowcoder scan <file.py> --json
  shadowcoder scan <file.py> --sarif
  shadowcoder scan <file.py> --model codellama
  shadowcoder scan <file.py> --no-ai
"""

import argparse
import json
import sys
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(
        prog="shadowcoder",
        description="⚔️  ShadowCoder — AI-powered attack simulation for Python code",
    )
    sub = parser.add_subparsers(dest="command")

    scan_p = sub.add_parser("scan", help="Scan a Python file")
    scan_p.add_argument("file", help="Python file to scan")
    scan_p.add_argument("--json", action="store_true", help="Output JSON")
    scan_p.add_argument("--sarif", action="store_true", help="Output SARIF 2.1.0")
    scan_p.add_argument("--model", default="llama3", help="Ollama model (default: llama3)")
    scan_p.add_argument("--ollama-url", default="http://localhost:11434", help="Ollama base URL")
    scan_p.add_argument("--no-ai", action="store_true", help="Skip AI enrichment (faster)")

    args = parser.parse_args()

    if args.command != "scan":
        parser.print_help()
        sys.exit(1)

    target = Path(args.file)
    if not target.exists():
        print(f"Error: file not found: {target}", file=sys.stderr)
        sys.exit(1)

    source = target.read_text(encoding="utf-8")

    from engine import AttackEngine, Reporter

    engine = AttackEngine(model=args.model, ollama_url=args.ollama_url)

    if args.no_ai:
        # Monkey-patch AI client to skip LLM calls
        engine.ai._is_available = lambda: False

    report = engine.scan(source, filename=str(target))
    reporter = Reporter()

    if args.json:
        print(reporter.to_json(report))
    elif args.sarif:
        print(json.dumps(reporter.to_sarif(report), indent=2))
    else:
        reporter.print_report(report)

    # Exit code: 1 if critical/high vulns found
    if any(ar.severity in ("CRITICAL", "HIGH") for ar in report.attack_results):
        sys.exit(1)


if __name__ == "__main__":
    main()
