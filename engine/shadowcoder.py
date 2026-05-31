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
    scan_p.add_argument("--exploit", action="store_true", help="Run live exploitation payloads")

    sabotage_p = sub.add_parser("sabotage", help="Inject vulnerabilities into a file (Sabotage)")
    sabotage_p.add_argument("file", help="Python file to sabotage")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    target = Path(args.file)
    if not target.exists():
        print(f"Error: file not found: {target}", file=sys.stderr)
        sys.exit(1)

    if args.command == "sabotage":
        from .sabotage_engine import SabotageEngine
        engine = SabotageEngine()
        if engine.sabotage_file(str(target)):
            print(f"Successfully sabotaged {target}")
        else:
            print(f"Failed to sabotage {target}")
            sys.exit(1)
        return

    source = target.read_text(encoding="utf-8")

    from .attack_engine import AttackEngine
    from .reporter import Reporter

    engine = AttackEngine(model=args.model, ollama_url=args.ollama_url)

    if args.no_ai:
        # Monkey-patch AI client to skip LLM calls
        engine.ai._is_available = lambda: False

    report = engine.scan(source, filename=str(target))
    
    if args.exploit:
        from .exploit_engine import ExploitEngine
        exploit_engine = ExploitEngine()
        print("\n" + "="*80)
        print("🚀 STARTING LIVE EXPLOITATION PHASE")
        print("="*80)
        
        exploit_results = []
        for ar in report.attack_results:
            if ar.exploitable:
                res = exploit_engine.run_exploit(source, ar)
                exploit_results.append(res)
        
        # Simple display of exploit results
        for res in exploit_results:
            status = "✅ CONFIRMED" if res["confirmed"] else "❌ FAILED"
            print(f"[{status}] {res['vuln_type']} (ID: {res['vuln_id']})")
            if res["confirmed"]:
                for attempt in res["attempts"]:
                    if attempt["confirmed"]:
                        print(f"   Payload: {attempt['payload']}")
                        print(f"   Output: {attempt['output']}")
                        break

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
