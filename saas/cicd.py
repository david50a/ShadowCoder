"""
ShadowCoder SaaS — CI/CD Integration
GitHub Actions, GitLab CI, and generic webhook-based scanning.

Provides:
  - /api/ci/scan       Authenticated scan endpoint for CI pipelines
  - /api/ci/badge      SVG badge for README
  - /api/webhooks/github  GitHub push/PR webhook handler
  - /api/webhooks/gitlab  GitLab push webhook handler
  - GitHub Actions YAML generator
  - GitLab CI YAML generator
"""

import hashlib
import hmac
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger("shadowcoder.cicd")

GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "")
GITLAB_WEBHOOK_SECRET = os.getenv("GITLAB_WEBHOOK_SECRET", "")

# ── Badge generator ────────────────────────────────────────────────────────────

BADGE_COLORS = {
    "secure":   ("#00c853", "#007c33"),  # green
    "low":      ("#64b5f6", "#1565c0"),  # blue
    "medium":   ("#ffa726", "#e65100"),  # orange
    "high":     ("#ef5350", "#b71c1c"),  # red
    "critical": ("#b71c1c", "#7f0000"),  # dark red
    "scanning": ("#78909c", "#37474f"),  # grey
    "error":    ("#757575", "#424242"),  # dark grey
}

def generate_badge_svg(status: str, vuln_count: int = 0, label: str = "ShadowCoder") -> str:
    color1, color2 = BADGE_COLORS.get(status, BADGE_COLORS["scanning"])
    if status == "secure":
        right_text = "secure"
    elif status == "scanning":
        right_text = "scanning"
    elif status == "error":
        right_text = "error"
    else:
        right_text = f"{vuln_count} {'vuln' if vuln_count == 1 else 'vulns'}"

    left_w  = len(label) * 7 + 10
    right_w = len(right_text) * 7 + 10
    total_w = left_w + right_w

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="20">
  <defs>
    <linearGradient id="s" x2="0" y2="100%">
      <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
      <stop offset="1" stop-opacity=".1"/>
    </linearGradient>
    <clipPath id="r"><rect width="{total_w}" height="20" rx="3"/></clipPath>
  </defs>
  <g clip-path="url(#r)">
    <rect width="{left_w}" height="20" fill="#555"/>
    <rect x="{left_w}" width="{right_w}" height="20" fill="{color1}"/>
    <rect width="{total_w}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="{left_w//2}" y="15" fill="#010101" fill-opacity=".3">{label}</text>
    <text x="{left_w//2}" y="14">{label}</text>
    <text x="{left_w + right_w//2}" y="15" fill="#010101" fill-opacity=".3">{right_text}</text>
    <text x="{left_w + right_w//2}" y="14">{right_text}</text>
  </g>
</svg>"""


# ── GitHub Actions YAML ────────────────────────────────────────────────────────

def generate_github_actions_yaml(ci_token: str, server_url: str = "https://your-shadowcoder.com") -> str:
    return f"""# ShadowCoder Security Scan — GitHub Actions
# Add this to .github/workflows/shadowcoder.yml
# Get your CI token from: {server_url}/dashboard/ci

name: ShadowCoder Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    name: "⚔️ ShadowCoder Exploit Analysis"
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Run ShadowCoder scan
        id: scan
        run: |
          # Scan all Python files and send results to ShadowCoder
          SCAN_RESULTS=$(find . -name "*.py" -not -path "./.git/*" | head -20 | xargs cat | \\
            curl -s -X POST "{server_url}/api/ci/scan" \\
            -H "X-CI-Token: {ci_token}" \\
            -H "Content-Type: application/json" \\
            -d @- <<'BODY'
          {{
            "source_code": "$(cat ${{github.workspace}}/*.py 2>/dev/null | head -c 100000)",
            "repo": "${{{{ github.repository }}}}",
            "branch": "${{{{ github.ref_name }}}}",
            "commit_sha": "${{{{ github.sha }}}}",
            "pr_number": "${{{{ github.event.number }}}}"
          }}
          BODY
          )
          
          echo "scan_results=$SCAN_RESULTS" >> $GITHUB_OUTPUT
          
          # Extract vulnerability count
          VULN_COUNT=$(echo $SCAN_RESULTS | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('vulnerabilities_found', 0))")
          CRITICAL=$(echo $SCAN_RESULTS | python3 -c "import sys,json; d=json.load(sys.stdin); print(sum(1 for f in d.get('findings',[]) if f.get('severity')=='CRITICAL'))")
          
          echo "vuln_count=$VULN_COUNT" >> $GITHUB_OUTPUT
          echo "critical_count=$CRITICAL" >> $GITHUB_OUTPUT
          
          # Fail if critical vulnerabilities found
          if [ "$CRITICAL" -gt 0 ]; then
            echo "::error::$CRITICAL critical vulnerabilities found! Review at {server_url}/dashboard"
            exit 1
          fi

      - name: Comment PR with results
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const results = JSON.parse('${{{{ steps.scan.outputs.scan_results }}}}');
            const vulns = results.vulnerabilities_found || 0;
            const status = vulns === 0 ? '✅ Secure' : `⚠️ ${{vulns}} vulnerabilities found`;
            
            await github.rest.issues.createComment({{
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
              body: `## ⚔️ ShadowCoder Security Scan\\n\\n**Status:** ${{status}}\\n\\n[View full report]({server_url}/dashboard)`
            }});

      - name: Upload SARIF report
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif-file: shadowcoder-results.sarif
          category: shadowcoder
        continue-on-error: true
"""


def generate_gitlab_ci_yaml(ci_token: str, server_url: str = "https://your-shadowcoder.com") -> str:
    return f"""# ShadowCoder Security Scan — GitLab CI
# Add this to .gitlab-ci.yml or include it

shadowcoder-security:
  stage: test
  image: python:3.11-slim
  
  variables:
    SHADOWCODER_TOKEN: "{ci_token}"
    SHADOWCODER_URL: "{server_url}"
  
  before_script:
    - pip install requests -q
  
  script:
    - |
      python3 - <<'SCRIPT'
      import os, json, sys, glob, requests
      
      # Collect Python files
      files = glob.glob("**/*.py", recursive=True)[:20]
      source = ""
      for f in files:
          try:
              source += open(f).read() + "\\n"
          except:
              pass
      
      # Run scan
      resp = requests.post(
          f"{{os.environ['SHADOWCODER_URL']}}/api/ci/scan",
          headers={{"X-CI-Token": os.environ["SHADOWCODER_TOKEN"]}},
          json={{
              "source_code": source[:100000],
              "repo": os.environ.get("CI_PROJECT_PATH", "unknown"),
              "branch": os.environ.get("CI_COMMIT_BRANCH", "unknown"),
              "commit_sha": os.environ.get("CI_COMMIT_SHA", "unknown"),
          }},
          timeout=60
      )
      
      result = resp.json()
      vulns = result.get("vulnerabilities_found", 0)
      critical = sum(1 for f in result.get("findings", []) if f.get("severity") == "CRITICAL")
      
      print(f"ShadowCoder: {{vulns}} vulnerabilities found ({{critical}} critical)")
      
      if critical > 0:
          print(f"BLOCKING: {{critical}} critical vulnerabilities found!")
          sys.exit(1)
      
      SCRIPT
  
  artifacts:
    reports:
      sast: shadowcoder-gl-sast.json
    expire_in: 1 week
  
  allow_failure: false
  only:
    - main
    - merge_requests
"""


# ── Webhook signature verification ───────────────────────────────────────────

def verify_github_signature(payload: bytes, sig_header: str) -> bool:
    if not GITHUB_WEBHOOK_SECRET:
        return True  # Skip verification in dev mode
    if not sig_header or not sig_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(
        GITHUB_WEBHOOK_SECRET.encode(), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, sig_header)


def verify_gitlab_token(token_header: str) -> bool:
    if not GITLAB_WEBHOOK_SECRET:
        return True
    return hmac.compare_digest(GITLAB_WEBHOOK_SECRET, token_header or "")


# ── CI scan result formatter ──────────────────────────────────────────────────

def format_ci_result(scan_result: dict, ci_context: dict) -> dict:
    """Format scan result for CI consumption with pass/fail status."""
    findings = scan_result.get("findings", [])
    critical = [f for f in findings if f.get("severity") == "CRITICAL"]
    high = [f for f in findings if f.get("severity") == "HIGH"]

    # Determine CI status
    if critical:
        ci_status = "failed"
        ci_message = f"BLOCKED: {len(critical)} critical vulnerability{'s' if len(critical) > 1 else ''} found"
    elif high:
        ci_status = "warning"
        ci_message = f"WARNING: {len(high)} high-severity vulnerability{'s' if len(high) > 1 else ''} found"
    elif findings:
        ci_status = "passed_with_warnings"
        ci_message = f"PASSED with {len(findings)} low/medium findings"
    else:
        ci_status = "passed"
        ci_message = "No vulnerabilities detected"

    return {
        **scan_result,
        "ci_status": ci_status,
        "ci_message": ci_message,
        "ci_context": ci_context,
        "blocking": ci_status == "failed",
        "summary": {
            "total": len(findings),
            "critical": len(critical),
            "high": len(high),
            "exploitable": scan_result.get("exploitable_count", 0),
            "chains": len(scan_result.get("attack_chains", [])),
        },
    }


# ── SARIF output (GitHub Code Scanning) ──────────────────────────────────────

def to_sarif(scan_result: dict, repo_url: str = "") -> dict:
    """Convert scan results to SARIF 2.1.0 format for GitHub Code Scanning."""
    rules = []
    results = []
    seen_rules = set()

    for finding in scan_result.get("findings", []):
        v = finding.get("vulnerability", {})
        rule_id = v.get("cwe", "SC-UNKNOWN").replace(" ", "-")

        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": v.get("vuln_type", "Unknown"),
                "shortDescription": {"text": v.get("vuln_type", "")},
                "fullDescription": {"text": v.get("description", "")},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{rule_id.replace('CWE-','')}.html",
                "properties": {
                    "tags": ["security", v.get("owasp", ""), finding.get("severity", "").lower()],
                    "precision": "high" if finding.get("exploitable") else "medium",
                    "problem.severity": {
                        "CRITICAL": "error", "HIGH": "error",
                        "MEDIUM": "warning", "LOW": "note"
                    }.get(finding.get("severity", "LOW"), "note"),
                },
            })

        sev_map = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
        results.append({
            "ruleId": rule_id,
            "level": sev_map.get(finding.get("severity", "LOW"), "note"),
            "message": {"text": v.get("description", "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": scan_result.get("target_file", "unknown.py")},
                    "region": {"startLine": v.get("line", 1)},
                }
            }],
            "properties": {"exploitable": finding.get("exploitable", False)},
        })

    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ShadowCoder",
                    "version": "2.0.0",
                    "informationUri": "https://shadowcoder.dev",
                    "rules": rules,
                }
            },
            "results": results,
            "automationDetails": {"id": f"shadowcoder/{scan_result.get('scanned_at', '')}"},
        }],
    }
