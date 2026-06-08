"""
Reporter — formats ScanReport into human-readable terminal output and JSON.
"""

import json
import textwrap
from datetime import datetime, timezone
from dataclasses import asdict
from typing import Any


SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪",
}

SEPARATOR = "─" * 72


class Reporter:
    def print_report(self, report) -> None:
        """Print a formatted terminal report."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        print(f"\n{'═' * 72}")
        print(f"  ⚔️  SHADOWCODER ATTACK SIMULATION REPORT")
        print(f"  File: {report.target_file}")
        print(f"  Scan: {now}  ({report.scan_time_ms}ms)")
        print(f"{'═' * 72}")

        if not report.attack_results:
            print("\n  ✅ No vulnerabilities detected.\n")
            return

        print(f"\n  Vulnerabilities:  {report.vulnerabilities_found}")
        print(f"  Exploitable:      {report.exploitable_count}")
        print(f"  Attack chains:    {len(report.attack_chains)}")
        print(f"\n  Summary: {report.summary}\n")

        # ── Findings ──────────────────────────────────────────────────────────
        print(SEPARATOR)
        print("  FINDINGS")
        print(SEPARATOR)
        for ar in report.attack_results:
            v = ar.vulnerability
            icon = SEVERITY_ICONS.get(ar.severity.value if hasattr(ar.severity, 'value') else ar.severity, "⚪")
            print(f"\n  {icon} [{ar.severity}] {v.vuln_type}")
            print(f"     Line {v.line}  ·  {v.cwe}  ·  {v.owasp}  ·  confidence {v.confidence:.0%}")
            print(f"     {v.description}")
            print(f"\n     Code:  {v.code_snippet[:120]}")
            if ar.simulation.get("taint_flow"):
                print(f"\n     Taint flow:")
                for step in ar.simulation["taint_flow"][:4]:
                    print(f"       → {step}")
            if ar.payloads:
                p = ar.payloads[0]
                print(f"\n     Top payload: {p['raw'][:100]}")
                print(f"     Impact:      {p['impact']}")
                if p.get("bypasses"):
                    print(f"     WAF bypass:  {p['bypasses'][0][:80]}")
            if ar.simulation.get("blast_radius"):
                print(f"\n     Blast radius: {ar.simulation['blast_radius']}")
            if ar.ai_analysis and not ar.ai_analysis.startswith("["):
                wrapped = textwrap.fill(ar.ai_analysis, width=65, initial_indent="     ", subsequent_indent="     ")
                print(f"\n     AI analysis:\n{wrapped}")
            if ar.chain_ids:
                print(f"\n     Part of chains: {', '.join(ar.chain_ids)}")

        # ── Attack Chains ─────────────────────────────────────────────────────
        if report.attack_chains:
            print(f"\n{SEPARATOR}")
            print("  ATTACK CHAINS")
            print(SEPARATOR)
            for chain in report.attack_chains:
                icon = SEVERITY_ICONS.get(chain["severity"], "⚪")
                print(f"\n  {icon} {chain['name']}  [{chain['chain_id']}]")
                print(f"     {chain['description'][:160]}")
                print(f"\n     Steps:")
                for i, step in enumerate(chain["steps"], 1):
                    print(f"       {i}. {step}")

        print(f"\n{'═' * 72}\n")

    def to_json(self, report) -> str:
        """Serialize report to JSON string."""
        def _serializable(obj: Any) -> Any:
            if hasattr(obj, "__dict__"):
                return {k: _serializable(v) for k, v in obj.__dict__.items()}
            if hasattr(obj, "value"):
                return obj.value
            if isinstance(obj, list):
                return [_serializable(i) for i in obj]
            if isinstance(obj, dict):
                return {k: _serializable(v) for k, v in obj.items()}
            return obj

        d = {
            "target_file": report.target_file,
            "scan_time_ms": report.scan_time_ms,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "vulnerabilities_found": report.vulnerabilities_found,
            "exploitable_count": report.exploitable_count,
            "summary": report.summary,
            "findings": [_serializable(ar) for ar in report.attack_results],
            "attack_chains": report.attack_chains,
        }
        return json.dumps(d, indent=2)

    def to_sarif(self, report) -> dict:
        """Output SARIF 2.1.0 format — compatible with GitHub Code Scanning."""
        rules = []
        results = []
        for ar in report.attack_results:
            v = ar.vulnerability
            rule = {
                "id": v.vuln_id,
                "name": v.vuln_type.replace(" ", ""),
                "shortDescription": {"text": v.vuln_type},
                "fullDescription": {"text": v.description},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{v.cwe.replace('CWE-','')}.html",
                "properties": {"security-severity": {"CRITICAL": "9.8", "HIGH": "8.0", "MEDIUM": "5.5", "LOW": "3.0"}.get(v.severity, "5.0")},
            }
            rules.append(rule)
            result = {
                "ruleId": v.vuln_id,
                "level": {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}.get(v.severity, "warning"),
                "message": {"text": v.description},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": report.target_file}, "region": {"startLine": v.line, "startColumn": v.col + 1}}}],
            }
            results.append(result)

            rules.append(rule)
            result = {
                "ruleId": v.vuln_id,
                "level": {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}.get(v.severity, "warning"),
                "message": {"text": v.description},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": report.target_file}, "region": {"startLine": v.line, "startColumn": v.col + 1}}}],
            }
            results.append(result)

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "ShadowCoder", "version": "1.0.0", "rules": rules}}, "results": results}],
        }

    def _normalize_report(self, report) -> dict:
        """Unifies ScanReport objects and raw result dicts into a standard dict."""
        from datetime import datetime, timezone
        if isinstance(report, dict):
            findings = []
            for f in report.get("findings", []):
                if "vulnerability" in f:
                    v = f["vulnerability"]
                    findings.append({
                        "id": v.get("vuln_id", "FND-UNK"),
                        "title": v.get("vuln_type", "Vulnerability"),
                        "severity": f.get("severity", "Medium").capitalize(),
                        "endpoint": f"Line {v.get('line')}" if v.get('line') else v.get('taint_sink', '/'),
                        "description": v.get("description", ""),
                        "recommendation": f.get("recommendation") or "Parameterize queries and validate inputs."
                    })
                else:
                    findings.append({
                        "id": f.get("id", "FND-UNK"),
                        "title": f.get("title", "Vulnerability"),
                        "severity": f.get("severity", "Medium").capitalize(),
                        "endpoint": f.get("endpoint", "/"),
                        "description": f.get("description", ""),
                        "recommendation": f.get("recommendation", "Remediate and validate user inputs.")
                    })
            return {
                "target": report.get("target_file") or report.get("target_url") or "Target",
                "scan_time_ms": report.get("scan_time_ms", 0),
                "scanned_at": report.get("scanned_at") or datetime.now(timezone.utc).isoformat(),
                "vulnerabilities_found": len(findings),
                "findings": findings,
                "summary": report.get("summary") or f"Scan completed with {len(findings)} findings.",
                "pages": report.get("pages", []),
                "forms": report.get("forms", []),
                "cookies": report.get("cookies", [])
            }

        # It is a ScanReport object
        from datetime import datetime, timezone
        from engine.ai_service import _fallback_fix
        findings = []
        for ar in report.attack_results:
            v = ar.vulnerability
            sev_val = ar.severity.value if hasattr(ar.severity, "value") else str(ar.severity)
            findings.append({
                "id": v.vuln_id,
                "title": v.vuln_type,
                "severity": sev_val.capitalize(),
                "endpoint": f"Line {v.line}",
                "description": v.description,
                "recommendation": _fallback_fix({"vuln_type": v.vuln_type})
            })
        return {
            "target": report.target_file,
            "scan_time_ms": report.scan_time_ms,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "vulnerabilities_found": len(findings),
            "findings": findings,
            "summary": report.summary,
            "pages": [],
            "forms": [],
            "cookies": []
        }

    def to_html(self, report) -> str:
        """Generates a premium cyber-styled single-file HTML report."""
        data = self._normalize_report(report)
        
        # Calculate stats
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in data["findings"]:
            sev = f["severity"].capitalize()
            if sev in severity_counts:
                severity_counts[sev] += 1
                
        # Build severity bar components
        total_vulns = len(data["findings"])
        
        # HTML template
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ShadowCoder Security Assessment Report</title>
    <style>
        :root {{
            --bg-dark: #0a0e14;
            --bg-card: #101622;
            --border: rgba(0, 255, 136, 0.15);
            --text-main: #e2e8f0;
            --text-muted: #8892b0;
            --green: #00ff88;
            --cyan: #00b4d8;
            --red: #ff2d55;
            --orange: #ff9f0a;
            --yellow: #ffd60a;
            --purple: #bf5af2;
        }}
        
        body {{
            background: var(--bg-dark);
            color: var(--text-main);
            font-family: 'SF Pro Display', -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 40px 20px;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1000px;
            margin: 0 auto;
        }}
        
        header {{
            border-bottom: 2px solid var(--border);
            padding-bottom: 20px;
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: flex-end;
        }}
        
        .brand {{
            font-family: monospace;
            font-size: 24px;
            font-weight: bold;
            color: var(--green);
            letter-spacing: 2px;
        }}
        
        .brand span {{
            color: #fff;
        }}
        
        .meta-info {{
            text-align: right;
            font-family: monospace;
            font-size: 12px;
            color: var(--text-muted);
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }}
        
        .card-title {{
            font-size: 11px;
            font-family: monospace;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 1.5px;
            margin-bottom: 10px;
        }}
        
        .card-value {{
            font-size: 28px;
            font-weight: bold;
            color: #fff;
        }}
        
        .card-value.critical {{ color: var(--red); }}
        .card-value.high {{ color: var(--orange); }}
        .card-value.medium {{ color: var(--yellow); }}
        .card-value.low {{ color: var(--cyan); }}
        
        .severity-breakdown {{
            display: flex;
            height: 12px;
            border-radius: 6px;
            overflow: hidden;
            background: rgba(255,255,255,0.05);
            margin: 20px 0 30px 0;
        }}
        
        .sev-bar {{
            height: 100%;
        }}
        .sev-bar.critical {{ background: var(--red); }}
        .sev-bar.high {{ background: var(--orange); }}
        .sev-bar.medium {{ background: var(--yellow); }}
        .sev-bar.low {{ background: var(--cyan); }}
        
        .summary-text {{
            font-size: 15px;
            color: var(--text-main);
            background: rgba(0, 255, 136, 0.03);
            border-left: 3px solid var(--green);
            padding: 16px;
            border-radius: 4px;
            margin-bottom: 40px;
        }}
        
        h2 {{
            font-size: 18px;
            font-family: monospace;
            border-bottom: 1px dashed rgba(255,255,255,0.1);
            padding-bottom: 10px;
            margin-top: 40px;
            color: #fff;
        }}
        
        .finding {{
            border: 1px solid rgba(255,255,255,0.05);
            border-radius: 6px;
            margin-bottom: 20px;
            background: rgba(16, 22, 34, 0.5);
            overflow: hidden;
        }}
        
        .finding-header {{
            background: rgba(255,255,255,0.02);
            padding: 15px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }}
        
        .finding-title-group {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        
        .finding-title {{
            font-size: 16px;
            font-weight: 600;
            color: #fff;
        }}
        
        .badge {{
            font-family: monospace;
            font-size: 10px;
            font-weight: bold;
            padding: 3px 8px;
            border-radius: 4px;
        }}
        
        .badge.critical {{ background: rgba(255, 45, 85, 0.15); color: var(--red); border: 1px solid rgba(255, 45, 85, 0.3); }}
        .badge.high {{ background: rgba(255, 159, 10, 0.15); color: var(--orange); border: 1px solid rgba(255, 159, 10, 0.3); }}
        .badge.medium {{ background: rgba(255, 214, 10, 0.15); color: var(--yellow); border: 1px solid rgba(255, 214, 10, 0.3); }}
        .badge.low {{ background: rgba(0, 180, 216, 0.15); color: var(--cyan); border: 1px solid rgba(0, 180, 216, 0.3); }}
        
        .finding-endpoint {{
            font-family: monospace;
            font-size: 12px;
            color: var(--text-muted);
            background: rgba(0,0,0,0.2);
            padding: 2px 6px;
            border-radius: 3px;
        }}
        
        .finding-body {{
            padding: 20px;
        }}
        
        .finding-section {{
            margin-bottom: 15px;
        }}
        
        .section-lbl {{
            font-family: monospace;
            font-size: 11px;
            color: var(--text-muted);
            text-transform: uppercase;
            margin-bottom: 4px;
        }}
        
        .section-val {{
            font-size: 14px;
        }}
        
        .section-val.code {{
            background: #000;
            padding: 10px;
            border-radius: 4px;
            font-family: monospace;
            color: var(--green);
            overflow-x: auto;
            border: 1px solid rgba(255,255,255,0.05);
        }}
        
        .list-items {{
            list-style: none;
            padding: 0;
            margin: 0;
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 10px;
        }}
        
        .list-item {{
            background: rgba(255,255,255,0.02);
            border: 1px solid rgba(255,255,255,0.05);
            padding: 8px 12px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 13px;
        }}
        
        .empty-state {{
            text-align: center;
            color: var(--text-muted);
            padding: 30px;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">⚔ SHADOW<span>CODER</span></div>
            <div class="meta-info">
                <div>TARGET: {data['target']}</div>
                <div>SCANNED: {data['scanned_at']}</div>
            </div>
        </header>
        
        <div class="summary-text">
            <strong>EXECUTIVE SUMMARY:</strong><br>
            {data['summary']}
        </div>
        
        <div class="summary-grid">
            <div class="card">
                <div class="card-title">Total Findings</div>
                <div class="card-value">{total_vulns}</div>
            </div>
            <div class="card">
                <div class="card-title">Critical Severity</div>
                <div class="card-value critical">{severity_counts['Critical']}</div>
            </div>
            <div class="card">
                <div class="card-title">High Severity</div>
                <div class="card-value orange">{severity_counts['High']}</div>
            </div>
            <div class="card">
                <div class="card-title">Medium / Low</div>
                <div class="card-value low">{severity_counts['Medium'] + severity_counts['Low']}</div>
            </div>
        </div>
        
        <div class="severity-breakdown">
        """
        
        # Add visual bar blocks
        for sev, count in severity_counts.items():
            if count > 0 and total_vulns > 0:
                pct = (count / total_vulns) * 100
                html += f'<div class="sev-bar {sev.lower()}" style="width: {pct}%" title="{sev}: {count}"></div>'
                
        html += """
        </div>
        """
        
        # Site Map / Details section for Dynamic URL scans
        if data.get("pages"):
            html += """
            <h2>Discovered Site Map</h2>
            <div class="card" style="margin-bottom: 40px;">
                <div class="card-title">Discovered Pages</div>
                <div class="list-items">
            """
            for page in data["pages"]:
                html += f'<div class="list-item">{page}</div>'
            html += """
                </div>
            </div>
            """
            
        # Findings List
        html += "<h2>Vulnerability Findings</h2>"
        if not data["findings"]:
            html += '<div class="card empty-state">No vulnerabilities detected during assessment.</div>'
        else:
            for f in data["findings"]:
                sev_cls = f["severity"].lower()
                html += f"""
                <div class="finding">
                    <div class="finding-header">
                        <div class="finding-title-group">
                            <span class="badge {sev_cls}">{f['severity'].upper()}</span>
                            <span class="finding-title">{f['title']}</span>
                        </div>
                        <span class="finding-endpoint">{f['endpoint']}</span>
                    </div>
                    <div class="finding-body">
                        <div class="finding-section">
                            <div class="section-lbl">Description</div>
                            <div class="section-val">{f['description']}</div>
                        </div>
                        <div class="finding-section">
                            <div class="section-lbl">Remediation Recommendation</div>
                            <div class="section-val code">{f['recommendation']}</div>
                        </div>
                    </div>
                </div>
                """
                
        html += """
    </div>
</body>
</html>
"""
        return html

    def to_pdf(self, report) -> bytes:
        """Generates a clean PDF file binary using pure Python byte structures."""
        data = self._normalize_report(report)
        
        pdf = [b"%PDF-1.4"]
        pdf_objs = []
        
        lines = []
        lines.append("SHADOWCODER SECURITY REPORT")
        lines.append("===========================")
        lines.append(f"Target: {data['target']}")
        lines.append(f"Scanned At: {data['scanned_at']}")
        lines.append(f"Scan Duration: {data['scan_time_ms']} ms")
        lines.append(f"Vulnerabilities Found: {data['vulnerabilities_found']}")
        lines.append("")
        lines.append("SUMMARY:")
        lines.append(data["summary"])
        lines.append("")
        
        if data.get("pages"):
            lines.append("DISCOVERED PAGES:")
            for p in data["pages"]:
                lines.append(f"  - {p}")
            lines.append("")
            
        lines.append("VULNERABILITY FINDINGS:")
        for idx, f in enumerate(data["findings"], 1):
            lines.append(f"{idx}. [{f['severity'].upper()}] {f['title']}")
            lines.append(f"   Endpoint: {f['endpoint']}")
            lines.append(f"   Description: {f['description']}")
            lines.append(f"   Recommendation: {f['recommendation']}")
            lines.append("")
            
        # Simple line-wrapping helper ( Courier 10pt on A4 has ~75 chars max )
        wrapped_lines = []
        for line in lines:
            if len(line) > 75:
                words = line.split(" ")
                curr = []
                for w in words:
                    if len(" ".join(curr + [w])) > 75:
                        wrapped_lines.append(" ".join(curr))
                        curr = [w]
                    else:
                        curr.append(w)
                if curr:
                    wrapped_lines.append(" ".join(curr))
            else:
                wrapped_lines.append(line)
                
        # Group lines into pages (max 48 lines per page)
        pages_lines = []
        curr_page = []
        for l in wrapped_lines:
            curr_page.append(l)
            if len(curr_page) >= 48:
                pages_lines.append(curr_page)
                curr_page = []
        if curr_page:
            pages_lines.append(curr_page)
            
        num_pages = len(pages_lines)
        if num_pages == 0:
            pages_lines = [["No findings or summary available."]]
            num_pages = 1
            
        # Page content streams start at object ID 4
        # Page objects start at object ID 4 + num_pages
        page_objs_refs = []
        for i in range(num_pages):
            page_objs_refs.append(f"{4 + num_pages + i} 0 R")
            
        catalog = b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        pages_list = f"2 0 obj\n<< /Type /Pages /Kids [{' '.join(page_objs_refs)}] /Count {num_pages} >>\nendobj\n".encode()
        font = b"3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj\n"
        
        pdf_objs.append(catalog)
        pdf_objs.append(pages_list)
        pdf_objs.append(font)
        
        # Generate content stream objects
        for idx, page_content in enumerate(pages_lines):
            stream_lines = []
            stream_lines.append(b"BT")
            stream_lines.append(b"/F1 9 Tf")      # Courier 9pt
            stream_lines.append(b"12 TL")       # Line spacing 12pt
            stream_lines.append(b"50 780 Td")   # Margin 50pt from left, 780pt from bottom
            
            for line in page_content:
                # Escape parenthesis for PDF string format
                escaped = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
                stream_lines.append(f"({escaped}) Tj T*".encode("utf-8", "replace"))
                
            stream_lines.append(b"ET")
            stream_data = b"\n".join(stream_lines)
            
            obj_id = 4 + idx
            content_stream_obj = f"{obj_id} 0 obj\n<< /Length {len(stream_data)} >>\nstream\n".encode() + stream_data + b"\nstreamend\nendobj\n"
            pdf_objs.append(content_stream_obj)
            
        # Generate page node objects
        for idx in range(num_pages):
            page_id = 4 + num_pages + idx
            stream_ref = f"{4 + idx} 0 R"
            page_obj = f"{page_id} 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 3 0 R >> >> /MediaBox [0 0 595.27 841.89] /Contents {stream_ref} >>\nendobj\n".encode()
            pdf_objs.append(page_obj)
            
        # Assemble body
        body = b"".join(pdf_objs)
        
        # Build file offset coordinates
        start_offset = len(pdf[0]) + 1
        offsets = []
        current_offset = start_offset
        for obj in pdf_objs:
            offsets.append(current_offset)
            current_offset += len(obj)
            
        # Build cross-reference section
        xref_lines = []
        xref_lines.append(b"xref")
        xref_lines.append(f"0 {len(offsets) + 1}".encode())
        xref_lines.append(b"0000000000 65535 f ")
        for offset in offsets:
            xref_lines.append(f"{offset:010d} 00000 n ".encode())
            
        xref = b"\n".join(xref_lines)
        
        # Build trailer section
        trailer = f"trailer\n<< /Size {len(offsets) + 1} /Root 1 0 R >>\nstartxref\n{current_offset}\n%%EOF".encode()
        
        return b"\n".join(pdf + pdf_objs + [xref, trailer])
