#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import io, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
"""
ShadowCoder — End-to-End Live Security Test
============================================
1. Starts test_target.py (vulnerable FastAPI app) on localhost:8001
2. Waits until it responds
3. Runs LocalhostDiscoveryEngine  → crawls all pages & forms
4. Runs AttackSurfaceMapper       → maps forms, params, cookies, auth pages
5. Runs AttackEngine (static)     → detects + simulates all vulnerabilities
6. Actively probes endpoints with generated payloads via HTTP
7. Prints a colour-coded final report

Usage:
    python run_live_test.py
"""

import os
import sys
import time
import json
import subprocess
import urllib.request
import urllib.parse
import urllib.error

# ── Make engine importable ────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── ANSI colours ──────────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

TARGET_URL  = "http://127.0.0.1:8001"
TARGET_FILE = os.path.join(os.path.dirname(__file__), "test_target.py")
STARTUP_TIMEOUT = 15   # seconds to wait for the server to start
SEV_COLOR = {
    "CRITICAL": RED + BOLD,
    "HIGH":     RED,
    "MEDIUM":   YELLOW,
    "LOW":      CYAN,
    "INFO":     DIM,
}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def banner(title: str) -> None:
    width = 70
    print(f"\n{BOLD}{CYAN}{'=' * width}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'=' * width}{RESET}")


def section(title: str) -> None:
    print(f"\n{BOLD}>> {title}{RESET}")
    print(f"  {'-' * 60}")


def ok(msg: str) -> None:
    print(f"  {GREEN}[+]{RESET}  {msg}")


def warn(msg: str) -> None:
    print(f"  {YELLOW}[!]{RESET}  {msg}")


def fail(msg: str) -> None:
    print(f"  {RED}[X]{RESET}  {msg}")


def info(msg: str) -> None:
    print(f"  {DIM}...{RESET}  {msg}")


def sev_label(sev: str) -> str:
    color = SEV_COLOR.get(sev, "")
    return f"{color}[{sev}]{RESET}"


# ─────────────────────────────────────────────────────────────────────────────
# Phase 0 — Start the target server
# ─────────────────────────────────────────────────────────────────────────────

def start_target_server():
    """Launch test_target.py via uvicorn. Returns the Popen handle."""
    cmd = [
        sys.executable, "-m", "uvicorn",
        "test_target:app",
        "--host", "127.0.0.1",
        "--port", "8001",
        "--log-level", "warning",
    ]
    proc = subprocess.Popen(
        cmd,
        cwd=os.path.dirname(os.path.abspath(__file__)),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc


def wait_for_server(url: str, timeout: int) -> bool:
    """Poll until the server responds or timeout expires."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=1)
            return True
        except Exception:
            time.sleep(0.4)
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Phase 1 — Discovery
# ─────────────────────────────────────────────────────────────────────────────

def run_discovery(target_url: str) -> dict:
    from engine.discovery_engine import LocalhostDiscoveryEngine, AttackSurfaceMapper

    section("Phase 1 — Site Discovery (live crawl)")
    engine = LocalhostDiscoveryEngine(max_depth=3, max_pages=50)
    site_map = engine.discover(target_url)

    ok(f"Pages found  : {site_map['pages']}")
    ok(f"Form paths   : {site_map['forms']}")

    section("Phase 2 — Attack Surface Mapping")
    mapper = AttackSurfaceMapper()
    surface = mapper.map_surface(target_url, site_map)

    ok(f"Forms        : {len(surface['forms'])} form(s)")
    for f in surface["forms"]:
        fields = [fld["name"] for fld in f.get("fields", [])]
        info(f"  → {f['method'].upper()} {f['action']}  fields={fields}")

    ok(f"Auth pages   : {surface['authentication_pages']}")
    ok(f"Upload paths : {surface['upload_endpoints'] or 'none'}")
    ok(f"Query params : {surface['query_parameters'] or 'none'}")

    graph = surface.get("graph", {})
    ok(f"Graph nodes  : {len(graph.get('nodes', []))}  edges: {len(graph.get('edges', []))}")

    return surface


# ─────────────────────────────────────────────────────────────────────────────
# Phase 3 — Static Attack Engine
# ─────────────────────────────────────────────────────────────────────────────

def run_static_scan(source_code: str, filename: str) -> object:
    from engine.attack_engine import AttackEngine

    section("Phase 3 — Static Analysis + Attack Simulation")
    engine = AttackEngine()
    report = engine.scan(source_code, filename)

    color = RED if report.vulnerabilities_found else GREEN
    print(f"\n  {color}{BOLD}Vulnerabilities found  : {report.vulnerabilities_found}{RESET}")
    print(f"  {color}{BOLD}Exploitable            : {report.exploitable_count}{RESET}")
    print(f"  {DIM}Scan time              : {report.scan_time_ms} ms{RESET}")
    print(f"  {DIM}Attack chains          : {len(report.attack_chains)}{RESET}")

    return report


# ─────────────────────────────────────────────────────────────────────────────
# Phase 4 — Live HTTP Probe (active exploitation attempts)
# ─────────────────────────────────────────────────────────────────────────────

LIVE_PROBES = [
    # (label, method, path, data_dict_or_None, expected_indicator)
    ("SQLi — auth bypass",      "POST", "/login",
     {"username": "' OR '1'='1' --", "password": "x"},
     "success"),

    ("SQLi — UNION dump",       "POST", "/login",
     {"username": "admin' UNION SELECT 1,username,password FROM users--", "password": "x"},
     "admin"),

    ("CMDi — basic",            "GET",  "/ping/exec?ip=127.0.0.1%20%26%20echo%20SHADOWCODER_RCE",
     None, "SHADOWCODER_RCE"),

    ("CMDi — dir listing",      "GET",  "/ping/exec?ip=127.0.0.1%20%26%20dir",
     None, "Volume"),

    ("SSRF — localhost self",   "GET",  "/fetch?url=http://127.0.0.1:8001/",
     None, "Vulnerable App"),

    ("SSRF — internal /etc/passwd via file://", "GET",
     "/fetch?url=file:///C:/Windows/win.ini",
     None, None),   # May fail on Windows; just observe response

    ("Normal login — valid",    "POST", "/login",
     {"username": "admin", "password": "supersecret123"},
     "success"),
]


def http_get(url: str) -> tuple[int, str]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ShadowCoder-LiveTest/1.0"})
        with urllib.request.urlopen(req, timeout=4) as r:
            return r.status, r.read().decode(errors="ignore")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="ignore")
    except Exception as e:
        return 0, str(e)


def http_post(url: str, data: dict) -> tuple[int, str]:
    try:
        body = urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(
            url, data=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "ShadowCoder-LiveTest/1.0",
            }
        )
        with urllib.request.urlopen(req, timeout=4) as r:
            return r.status, r.read().decode(errors="ignore")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="ignore")
    except Exception as e:
        return 0, str(e)


def run_live_probes(target_url: str) -> list[dict]:
    section("Phase 4 — Live HTTP Exploit Probes")
    results = []

    for label, method, path, data, indicator in LIVE_PROBES:
        url = target_url + path
        if method == "GET":
            status, body = http_get(url)
        else:
            status, body = http_post(url, data or {})

        # Determine success
        if indicator:
            hit = indicator.lower() in body.lower()
        else:
            hit = status != 0  # any response counts

        entry = {
            "label": label,
            "method": method,
            "path": path,
            "status": status,
            "hit": hit,
            "snippet": body[:120].replace("\n", " ").strip(),
        }
        results.append(entry)

        tag = f"{GREEN}CONFIRMED{RESET}" if hit else f"{DIM}no match{RESET}"
        prefix = "[+]" if hit else "[ ]"
        print(f"  {prefix}  {BOLD}{label}{RESET}")
        print(f"       {method} {path}")
        print(f"       HTTP {status}  =>  {tag}")
        if hit and indicator:
            idx = body.lower().find(indicator.lower())
            snippet = body[max(0, idx-20):idx+60].replace("\n", " ").strip()
            print(f"       {DIM}…{snippet}…{RESET}")
        print()

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Phase 5 — Findings Report
# ─────────────────────────────────────────────────────────────────────────────

def print_findings(report) -> None:
    section("Phase 5 — Detailed Vulnerability Findings")

    if not report.attack_results:
        ok("No vulnerabilities detected by static engine.")
        return

    for i, ar in enumerate(report.attack_results, 1):
        v = ar.vulnerability
        c = SEV_COLOR.get(ar.severity.value if hasattr(ar.severity, "value") else str(ar.severity), "")
        print(f"\n  {c}{BOLD}[{i}] {v.vuln_type}{RESET}  {sev_label(v.severity)}")
        print(f"      Line {v.line}  •  {v.cwe or 'CWE-?'}  •  {v.owasp or 'OWASP-?'}")
        print(f"      {DIM}{v.description}{RESET}")

        if v.code_snippet:
            print(f"      {DIM}Code: {v.code_snippet.strip()[:80]}{RESET}")

        if ar.payloads:
            sample = ar.payloads[0].get("raw", "")[:60]
            print(f"      {YELLOW}Payload sample: {sample}{RESET}")

        exploitable_label = f"{RED}YES - EXPLOITABLE{RESET}" if ar.exploitable else f"{DIM}no{RESET}"
        print(f"      Exploitable: {exploitable_label}")

    # Attack chains
    if report.attack_chains:
        print(f"\n  {BOLD}Attack Chains ({len(report.attack_chains)}):{RESET}")
        for chain in report.attack_chains:
            print(f"    • {chain.get('chain_id', '?')} — {chain.get('description', '')} "
                  f"({len(chain.get('node_ids', []))} steps)")


# ─────────────────────────────────────────────────────────────────────────────
# Phase 6 — Summary
# ─────────────────────────────────────────────────────────────────────────────

def print_summary(report, probe_results: list[dict], surface: dict) -> None:
    banner("SHADOWCODER — FINAL ASSESSMENT SUMMARY")

    confirmed_probes = sum(1 for p in probe_results if p["hit"])
    total_probes     = len(probe_results)

    print(f"\n  {'Target URL':<28} {TARGET_URL}")
    print(f"  {'Target File':<28} {TARGET_FILE}")
    print()
    print(f"  {'Static Vulnerabilities Found':<28} {report.vulnerabilities_found}")
    print(f"  {'Statically Exploitable':<28} {report.exploitable_count}")
    print(f"  {'Attack Chains Built':<28} {len(report.attack_chains)}")
    print()
    print(f"  {'Live Probes Fired':<28} {total_probes}")
    print(f"  {'Live Probes Confirmed':<28} {GREEN}{BOLD}{confirmed_probes}{RESET} / {total_probes}")
    print()

    # Per-vuln-type breakdown
    type_counts: dict[str, int] = {}
    for ar in report.attack_results:
        t = ar.vulnerability.vuln_type
        type_counts[t] = type_counts.get(t, 0) + 1

    if type_counts:
        print(f"  {BOLD}Vulnerability Breakdown:{RESET}")
        for t, n in sorted(type_counts.items(), key=lambda x: -x[1]):
            print(f"    - {n}x  {t}")

    # Confirmed live attacks
    confirmed = [p for p in probe_results if p["hit"]]
    if confirmed:
        print(f"  {RED}{BOLD}[!!!] LIVE EXPLOITS CONFIRMED:{RESET}")
        for p in confirmed:
            print(f"    [{p['method']}] {p['path']:<45} -> {p['label']}")

    # Verdict
    print()
    if confirmed_probes >= 3:
        verdict = f"{RED}{BOLD}CRITICAL — Multiple live exploits confirmed. System is NOT secure.{RESET}"
    elif confirmed_probes >= 1:
        verdict = f"{YELLOW}{BOLD}HIGH — At least one live exploit confirmed. Immediate remediation required.{RESET}"
    elif report.vulnerabilities_found:
        verdict = f"{YELLOW}MEDIUM — Static vulnerabilities found but no live exploit confirmed.{RESET}"
    else:
        verdict = f"{GREEN}PASS — No vulnerabilities detected.{RESET}"

    print(f"  Verdict: {verdict}")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    banner("SHADOWCODER END-TO-END LIVE SECURITY TEST")
    print(f"  Target  : {CYAN}{TARGET_URL}{RESET}")
    print(f"  Source  : {CYAN}{TARGET_FILE}{RESET}")
    print(f"  Time    : {time.strftime('%Y-%m-%d %H:%M:%S')}")

    # ── Load source ──────────────────────────────────────────────────────────
    with open(TARGET_FILE, "r", encoding="utf-8") as fh:
        source_code = fh.read()

    # ── Start server ─────────────────────────────────────────────────────────
    section("Phase 0 — Starting Vulnerable Target Server")
    server_proc = None
    server_was_running = False

    try:
        # Check if already running
        urllib.request.urlopen(TARGET_URL, timeout=1)
        ok("Server already running — skipping launch.")
        server_was_running = True
    except Exception:
        info("Launching test_target.py via uvicorn …")
        server_proc = start_target_server()
        if wait_for_server(TARGET_URL, STARTUP_TIMEOUT):
            ok(f"Server started (PID {server_proc.pid}) → {TARGET_URL}")
        else:
            fail("Server did not start within timeout. Aborting.")
            if server_proc:
                server_proc.terminate()
            sys.exit(1)

    try:
        # ── Discovery ────────────────────────────────────────────────────────
        surface = run_discovery(TARGET_URL)

        # ── Static scan ──────────────────────────────────────────────────────
        report = run_static_scan(source_code, "test_target.py")

        # ── Live probes ──────────────────────────────────────────────────────
        probe_results = run_live_probes(TARGET_URL)

        # ── Findings detail ──────────────────────────────────────────────────
        print_findings(report)

        # ── Final summary ─────────────────────────────────────────────────────
        print_summary(report, probe_results, surface)

        # ── Save JSON report ─────────────────────────────────────────────────
        report_path = os.path.join(os.path.dirname(__file__), "live_test_report.json")
        output = {
            "target_url":             TARGET_URL,
            "target_file":            TARGET_FILE,
            "scanned_at":             time.strftime("%Y-%m-%dT%H:%M:%S"),
            "vulnerabilities_found":  report.vulnerabilities_found,
            "exploitable_count":      report.exploitable_count,
            "attack_chains":          len(report.attack_chains),
            "live_probes": [
                {"label": p["label"], "confirmed": p["hit"], "status": p["status"]}
                for p in probe_results
            ],
            "discovery": {
                "pages": surface.get("pages_found", []),
                "forms": [f["action"] for f in surface.get("forms", [])],
                "auth_pages": surface.get("authentication_pages", []),
            },
        }
        with open(report_path, "w", encoding="utf-8") as fh:
            json.dump(output, fh, indent=2)
        ok(f"JSON report saved → {report_path}")

    finally:
        if server_proc and not server_was_running:
            section("Cleanup")
            server_proc.terminate()
            server_proc.wait(timeout=5)
            ok(f"Server (PID {server_proc.pid}) stopped.")


if __name__ == "__main__":
    main()
