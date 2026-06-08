import requests
import urllib.parse
from typing import List, Dict

# Database error patterns to detect SQL Injection
DB_ERROR_PATTERNS = [
    "sqlite3.OperationalError",
    "OperationalError:",
    "sqlite3.Error",
    "SQL syntax",
    "mysql_fetch_array",
    "SQLSTATE",
    "pg_exec",
    "PostgreSQL query failed",
    "driver.Valuer",
]

# Debug mode and stack trace signatures
DEBUG_SIGNATURES = [
    "Werkzeug Debugger",
    "Django debug",
    "Traceback (most recent call last):",
    "Exception at /",
    "ZeroDivisionError:",
    "NameError:",
    "TypeError:",
    "UnboundLocalError:",
    "IndexError:",
    "KeyError:",
    "AttributeError:",
    "ValueError:",
    "SystemError:",
    "fastapi.exceptions.HTTPException",
]

# Admin route targets to check
ADMIN_ROUTES = [
    "/admin",
    "/administrator",
    "/wp-admin",
    "/config",
    "/env",
    "/.env",
    "/.git/config",
    "/console",
    "/dashboard",
    "/api/docs",
]

class SecurityTestModules:
    """
    Runs non-destructive passive and active security checks on a target site.
    """
    def __init__(self):
        pass

    def run_all_checks(self, start_url: str, mapped_surface: Dict) -> List[Dict]:
        """
        Runs all security modules and returns a list of raw findings.
        """
        findings = []
        parsed_url = urllib.parse.urlparse(start_url)
        target_host = f"{parsed_url.scheme}://{parsed_url.netloc}"

        session = requests.Session()
        session.headers.update({"User-Agent": "ShadowCoder-SecurityScanner/2.0"})

        # ── 1. Authentication Checks ──────────────────────────────────────────
        findings.extend(self.check_exposed_admin_routes(target_host, session))
        findings.extend(self.check_weak_session_handling(mapped_surface))
        findings.extend(self.check_missing_login_requirements(target_host, mapped_surface, session))

        # ── 2. Configuration Checks ───────────────────────────────────────────
        findings.extend(self.check_debug_mode_and_stack_traces(target_host, mapped_surface, session))
        findings.extend(self.check_missing_security_headers(target_host, mapped_surface, session))

        # ── 3. Input Validation Checks ────────────────────────────────────────
        findings.extend(self.check_input_validation(target_host, mapped_surface, session))

        return findings

    # ── Authentication Checks ─────────────────────────────────────────────────

    def check_exposed_admin_routes(self, target_host: str, session: requests.Session) -> List[Dict]:
        findings = []
        for route in ADMIN_ROUTES:
            url = urllib.parse.urljoin(target_host, route)
            try:
                response = session.get(url, timeout=3.0, allow_redirects=False)
                if response.status_code == 200:
                    # Double check body doesn't look like a login form or generic page
                    body_lower = response.text.lower()
                    if "admin" in body_lower or "dashboard" in body_lower or route in ADMIN_ROUTES[:5]:
                        findings.append({
                            "type": "auth",
                            "title": "Exposed Admin Route",
                            "severity": "High",
                            "endpoint": route,
                            "description": f"The administrative or configuration route '{route}' is publicly exposed and returns HTTP 200.",
                            "recommendation": f"Restrict access to '{route}' using IP whitelisting, VPN boundaries, or enforce strong multi-factor authentication (MFA)."
                        })
            except Exception:
                pass
        return findings

    def check_weak_session_handling(self, mapped_surface: Dict) -> List[Dict]:
        findings = []
        cookies = mapped_surface.get("cookies", [])
        for cookie in cookies:
            cookie_name = cookie.get("name", "")
            # Identify session cookies
            is_session = any(x in cookie_name.lower() for x in ("session", "jwt", "token", "sid", "uid", "auth"))
            
            if is_session:
                issues = []
                if not cookie.get("http_only", False):
                    issues.append("missing HttpOnly flag (vulnerable to XSS session theft)")
                if not cookie.get("secure", False):
                    issues.append("missing Secure flag (vulnerable to MITM interception over HTTP)")
                
                if issues:
                    desc_issues = " and ".join(issues)
                    findings.append({
                        "type": "auth",
                        "title": "Weak Session Cookie Handling",
                        "severity": "Medium",
                        "endpoint": "Cookie: " + cookie_name,
                        "description": f"Session cookie '{cookie_name}' was found {desc_issues}.",
                        "recommendation": f"Configure session cookies with the 'HttpOnly' flag to prevent JavaScript read access and the 'Secure' flag to ensure they are only sent over HTTPS."
                    })
        return findings

    def check_missing_login_requirements(self, target_host: str, mapped_surface: Dict, session: requests.Session) -> List[Dict]:
        findings = []
        # Check endpoints that sound sensitive (e.g. /dashboard, /profile, /settings, /api/user)
        # and verify if they require auth
        sensitive_paths = ["/dashboard", "/profile", "/settings", "/api/user", "/api/dashboard", "/api/settings"]
        
        for path in sensitive_paths:
            url = urllib.parse.urljoin(target_host, path)
            try:
                # Request without cookies/session
                response = session.get(url, timeout=3.0, allow_redirects=False)
                if response.status_code == 200:
                    body_lower = response.text.lower()
                    # Verify it's not a login page served at that URL
                    if "login" not in body_lower and "sign in" not in body_lower:
                        findings.append({
                            "type": "auth",
                            "title": "Missing Login Requirement",
                            "severity": "High",
                            "endpoint": path,
                            "description": f"Sensitive page '{path}' was accessed successfully without authentication (HTTP 200).",
                            "recommendation": f"Implement session validation checks or routing guards on the backend for '{path}' to ensure only authenticated users can access the endpoint."
                        })
            except Exception:
                pass
        return findings

    # ── Configuration Checks ──────────────────────────────────────────────────

    def check_debug_mode_and_stack_traces(self, target_host: str, mapped_surface: Dict, session: requests.Session) -> List[Dict]:
        findings = []
        
        # Test pages for stack trace leaks
        pages = mapped_surface.get("graph", {}).get("nodes", [])
        for node in pages:
            path = node.get("id", "/")
            url = urllib.parse.urljoin(target_host, path)
            
            try:
                # Trigger a simple error by appending invalid format or parameters
                response = session.get(url + "/%ff", timeout=3.0)
                
                # Check for debug indicators
                debug_found = False
                for sig in DEBUG_SIGNATURES:
                    if sig in response.text:
                        debug_found = True
                        findings.append({
                            "type": "config",
                            "title": "Stack Trace Exposure",
                            "severity": "Medium",
                            "endpoint": path,
                            "description": f"The application leaked a system stack trace or error traceback under '{path}' during an invalid path request.",
                            "recommendation": "Configure a generic global error handler on the backend. Disable interactive debug screens and return clean, user-friendly 404/500 pages."
                        })
                        break
                
                if not debug_found:
                    # Check if standard page has debug console
                    response_normal = session.get(url, timeout=3.0)
                    if "debugger" in response_normal.text.lower() or "console" in response_normal.text.lower() and "werkzeug" in response_normal.text.lower():
                        findings.append({
                            "type": "config",
                            "title": "Debug Mode Enabled",
                            "severity": "High",
                            "endpoint": path,
                            "description": f"An active debugger terminal or developer console was detected on '{path}'.",
                            "recommendation": "Ensure debugging mode is disabled in production settings (e.g., set `debug=False` or `ENV=production`)."
                        })
            except Exception:
                pass
                
        return findings

    def check_missing_security_headers(self, target_host: str, mapped_surface: Dict, session: requests.Session) -> List[Dict]:
        findings = []
        url = target_host
        try:
            response = session.get(url, timeout=3.0)
            headers = response.headers
            
            missing = []
            if "X-Frame-Options" not in headers:
                missing.append("X-Frame-Options (vulnerable to Clickjacking)")
            if "X-Content-Type-Options" not in headers:
                missing.append("X-Content-Type-Options (vulnerable to MIME-sniffing)")
            if "Content-Security-Policy" not in headers:
                missing.append("Content-Security-Policy (vulnerable to XSS / injection)")
            if "Strict-Transport-Security" not in headers and url.startswith("https"):
                missing.append("Strict-Transport-Security (vulnerable to SSL strip)")
                
            if missing:
                findings.append({
                    "type": "config",
                    "title": "Missing Security Headers",
                    "severity": "Low",
                    "endpoint": "/",
                    "description": "The server response headers are missing standard HTTP security enhancements: " + ", ".join(missing),
                    "recommendation": "Configure the web server or application middleware to inject: X-Frame-Options: DENY, X-Content-Type-Options: nosniff, and a restrictive Content-Security-Policy header."
                })
        except Exception:
            pass
        return findings

    # ── Input Validation Checks ───────────────────────────────────────────────

    def check_input_validation(self, target_host: str, mapped_surface: Dict, session: requests.Session) -> List[Dict]:
        findings = []
        
        # 1. Test Query Parameters
        query_params = mapped_surface.get("query_parameters", {})
        for path, params in query_params.items():
            for param in params:
                url = urllib.parse.urljoin(target_host, path)
                
                # Test XSS Reflection
                xss_probe = "<scRipt>alert('SC')</scRipt>"
                try:
                    resp = session.get(url, params={param: xss_probe}, timeout=3.0)
                    if xss_probe in resp.text:
                        findings.append({
                            "type": "input",
                            "title": "Cross-Site Scripting (Reflected XSS)",
                            "severity": "High",
                            "endpoint": f"{path}?{param}=",
                            "description": f"User input submitted via query parameter '{param}' was reflected directly and raw in the HTML response.",
                            "recommendation": "Escape and sanitize user inputs before rendering them in HTML templates. Use context-aware HTML/JS escaping helpers."
                        })
                        continue # Skip SQL probe if XSS confirmed to avoid spamming
                except Exception:
                    pass

                # Test SQL Injection Error
                sqli_probe = "' OR '1'='1"
                try:
                    resp = session.get(url, params={param: sqli_probe}, timeout=3.0)
                    # Check for DB errors
                    for pattern in DB_ERROR_PATTERNS:
                        if pattern in resp.text:
                            findings.append({
                                "type": "input",
                                "title": "SQL Injection (Error-Based)",
                                "severity": "Critical",
                                "endpoint": f"{path}?{param}=",
                                "description": f"Submitting a quote probe to query parameter '{param}' triggered a database syntax error pattern: {pattern}",
                                "recommendation": "Use parameterized queries / prepared statements for all database operations. Never concatenate input into query strings."
                            })
                            break
                except Exception:
                    pass

        # 2. Test Forms
        forms = mapped_surface.get("forms", [])
        for form in forms:
            action = form.get("action", "/")
            method = form.get("method", "get")
            fields = form.get("fields", [])
            
            if not fields:
                continue

            url = urllib.parse.urljoin(target_host, action)
            
            # Send harmless XSS and SQL probes to all fields
            xss_payload = {f["name"]: "<scRipt>alert('SC')</scRipt>" for f in fields if f["type"] in ("text", "search", "textarea")}
            sqli_payload = {f["name"]: "' OR '1'='1" for f in fields if f["type"] in ("text", "search", "textarea")}

            if not xss_payload:
                continue

            # XSS form test
            try:
                if method == "post":
                    resp = session.post(url, data=xss_payload, timeout=3.0)
                else:
                    resp = session.get(url, params=xss_payload, timeout=3.0)
                    
                for name, probe in xss_payload.items():
                    if probe in resp.text:
                        findings.append({
                            "type": "input",
                            "title": "Cross-Site Scripting (Reflected Form Input)",
                            "severity": "High",
                            "endpoint": action,
                            "description": f"Input submitted to form field '{name}' on action '{action}' was reflected raw in the response.",
                            "recommendation": "Ensure the application HTML-encodes user inputs on submission before rendering them back to screen."
                        })
                        break
            except Exception:
                pass

            # SQLi form test
            try:
                if method == "post":
                    resp = session.post(url, data=sqli_payload, timeout=3.0)
                else:
                    resp = session.get(url, params=sqli_payload, timeout=3.0)
                    
                for pattern in DB_ERROR_PATTERNS:
                    if pattern in resp.text:
                        findings.append({
                            "type": "input",
                            "title": "SQL Injection in Form Submission",
                            "severity": "Critical",
                            "endpoint": action,
                            "description": f"Submitting SQL syntax to form fields on '{action}' triggered a database syntax error pattern: {pattern}",
                            "recommendation": "Enforce strict parameterization on backend SQL queries. Apply server-side input validation on form fields."
                        })
                        break
            except Exception:
                pass

        return findings
