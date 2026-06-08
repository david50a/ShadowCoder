import sys
import os
import unittest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from engine.discovery_engine import LocalhostDiscoveryEngine, AttackSurfaceMapper
from engine.security_checks import SecurityTestModules
from engine.findings_engine import FindingsEngine
from engine.reporter import Reporter
from api.server import app

class TestLocalhostDiscoveryEngine(unittest.TestCase):
    def test_discovery_parser_links(self):
        # We can test parser on mock html content
        from engine.discovery_engine import LinkAndFormParser
        parser = LinkAndFormParser("http://localhost:8000")
        mock_html = """
        <html>
            <a href="/login">Login</a>
            <a href="/dashboard">Dashboard</a>
            <a href="http://google.com">External</a>
            <form action="/api/submit" method="post">
                <input type="text" name="username">
                <input type="password" name="password">
            </form>
        </html>
        """
        parser.feed(mock_html)
        self.assertIn("http://localhost:8000/login", parser.links)
        self.assertIn("http://localhost:8000/dashboard", parser.links)
        self.assertIn("http://google.com", parser.links)
        
        self.assertEqual(len(parser.forms), 1)
        form = parser.forms[0]
        self.assertEqual(form["action"], "http://localhost:8000/api/submit")
        self.assertEqual(form["method"], "post")
        self.assertEqual(len(form["fields"]), 2)
        self.assertEqual(form["fields"][0]["name"], "username")
        self.assertEqual(form["fields"][1]["type"], "password")


class TestSecurityChecks(unittest.TestCase):
    def test_missing_headers(self):
        # Setup mock mapped surface
        findings_engine = FindingsEngine()
        raw_finding = {
            "title": "Missing Security Headers",
            "severity": "Low",
            "endpoint": "/",
            "description": "Missing X-Frame-Options",
            "recommendation": "Configure Deny header"
        }
        standardized = findings_engine.standardize([raw_finding])
        self.assertEqual(len(standardized), 1)
        self.assertEqual(standardized[0]["severity"], "Low")
        self.assertEqual(standardized[0]["title"], "Missing Security Headers")
        self.assertTrue(standardized[0]["id"].startswith("FND-"))


class TestReporterFormats(unittest.TestCase):
    def test_html_generation(self):
        reporter = Reporter()
        mock_report = {
            "target_url": "http://localhost:8000",
            "scan_time_ms": 150,
            "summary": "Mock scan summary.",
            "findings": [
                {
                    "title": "Potential Input Validation Issue",
                    "severity": "Medium",
                    "endpoint": "/search",
                    "description": "Input validation is missing.",
                    "recommendation": "Filter user input."
                }
            ],
            "pages": ["/", "/login", "/dashboard"]
        }
        
        html_content = reporter.to_html(mock_report)
        self.assertIn("ShadowCoder Security Assessment Report", html_content)
        self.assertIn("http://localhost:8000", html_content)
        self.assertIn("Mock scan summary.", html_content)
        self.assertIn("Potential Input Validation Issue", html_content)
        self.assertIn("/search", html_content)

    def test_pdf_generation(self):
        reporter = Reporter()
        mock_report = {
            "target_url": "http://localhost:8000",
            "scan_time_ms": 150,
            "summary": "Mock scan summary.",
            "findings": [
                {
                    "title": "Potential Input Validation Issue",
                    "severity": "Medium",
                    "endpoint": "/search",
                    "description": "Input validation is missing.",
                    "recommendation": "Filter user input."
                }
            ],
            "pages": ["/", "/login", "/dashboard"]
        }
        
        pdf_bytes = reporter.to_pdf(mock_report)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-1.4"))
        self.assertIn(b"%%EOF", pdf_bytes)
        self.assertIn(b"SHADOWCODER SECURITY REPORT", pdf_bytes)


class TestFastApiEndpoints(unittest.TestCase):
    def test_unified_endpoints(self):
        client = TestClient(app)
        
        # Test invalid body
        resp = client.post("/scan", json={})
        self.assertEqual(resp.status_code, 400)
        
        # Test static code scan submission
        code = "print('Hello')"
        resp = client.post("/scan", json={"source_code": code, "filename": "test.py"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("job_id", data)
        self.assertEqual(data["status"], "RUNNING")
        
        job_id = data["job_id"]
        
        # Test status polling
        status_resp = client.get(f"/scan/{job_id}")
        self.assertEqual(status_resp.status_code, 200)
        status_data = status_resp.json()
        self.assertEqual(status_data["job_id"], job_id)
        self.assertIn(status_data["status"], ("RUNNING", "COMPLETE", "FAILED"))

if __name__ == "__main__":
    unittest.main()
