import socket
import unittest
from unittest.mock import Mock, patch

import requests

import app as auditor


PUBLIC_DNS_RECORD = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]


def response(status=200, headers=None):
    result = Mock()
    result.status_code = status
    result.headers = headers or {}
    result.close = Mock()
    return result


class URLValidationTests(unittest.TestCase):
    @patch("app.socket.getaddrinfo", return_value=PUBLIC_DNS_RECORD)
    def test_accepts_public_http_and_https_urls(self, _resolver):
        self.assertEqual(auditor.validate_url("https://example.com/path#fragment"), "https://example.com/path")
        self.assertEqual(auditor.validate_url("http://example.com"), "http://example.com/")

    def test_rejects_empty_invalid_and_unsupported_urls(self):
        for value in ("", "not a URL", "ftp://example.com", "https:///missing-host"):
            with self.subTest(value=value), self.assertRaises(auditor.ScanError):
                auditor.validate_url(value)

    def test_blocks_localhost_and_private_ip_literals(self):
        for value in ("http://localhost", "http://127.0.0.1", "http://10.0.0.8", "http://[::1]/"):
            with self.subTest(value=value), self.assertRaises(auditor.ScanError):
                auditor.validate_url(value)

    @patch("app.socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.4", 0))])
    def test_blocks_hostname_resolving_to_private_ip(self, _resolver):
        with self.assertRaises(auditor.ScanError):
            auditor.validate_url("https://private.example")

    @patch("app.socket.getaddrinfo", side_effect=socket.gaierror)
    def test_reports_dns_failure(self, _resolver):
        with self.assertRaisesRegex(auditor.ScanError, "could not be resolved"):
            auditor.validate_url("https://missing.example")


class ScoringAndAnalysisTests(unittest.TestCase):
    def test_score_is_bounded_and_interpreted(self):
        self.assertEqual(auditor.calculate_score([]), (100, "Good"))
        all_missing = [{"points_deducted": 100}]
        self.assertEqual(auditor.calculate_score(all_missing), (0, "Poor"))
        self.assertEqual(auditor.calculate_score([{"points_deducted": 20}]), (80, "Good"))

    @patch("app.socket.getaddrinfo", return_value=PUBLIC_DNS_RECORD)
    @patch("app.requests.get")
    def test_all_six_headers_present(self, get, _resolver):
        get.return_value = response(200, {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        })
        result = auditor.analyze_target("https://example.com")
        self.assertEqual(len(result["findings"]), 6)
        self.assertEqual(result["present_count"], 6)
        self.assertEqual(result["score"], 100)
        self.assertTrue(all(item["status"] == "Present" for item in result["findings"]))
        get.assert_called_once_with(
            "https://example.com/", headers={"User-Agent": auditor.USER_AGENT},
            timeout=auditor.REQUEST_TIMEOUT, allow_redirects=False, stream=True,
        )

    @patch("app.socket.getaddrinfo", return_value=PUBLIC_DNS_RECORD)
    @patch("app.requests.get")
    def test_missing_and_weak_headers_are_reported(self, get, _resolver):
        get.return_value = response(200, {
            "Strict-Transport-Security": "max-age=60",
            "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline';",
            "X-Content-Type-Options": "something",
            "X-Frame-Options": "ALLOWALL",
            "Referrer-Policy": "unsafe-url",
            "Permissions-Policy": "camera=*",
        })
        result = auditor.analyze_target("https://example.com")
        self.assertTrue(all(item["status"] == "Weak" for item in result["findings"]))
        self.assertTrue(all(item["points_deducted"] > 0 for item in result["findings"]))
        self.assertLess(result["score"], 100)

    @patch("app.socket.getaddrinfo", return_value=PUBLIC_DNS_RECORD)
    @patch("app.requests.get")
    def test_missing_headers_include_notice(self, get, _resolver):
        get.return_value = response(200)
        result = auditor.analyze_target("https://example.com")
        self.assertEqual(result["missing_count"], 6)
        self.assertIn("did not include", result["notice"])

    @patch("app.socket.getaddrinfo", return_value=PUBLIC_DNS_RECORD)
    @patch("app.requests.get", side_effect=requests.Timeout)
    def test_timeout_is_a_user_safe_error(self, _get, _resolver):
        with self.assertRaisesRegex(auditor.ScanError, "timed out"):
            auditor.analyze_target("https://example.com")

    @patch("app.socket.getaddrinfo", return_value=PUBLIC_DNS_RECORD)
    @patch("app.requests.get", side_effect=requests.ConnectionError)
    def test_connection_failure_is_a_user_safe_error(self, _get, _resolver):
        with self.assertRaisesRegex(auditor.ScanError, "could not be reached"):
            auditor.analyze_target("https://example.com")

    @patch("app.socket.getaddrinfo", side_effect=[PUBLIC_DNS_RECORD, [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]])
    @patch("app.requests.get")
    def test_prohibited_redirect_is_blocked_before_request(self, get, _resolver):
        get.return_value = response(302, {"Location": "http://127.0.0.1/admin"})
        with self.assertRaisesRegex(auditor.ScanError, "public IP"):
            auditor.analyze_target("https://example.com")
        get.assert_called_once()

    @patch("app.socket.getaddrinfo", return_value=PUBLIC_DNS_RECORD)
    @patch("app.requests.get")
    def test_http_error_response_is_still_analyzed_with_notice(self, get, _resolver):
        get.return_value = response(503, {})
        result = auditor.analyze_target("https://example.com")
        self.assertIn("HTTP 503", result["notice"])


class RouteAndReportTests(unittest.TestCase):
    def setUp(self):
        auditor.app.config.update(TESTING=True)
        self.client = auditor.app.test_client()

    def test_index_route_loads_dashboard(self):
        response_result = self.client.get("/")
        self.assertEqual(response_result.status_code, 200)
        self.assertIn(b"Headerwatch", response_result.data)

    def test_empty_url_returns_json_error(self):
        response_result = self.client.post("/api/analyze", json={"url": ""})
        self.assertEqual(response_result.status_code, 400)
        self.assertIn("Enter a website URL", response_result.get_json()["error"])

    @patch("app.analyze_target", return_value={"ok": True, "score": 85, "findings": []})
    def test_successful_analysis_route_returns_json(self, analyze):
        response_result = self.client.post("/api/analyze", json={"url": "https://example.com"})
        self.assertEqual(response_result.status_code, 200)
        self.assertEqual(response_result.get_json()["score"], 85)
        analyze.assert_called_once_with("https://example.com")

    def test_report_route_downloads_html(self):
        response_result = self.client.post("/report", json={"result": {
            "target_url": "https://example.com", "findings": [], "score": 100,
            "assessment": "Good", "scanned_at": "today",
        }})
        self.assertEqual(response_result.status_code, 200)
        self.assertIn("attachment", response_result.headers["Content-Disposition"])
        self.assertIn(b"Security Header Audit Report", response_result.data)

    def test_dashboard_static_assets_are_served(self):
        for asset in ("style.css", "script.js"):
            with self.subTest(asset=asset):
                response_result = self.client.get(f"/static/{asset}")
                self.assertEqual(response_result.status_code, 200)
                self.assertGreater(len(response_result.data), 100)
                response_result.close()

    def test_html_report_escapes_untrusted_content(self):
        malicious = '<script>alert("xss")</script>'
        report = auditor.create_html_report({
            "target_url": malicious,
            "scanned_at": "today",
            "score": 100,
            "assessment": malicious,
            "findings": [{
                "name": "CSP", "status": "Weak", "value": malicious,
                "purpose": malicious, "risk": malicious, "recommendation": malicious,
            }],
        })
        self.assertNotIn(malicious, report)
        self.assertIn("&lt;script&gt;", report)

    def test_report_route_requires_a_completed_scan(self):
        response_result = self.client.post("/report", json={})
        self.assertEqual(response_result.status_code, 400)


if __name__ == "__main__":
    unittest.main()