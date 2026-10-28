"""Tests for mlflow_scorer_scanner, run against local mock MLflow servers.

No real MLflow server, no payloads, no scorer endpoint is ever touched:
the mock only serves GET /version, exactly like the scanner expects.
"""

import http.server
import json
import threading
import unittest

import mlflow_scorer_scanner as scanner


def make_server(body, status=200):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/version":
                payload = body.encode()
                self.send_response(status)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, "http://127.0.0.1:%d" % server.server_address[1]


class TestGrading(unittest.TestCase):
    def test_vulnerable_boundaries(self):
        for version in ("3.12.0rc0", "3.12.0", "3.14.0", "3.16.1", "3.17.0rc0"):
            verdict, _, _ = scanner.grade(version)
            self.assertEqual(verdict, "VULNERABLE", version)

    def test_fixed_and_predating(self):
        self.assertEqual(scanner.grade("3.17.0")[0], "FIXED")
        self.assertEqual(scanner.grade("3.17.1")[0], "FIXED")
        self.assertEqual(scanner.grade("3.11.0")[0], "NOT_AFFECTED")
        self.assertEqual(scanner.grade("3.10.0")[0], "NOT_AFFECTED")

    def test_rc_ordering(self):
        self.assertLess(scanner.parse_version("3.12.0rc0"), scanner.parse_version("3.12.0"))
        self.assertLess(scanner.parse_version("3.17.0rc0"), scanner.parse_version("3.17.0"))

    def test_unknown_not_clean(self):
        for body in ("", "<html>MLflow</html>", "not-a-version", '{"nope": 1}'):
            self.assertEqual(scanner.grade(body)[0], "UNKNOWN", body)
        # A JSON wrapper with a real version still grades.
        self.assertEqual(scanner.grade('{"version": "3.14.0"}')[0], "VULNERABLE")


class TestMockServers(unittest.TestCase):
    def run_case(self, body, status, expected):
        server, url = make_server(body, status)
        try:
            self.assertEqual(scanner.scan(url)["verdict"], expected)
        finally:
            server.shutdown()
            server.server_close()

    def test_vulnerable_server(self):
        self.run_case("3.14.0", 200, "VULNERABLE")

    def test_fixed_server(self):
        self.run_case("3.17.0", 200, "FIXED")

    def test_not_affected_server(self):
        self.run_case("3.11.0", 200, "NOT_AFFECTED")

    def test_auth_gated_is_unknown_not_clean(self):
        self.run_case("", 401, "UNKNOWN")

    def test_missing_endpoint_is_unknown_not_clean(self):
        self.run_case("", 404, "UNKNOWN")

    def test_unreachable_is_error(self):
        result = scanner.scan("http://127.0.0.1:1")
        self.assertEqual(result["verdict"], "ERROR")

    def test_non_http_target_is_error(self):
        self.assertEqual(scanner.scan("localhost:5000")["verdict"], "ERROR")


if __name__ == "__main__":
    unittest.main()
