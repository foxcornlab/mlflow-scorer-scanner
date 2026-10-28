#!/usr/bin/env python3
"""Detection-only triage scanner for CVE-2026-116692 (MLflow scorer RCE).

It makes exactly one safe request: GET <base>/version, the endpoint MLflow
itself documents for checking a tracking server's version. It never sends a
scorer payload, never creates an experiment, run, or artifact, and never
touches /ajax-api/3.0/mlflow/scorer/invoke. A version in the affected range
is a triage finding, not proof of exploitability: exploitation also needs a
writable scorer package on the server and, on auth-enabled deployments, a
principal able to create experiments/runs and upload artifacts.

Usage:
    python3 mlflow_scorer_scanner.py http://localhost:5000
    python3 mlflow_scorer_scanner.py https://mlflow.example.com --json

Exit codes: 0 = fixed, not affected, or unknown; 2 = vulnerable; 1 = scan error.
"""

import argparse
import json
import re
import sys
import urllib.error
import urllib.request

CVE = "CVE-2026-116692"
GHSA = "GHSA-26p8-2jq9-3vq9"
# Affected: 3.12.0rc0 (inclusive) through anything before 3.17.0. Fixed: 3.17.0.
AFFECTED_MIN = (3, 12, 0)
FIXED = (3, 17, 0)
USER_AGENT = "mlflow-scorer-scanner/1.0 (+https://github.com/foxcornlab/mlflow-scorer-scanner)"

_VERSION_RE = re.compile(
    r"^(\d+)\.(\d+)\.(\d+)"
    r"(?:rc(\d+))?"
    r"(?:\.?(?:dev|a|b)\d*)?$"
)


def parse_version(text):
    """Parse an MLflow version string into a comparable key, or None.

    Returns (major, minor, patch, is_final, rc_number) where a release
    candidate sorts before the final release of the same numbers, so
    3.12.0rc0 < 3.12.0 < 3.12.1. Trailing junk (HTML, JSON wrappers handled
    by the caller) is rejected rather than guessed at.
    """
    if text is None:
        return None
    text = text.strip().strip('"').strip()
    match = _VERSION_RE.match(text)
    if not match:
        return None
    major, minor, patch = (int(match.group(i)) for i in (1, 2, 3))
    rc = match.group(4)
    if rc is None:
        return (major, minor, patch, 1, 0)
    return (major, minor, patch, 0, int(rc))


def grade(version_text):
    """Grade a raw /version body. Returns (verdict, version_or_None, detail)."""
    if version_text is None:
        return ("UNKNOWN", None, "no version returned")
    text = version_text.strip()
    if not text or text.startswith("<"):
        return ("UNKNOWN", None, "version endpoint did not return a plain version string")
    # Tolerate a JSON wrapper, e.g. {"version": "3.14.0"}, but nothing else.
    if text.startswith("{"):
        try:
            text = json.loads(text).get("version", "")
        except (ValueError, AttributeError):
            return ("UNKNOWN", None, "version endpoint returned unparseable JSON")
        if not isinstance(text, str):
            return ("UNKNOWN", None, "version endpoint returned unparseable JSON")
    key = parse_version(text)
    if key is None:
        return ("UNKNOWN", None, "unparseable version string: %r" % text[:80])
    version = text.strip()
    if key < (AFFECTED_MIN[0], AFFECTED_MIN[1], AFFECTED_MIN[2], 0, 0):
        return ("NOT_AFFECTED", version,
                "third-party scorer support arrived in 3.12.0rc0; this release predates it")
    if key < (FIXED[0], FIXED[1], FIXED[2], 1, 0):
        return ("VULNERABLE", version,
                "in affected range 3.12.0rc0 to before 3.17.0; upgrade to 3.17.0")
    return ("FIXED", version, "3.17.0 or later")


def fetch_version(base_url, timeout=10):
    """GET <base>/version. Returns (status, body_or_None, error_or_None)."""
    url = base_url.rstrip("/") + "/version"
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return (response.status, response.read().decode("utf-8", "replace"), None)
    except urllib.error.HTTPError as exc:
        # 401/403 means the version is hidden behind auth: unknown, not clean.
        # A 404 means this is probably not an MLflow tracking server at all.
        if exc.code in (401, 403):
            return (exc.code, None, "version endpoint requires authentication")
        return (exc.code, None, "version endpoint returned HTTP %d" % exc.code)
    except urllib.error.URLError as exc:
        return (None, None, "could not reach target: %s" % exc.reason)
    except (ValueError, OSError) as exc:
        return (None, None, "request failed: %s" % exc)


def scan(base_url, timeout=10):
    if not base_url.startswith(("http://", "https://")):
        return {"target": base_url, "verdict": "ERROR",
                "detail": "target must start with http:// or https://"}
    status, body, error = fetch_version(base_url, timeout)
    if error is not None:
        # Auth-gated and missing endpoints are UNKNOWN, transport failures ERROR.
        if "requires authentication" in error or "HTTP 404" in error:
            verdict = "UNKNOWN"
            return {"target": base_url, "verdict": verdict,
                    "http_status": status, "detail": error}
        return {"target": base_url, "verdict": "ERROR",
                "http_status": status, "detail": error}
    verdict, version, detail = grade(body)
    result = {"target": base_url, "verdict": verdict, "http_status": status,
              "detail": detail}
    if version is not None:
        result["version"] = version
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Detection-only triage for CVE-2026-116692 (MLflow scorer RCE).")
    parser.add_argument("target", help="MLflow tracking server base URL, e.g. http://localhost:5000")
    parser.add_argument("--timeout", type=float, default=10, help="request timeout in seconds")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    result = scan(args.target, timeout=args.timeout)
    result.update({"cve": CVE, "advisory": GHSA})
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("target:  %s" % result["target"])
        if "version" in result:
            print("version: %s" % result["version"])
        print("verdict: %s" % result["verdict"])
        print("detail:  %s" % result["detail"])
    if result["verdict"] == "VULNERABLE":
        return 2
    if result["verdict"] == "ERROR":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
