# `mlflow-scorer-scanner`

Detection-only triage scanner for `MLflow` third-party scorer deserialization `RCE`, `CVE-2026-116692`. It asks a tracking server one safe question, its version, and grades it. It never exploits anything.

## `The flaw`

| `Detail` | `Value` |
| --- | --- |
| `CVE` | `CVE-2026-116692` |
| `Advisory` | `GHSA-26p8-2jq9-3vq9` |
| `Bug` | `Deserialization of untrusted data` (`CWE-94`), third-party scorer handling in `mlflow/genai/scorers/base.py` |
| `Impact` | `Unauthenticated remote code execution` on a default tracking server, root in the official image |
| `Severity` | `9.8` critical |

`MLflow 3.12.0` introduced registration and deserialization support for third-party scorers. The vulnerable code accepts a request-selected module path beneath one of four allowed package prefixes instead of requiring an exact allowed module, then imports that module and constructs the class during `Scorer.model_validate_json()`. An attacker who can place a `Python` module under a writable allowed package, via the normal artifact endpoints, and then submit it through `/ajax-api/3.0/mlflow/scorer/invoke`, gets code execution in the server process. This scanner never does any of that: no scorer request, no experiment, no run, no artifact upload.

Two source disagreements, and what this scanner follows. One write-up frames the range as `3.12.0` through `3.16.x`; the advisory text itself, quoted in a second write-up, starts at `3.12.0rc0` and ends before `3.17.0`. This scanner follows the advisory text, so `3.12.0rc0` grades `VULNERABLE`. On authentication, the advisory text says auth-disabled deployments permit the attack without credentials, while basic-auth deployments require a principal able to create experiments and runs and upload artifacts. A version in range on an auth-enabled server is therefore still a finding, but a weaker one than the same version exposed without auth.

## `Fixed versions`

| `Branch` | `Status` |
| --- | --- |
| `MLflow < 3.12.0rc0` | `NOT_AFFECTED`, scorer support did not exist yet |
| `MLflow 3.12.0rc0` to before `3.17.0` | `VULNERABLE` |
| `MLflow >= 3.17.0` | `FIXED` |

Updating to `3.17.0` is the fix. Until then, do not expose a tracking server without authentication, and make sure no scorer package path is writable by the server process.

## `What it checks`

- `GET <base>/version`, the endpoint `MLflow` itself documents for checking a tracking server version. That is the only request it makes.
- The returned version string, graded against the range above. A `JSON` wrapper like `{"version": "3.14.0"}` is accepted; anything else unparseable grades `UNKNOWN`.

## `What it never does`

No payloads. No scorer invocations. No experiment, run, or artifact creation. No upload of any file, malicious or otherwise. It reads one public version string and stops.

## `Grading`

| `Finding` | `Severity` |
| --- | --- |
| `Version 3.12.0rc0` to before `3.17.0` | `VULNERABLE` |
| `Version 3.17.0` or later | `FIXED` |
| `Version before 3.12.0rc0` | `NOT_AFFECTED` |
| `Version hidden behind auth`, `404`, or unparseable | `UNKNOWN`, not clean |
| `Target unreachable` or not `http(s)` | `ERROR`, not clean |

## `Usage`

```
# Triage one tracking server (default MLflow port is 5000)
python3 mlflow_scorer_scanner.py http://localhost:5000

# Machine-readable output
python3 mlflow_scorer_scanner.py https://mlflow.example.com --json

# Tests (mock servers only, no real MLflow needed)
python3 -m unittest discover -s tests -v
```

Exit codes: `0` = fixed, not affected, or unknown, `2` = vulnerable finding, `1` = scan error.

## `Honest caveats`

- A version in range is triage, not proof of exploitability. The full chain also needs a writable allowed scorer package, and on auth-enabled servers an authenticated principal with experiment, run, and artifact rights.
- No public exploit code was indexed for this `CVE` at time of writing, and it was not in `CISA KEV`. That is a statement about what was public on `2026-10-28`, not a safety claim.
- No `Nuclei` template or widely-available public scanner specifically for `CVE-2026-116692` was found at time of writing. Generic `MLflow` version and unauthenticated-access checks exist, but they do not grade this scorer range.
- If `/version` is blocked or auth-gated, this scanner says `UNKNOWN`, not clean. Confirm the version another way before closing the finding.

## `References`

- `GHSA-26p8-2jq9-3vq9` (`MLflow` advisory, affected range, fixed in `3.17.0`)
- `CVE-2026-116692` record (published `2026-10-27`, `CVSS 9.8`, `CWE-94`)
- `MLflow` tracking server docs (the `/version` endpoint)

## `Thanks to`

- The `MLflow` maintainers for the advisory and the `3.17.0` fix
- Everyone publishing `MLflow` tracking-server exposure research

## `Disclaimer`

Built for defensive triage and authorized testing only. Scan only systems you own or are authorized to test. The authors are not responsible for misuse.

> Research by `Vineeth Kumar` (`foxcornlab`). Found a bug or want a feature, open an `issue`.
