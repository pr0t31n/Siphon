# Siphon

**API Penetration Testing Orchestrator** — OWASP API Security Top 10 2023

Siphon is a comprehensive API security assessment tool that performs automated
testing against the OWASP API Security Top 10 (2023 edition). It discovers
endpoints from OpenAPI/Swagger specifications, fingerprints the server, and
runs structured attack phases covering injection, authentication bypass, rate
limiting, mass assignment, SSRF, data exposure, GraphQL attacks, BOLA, BFLA,
JWT attacks, and cross-user data leakage.

---

## OWASP API Security Top 10 2023 Coverage

| OWASP Category                                | Phase(s)             |
|-----------------------------------------------|----------------------|
| API1:2023 — Broken Object Level Authorization | Phase 10 (bola)      |
| API2:2023 — Broken Authentication             | Phase 4 (auth_bypass), Phase 13 (session), Phase 14 (jwt) |
| API3:2023 — Broken Object Property Level Auth | Phase 6 (mass_assignment), Phase 8 (data_exposure) |
| API4:2023 — Unrestricted Resource Consumption | Phase 5 (rate_limiting) |
| API5:2023 — Broken Function Level Auth        | Phase 11 (bfla)      |
| API6:2023 — Unrestricted Access to Sensitive Business Flows | Phase 5, Phase 2 |
| API7:2023 — Server Side Request Forgery       | Phase 7 (ssrf)       |
| API8:2023 — Security Misconfiguration         | Phase 1 (recon), Phase 9 (graphql) |
| API9:2023 — Improper Inventory Management     | Phase 0 (discovery)  |
| API10:2023 — Unsafe Consumption of APIs       | Phase 3 (injection)  |

---

## Prerequisites

- Python 3.10+
- pip packages: `requests`, `colorama`, `pyyaml`
- Optional system tools: `nuclei`, `jq`, `curl`

Install all dependencies:

```bash
python3 install.py
```

Or install Python packages manually:

```bash
pip install -r requirements.txt
```

---

## Usage

### Basic scan (unauthenticated):
```bash
python3 siphon.py --url https://api.example.com/v1
```

### Scan with OpenAPI spec:
```bash
python3 siphon.py --url https://api.example.com/v1 \
    --openapi /path/to/openapi.json
```

### Authenticated scan with Bearer token:
```bash
python3 siphon.py --url https://api.example.com/v1 \
    --auth-token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Form-based auth scan:
```bash
python3 siphon.py --url https://api.example.com/v1 \
    --auth-type form \
    --login-url https://api.example.com/auth/login \
    --username user@example.com \
    --password s3cr3t
```

### Fast scan (skip slow phases):
```bash
python3 siphon.py --url https://api.example.com/v1 --fast
```

### Use a settings file:
```bash
python3 siphon.py --settings myproject.json
```

### List all phases:
```bash
python3 siphon.py --list-phases
```

---

## Settings Reference

Create a JSON settings file to configure a full engagement:

```json
{
  "engagement": {
    "consultant":       "Jane Smith",
    "client_name":      "Acme Corporation",
    "client_short":     "acme",
    "consultant_email": "jane@consultancy.com",
    "start_date":       "2025-01-01",
    "end_date":         "2025-01-07"
  },
  "scan": {
    "project":          "acme_api_pentest",
    "api_base_url":     "https://api.acme.com/v2",
    "openapi_url":      "https://api.acme.com/openapi.json",
    "threads":          20,
    "timeout":          10,
    "proxy":            "http://127.0.0.1:8080",
    "verify_ssl":       false,
    "phases": {
      "discovery":      true,
      "recon":          true,
      "fuzzing":        true,
      "injection":      true,
      "auth_bypass":    true,
      "rate_limiting":  true,
      "mass_assignment":true,
      "ssrf":           true,
      "data_exposure":  true,
      "graphql":        true,
      "bola":           true,
      "bfla":           true,
      "cross_user":     true,
      "session":        true,
      "jwt":            true
    },
    "auth": {
      "enabled":        true,
      "auth_type":      "token",
      "auth_token":     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "token_type":     "Bearer"
    },
    "auth2": {
      "enabled":        true,
      "auth_token":     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    },
    "jwt_secret":       "optional-known-secret-for-cracking",
    "rate_limit_threshold": 50,
    "mass_assignment_fields": ["is_admin", "role", "plan"]
  }
}
```

### Key Settings

| Setting | Description |
|---------|-------------|
| `scan.api_base_url` | API root URL (e.g. `https://api.example.com/v1`) |
| `scan.openapi_url`  | URL or file path to OpenAPI/Swagger specification |
| `scan.project`      | Output directory name |
| `scan.threads`      | Concurrent request threads (default: 20) |
| `scan.timeout`      | Per-request timeout in seconds (default: 10) |
| `scan.proxy`        | HTTP proxy for all requests (e.g. Burp Suite) |
| `scan.verify_ssl`   | TLS certificate verification (default: false) |
| `scan.auth.auth_type` | `token` \| `basic` \| `form` |
| `scan.auth.auth_token` | Pre-obtained Bearer token |
| `scan.jwt_secret`   | Known JWT secret for HMAC cracking phase |
| `scan.rate_limit_threshold` | Request count before expecting 429 |

---

## Output Files

All results are written to the `project` directory:

| File | Description |
|------|-------------|
| `siphon_output.json` | Full findings catalogue in JSON format |
| `siphon_output.csv`  | Findings in CSV format for spreadsheet import |
| `siphon_output.txt`  | Human-readable text report |
| `api_inventory.json` | Discovered endpoint inventory |

### Finding Format

```json
{
  "id": 1,
  "phase": "auth_bypass",
  "title": "JWT None Algorithm Accepted",
  "severity": "CRITICAL",
  "url": "https://api.example.com/v1/users",
  "detail": "Server accepted JWT with alg:none on GET /users.",
  "evidence": "none-alg token accepted, HTTP 200",
  "remediation": "Reject JWTs with alg:none; enforce strict algorithm validation.",
  "timestamp": "2025-01-01T12:00:00Z"
}
```

Severity levels: `CRITICAL` | `HIGH` | `MEDIUM` | `LOW` | `INFO`

---

## Phase Details

| Phase | Name | Description |
|-------|------|-------------|
| 0 | discovery | Probe for OpenAPI/Swagger spec; build endpoint inventory |
| 1 | recon | Fingerprint server headers; check CORS and security headers |
| 2 | fuzzing | HTTP method fuzzing; undocumented parameter discovery |
| 3 | injection | SQLi, NoSQLi, SSTI, XXE, LDAP injection via API parameters |
| 4 | auth_bypass | JWT none-alg, weak HMAC, missing auth enforcement |
| 5 | rate_limiting | Rate limit detection and IP header bypass techniques |
| 6 | mass_assignment | Over-posting privileged fields in write endpoints |
| 7 | ssrf | SSRF via URL-accepting API parameters |
| 8 | data_exposure | Sensitive field detection in API responses |
| 9 | graphql | GraphQL introspection; query depth attacks |
| 10 | bola | BOLA/IDOR — cross-user object access (auth required) |
| 11 | bfla | BFLA — admin endpoint access with regular user (auth required) |
| 12 | cross_user | Cross-user data leakage (auth + auth2 required) |
| 13 | session | JWT expiry, logout invalidation, algorithm checks (auth required) |
| 14 | jwt | JWT HMAC cracking, jku injection, kid injection (auth required) |

---

## Crucible Integration

Siphon is wrapped by **Crucible** (port 5500) as tool key `"si"`. When launched
by Crucible, the environment variable `VANTAGE_MANAGED=1` is set and Siphon emits
structured protocol tokens on stdout:

| Token | Purpose |
|-------|---------|
| `__VANTAGE_LOG__:` | Log message |
| `__VANTAGE_ERR__:` | Error message |
| `__VANTAGE_STATUS__:` | Phase state update (JSON) |
| `__VANTAGE_PROMPT__:` | Interactive prompt request (JSON) |

---

## Legal Disclaimer

**Siphon is intended for authorized security testing only.** Always obtain
explicit written permission from the asset owner before running any scans.
Unauthorized use against systems you do not own or have permission to test may
violate computer fraud and abuse laws. The authors accept no liability for
misuse of this tool.
