# Siphon

**API Penetration Testing Orchestrator** — OWASP API Security Top 10 2023

Siphon is a comprehensive API security assessment tool that performs automated
testing against the OWASP API Security Top 10 (2023 edition). It discovers
endpoints from OpenAPI/Swagger specifications, fingerprints the server, and
runs structured attack phases covering injection, authentication bypass, rate
limiting, mass assignment, SSRF, data exposure, GraphQL attacks, BOLA, BFLA,
JWT attacks, and cross-user data leakage.

**AI/ML API Detection (v2.40.0):** Phase 0 (discovery) now probes for AI/ML API
endpoints — OpenAI-compatible, Ollama, Gradio, MLflow, Triton, Streamlit, and
LangFlow. Detected AI services generate an INFO finding and an `ai_discovered`
action item recommending pAIn testing. OpenAPI spec analysis also flags AI/ML
endpoints by path patterns, body field schemas (prompt, messages, temperature,
max_tokens), and tags.

---


> **[View full documentation on the Codex Wiki](https://wiki.pr0t31n.com/tools/siphon)** — detailed features, CLI reference, findings catalogue, and integration guides.

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
| `api_inventory.json` | Discovered endpoint inventory (value-aware as of v2.13.0 — see below) |
| `meta.json` | Tool identity + version (§13b) |
| `scan.log` / `scan.log.json` | Timestamped audit log (v2.26.0+): own version + phase EVENT transitions + all messages (§13b/§14j/§14k). External tool versions are recorded in each invocation's `.log` sibling. |
| `errors.log` / `errors.log.json` | ERROR-level + TOOL_ERROR entries |

### Value-aware endpoint inventory (v2.13.0)

As of v2.13.0 the spec/data-file parsers no longer discard the values, types and
examples those files carry. Each endpoint in `api_inventory.json` is enriched with:

- **Parameter schema** — per query/path parameter `type`, `format`, `enum`,
  `example` and `default` extracted from OpenAPI/Swagger (including `$ref`
  resolution), or the actual values supplied in a Postman/Insomnia/HAR file.
- **`body_schema`** — a normalised, nested schema for the request body, derived
  from the OpenAPI request body or inferred from a populated example body.
- **`observed_responses`** — real/example responses harvested from HAR captures
  and saved Postman example responses (a known-good oracle for later phases).
- **Name-based type inference** — when nothing is declared, the field name is
  used to infer a likely type/format (e.g. `*_id` → integer, `email` → email,
  `*_at` → date-time, `is_*` → boolean, `callback`/`url` → uri).

These additions are backward compatible — existing keys (`params`,
`body_fields`, etc.) are preserved, so downstream consumers are unaffected.

### Valid-body injection testing (v2.14.0)

Injection testing (SQLi / NoSQLi / SSTI / LDAP) now builds an **otherwise-valid
request body** from the endpoint's schema and injects the payload into only the
field under test. Previously a non-GET injection request contained just the
single tested field, so APIs that enforce required fields rejected the request
with HTTP 400 before the payload reached the injection sink — a false negative
on every multi-field `POST`/`PUT`/`PATCH` endpoint. Query/path parameters are
injected via the URL while a valid body is still supplied.

> **Note:** because injection requests against write methods are now valid, they
> may create or modify records on the target. Run only with authorisation. The
> payload set used excludes destructive stacked queries (e.g. `DROP TABLE`).
> Configurable safe-mode gating is planned for a later release.

### Differential blind-injection detection (v2.15.0)

Injection testing now includes a differential analysis engine that detects
**blind** SQL injection without relying on database error strings:

- **Boolean-based blind** — a known-good baseline is captured from a valid
  request; a `TRUE` injected condition that tracks the baseline while a `FALSE`
  condition diverges confirms the injection alters query logic.
- **Time-based blind** — time-delay payloads (`SLEEP` / `pg_sleep` / `WAITFOR`)
  that induce a repeatable, measured response delay (confirmed over two probes,
  with a jitter threshold) confirm backend SQL execution.

Findings now carry a **confidence** rating (`Certain` / `Firm` / `Tentative`):
error-based SQLi is reported as `Tentative` (single-probe signal) while
differential blind findings are `Firm`. Time-based testing is skipped when the
configured timeout is too small to observe the induced delay.

### Typed fuzz corpora & parameter wordlists (v2.16.0)

Parameter fuzzing no longer uses a flat 8-value list. Values are now chosen per
parameter **type** — using the type/format detected in the value-aware inventory
or inferred from the field name — from valid / boundary / malformed corpora
(e.g. an `integer` parameter is fuzzed with `0`, `-1`, `2147483648`, overflow and
type-mismatch values; an `email` parameter with header-injection and malformed
variants). Undocumented-parameter discovery (and the FFUF parameter pass) draw
from a curated, API-oriented wordlist.

Both are editable data files shipped under `<siphon>/data/` — no code change is
needed to extend them per engagement:

| File | Purpose |
|------|---------|
| `data/api_param_names.txt` | Parameter-name wordlist (one per line; unioned with the in-code defaults) |
| `data/fuzz_values.json` | Optional per-type fuzz-value override / extension |

### Schema-driven abuse testing (v2.17.0)

Using the value-aware inventory, Siphon now tests for missing server-side input
validation on documented parameters. A valid baseline request must be accepted
first (false-positive gate); each test then sends an otherwise-valid request with
one field set to an invalid value and reports acceptance:

- **Enumerated value restriction not enforced** — an out-of-enum value is accepted.
- **Numeric boundary not enforced** — an out-of-range value is accepted.
- **Parameter type confusion** — a scalar field accepts a JSON array (a vector for
  NoSQL operator injection / type-juggling auth bypass).

These are reported at LOW/MEDIUM severity with `Tentative` confidence
(acceptance is a validation-hygiene signal, not a confirmed exploit).

**Postman collection variables** (`{{variable}}`) are now resolved from the
collection's `variable` map, so harvested paths and example values are usable
directly.

### Additional schema-abuse checks (v2.18.0)

- **HTTP Parameter Pollution** — duplicate query parameters that change the
  response vs the single-value baseline (filter/WAF-bypass surface).
- **Content-Type confusion** — a JSON endpoint that also accepts a
  form-urlencoded body (parser-differential / CSRF surface).
- **Unbounded resource consumption** — pagination parameters (`limit`,
  `page_size`, …) that accept an extreme value and return a materially larger
  result set, i.e. no server-side cap (OWASP API4).
- **Excessive data exposure (BOPLA)** — response fields that are **not** part of
  the documented response schema and look sensitive (PII/credentials/tokens).
  When no response schema exists, a saved **example response** (HAR / Postman)
  is used as the known-good oracle.

### Mandatory environment & safety model (v2.20.0)

Siphon requires an explicit **`environment`** declaration — there is no default.
Set it via `--environment {production,non-production}` (CLI) or `scan.environment`
(settings); Crucible presents a required dropdown. Siphon **refuses to run**
without it.

- **non-production** → full testing.
- **production** → partial testing: **no write-method state changes** (injection,
  schema-abuse, XXE, command/CRLF/path-traversal, deserialization, and method
  fuzzing are skipped on `POST`/`PUT`/`PATCH`/`DELETE`; read-method equivalents
  still run), and the **business-flow and mass-assignment phases are disabled**.
  BOLA/cross-user and rate-limit tests still run.

Other safety/quality changes in v2.20.0:

- Destructive stacked-query payloads (`DROP TABLE` etc.) are **removed**; they are
  never sent.
- Time-based blind SQLi is consolidated into a **single** gated differential pass
  (no more redundant `SLEEP` passes hammering the DB).
- Injection detections are hardened against false positives: SSTI uses a
  randomised arithmetic sentinel with a reflection control probe; error-based
  SQLi, XXE, and command injection each require a **confirming control probe**
  before reporting (and carry `Firm`/`Tentative` confidence accordingly).

Evidence files referenced by findings are recorded **relative to the run
directory** (CLAUDE.md §13c), so Crucible / Prometheus resolve them.

### Logging, back-off & auth-bypass accuracy (v2.21.0)

- **Tool execution logging (§14):** every external binary invocation
  (kiterunner, ffuf, feroxbuster, dirsearch, sslscan, testssl) now emits a
  sibling `.log` next to its primary output via the shared
  `pr0t31n_tool_runner`, capturing the command line, timing, exit code, and
  stdout/stderr.
- **HTTP 429 back-off (C14):** when a target returns `429 Too Many Requests`,
  the shared request helpers sleep for the `Retry-After` interval (capped at
  30 s) before continuing, so Siphon stops hammering an overloaded endpoint.
  The 429 is still surfaced so rate-limit *detection* continues to work.
- **Missing-authentication accuracy (B6):** the "Missing Authentication
  Enforcement" check now performs an authenticated second probe. A finding is
  raised only when the unauthenticated response exposes sensitive/user data or
  is confirmed to be the same resource an authenticated request returns —
  eliminating false positives on benign public endpoints. Findings carry
  `Firm`/`Tentative` confidence accordingly.

### Expanded coverage (v2.22.0)

- **Schema-driven mass assignment (C8):** the over-posting test now builds a
  schema-valid baseline body (Phase A inventory) so the request passes
  validation and the injected privileged fields actually reach the model, and
  injects only properties **not** declared by the schema (true undeclared
  over-posting). Runs in non-production only.
- **Broader SSRF payloads (C9):** added AWS IAM-credentials metadata path, GCP /
  Azure / Alibaba metadata endpoints, gopher:// and dict:// internal-service
  probes, and decimal-IP / userinfo-confusion bypasses. `phase_ssrf` now also
  honors the production safety gate (write-method SSRF is skipped in production).
- **JWT attacks (C11):** already covered by the JWT phase — HMAC secret
  brute-force, jku/x5u JWKS spoofing, kid SQL-injection and path-traversal, and
  RS256→HS256 algorithm confusion. No change required.

### Non-HTTP protocol coverage (v2.23.0, Phase 21 — `protocols`)

A new `protocols` phase performs **detection + passive checks** (no message
fuzzing / method invocation) for:

- **WebSocket** — derives `ws`/`wss` candidates from the inventory + common
  paths, attempts the handshake, and flags unencrypted `ws://` transport and
  handshakes that accept an arbitrary `Origin` without credentials (CSWSH risk).
  Requires `websocket-client` (degrades gracefully if absent).
- **Server-Sent Events (SSE)** — detects `text/event-stream` endpoints and flags
  unauthenticated streams and cleartext-HTTP streams. Uses `requests` (no extra
  dependency).
- **gRPC** — uses `grpcurl` server reflection to enumerate services and flags
  exposed reflection and plaintext (non-TLS) transport. Requires `grpcurl`
  (degrades gracefully if absent); the invocation emits a §14 `.log` sibling.

All protocol checks are read-only, so the phase runs in both production and
non-production. New dependencies are installed by `install.py`
(`websocket-client` via pip, `grpcurl` via go/brew).

### Request chaining (v2.24.0, Phase 0c — `chaining`)

A new `chaining` phase runs immediately after discovery, before the testing
phases. It executes the inventory's requests in **declared order**, capturing
reusable values from each response — `id`/`*_id`/`uuid`/`slug`, tokens
(`token`/`access_token`/`jwt`/`api_key`), and `Location` headers — into a chain
context. It then:

- applies a captured bearer token to the session (when none is set),
- **seeds** the captured values back into the endpoint inventory (as
  `observed_values` / schema `example`s), so later phases build requests that
  satisfy create→read→update preconditions and reach real application logic
  (e.g. `GET /users/{id}` uses a `{id}` returned by a prior `POST /users`).

The phase produces no findings (it establishes state). In **production** only
read methods are executed (no state changes); **non-production** runs the full
chain (capped at 40 requests).

> Still deferred (later release): §14 per-tool `.log` siblings for the external
> binaries (ffuf / kiterunner / feroxbuster / dirsearch / sslscan / testssl), and
> stateful request chaining (executing collection requests in dependency order to
> satisfy create→read→update preconditions).

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
by Crucible, the environment variable `CRUCIBLE_MANAGED=1` is set and Siphon emits
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
