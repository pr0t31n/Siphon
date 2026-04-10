#!/usr/bin/env python3
"""
testConnection.py — Siphon authentication connection test utility.

Tests that configured credentials successfully authenticate against the
target API and that subsequent requests can be made.  Designed to be
called both from the command line and from Crucible's test-connection
endpoint (via --output-json for machine-readable results).

Usage examples:

  # Use an existing Siphon settings file
  python3 testConnection.py --settings si_settings.json

  # Inline JSON config (used by Crucible backend)
  python3 testConnection.py --json '{"url":"https://api.example.com","auth":{...}}'

  # Individual flags
  python3 testConnection.py --url https://api.example.com \\
      --auth-method cookie_login \\
      --login-url https://api.example.com/api/auth/login \\
      --login-data '{"username":"usr","password":"pw"}'

  # List supported auth methods
  python3 testConnection.py --list-methods
"""

import argparse
import json
import sys

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VERSION = "1.4.5"

AUTH_METHODS: dict[str, str] = {
    "bearer":              "Bearer Token (Authorization: Bearer <token>)",
    "basic":               "HTTP Basic Auth (username / password)",
    "digest":              "HTTP Digest Auth (username / password)",
    "apikey":              "API Key (custom header or query parameter)",
    "cookie_login":        "Cookie Login  — POST credentials, use response cookies",
    "token_login":         "Token Login   — POST credentials, extract token from JSON response",
    "oauth2_client_creds": "OAuth2 Client Credentials (machine-to-machine, RFC 6749 §4.4)",
    "header_creds":        "Custom Headers — static key-value credential headers",
    "ntlm":                "NTLM / Windows Authentication (Active Directory)",
}


# ─────────────────────────────────────────────────────────────────────────────
# Session helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_session(verify_ssl: bool = False, proxy: str = "") -> requests.Session:
    sess = requests.Session()
    retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
    sess.mount("http://",  HTTPAdapter(max_retries=retry))
    sess.mount("https://", HTTPAdapter(max_retries=retry))
    sess.verify = verify_ssl
    if proxy:
        sess.proxies = {"http": proxy, "https": proxy}
    sess.headers["User-Agent"] = f"Siphon-testConnection/{VERSION}"
    return sess


def _login_post(
    sess: requests.Session,
    auth: dict,
    timeout: int,
) -> "requests.Response | None":
    """POST to login_url, building the body according to login_mode."""
    url = auth.get("login_url", "")
    if not url:
        return None
    login_mode = auth.get("login_mode", "merge")
    uf = auth.get("login_username_field", "username")
    pf = auth.get("login_password_field", "password")
    u  = auth.get("username", "")
    p  = auth.get("password", "")
    if login_mode == "fields":
        # Body built entirely from the credential field values
        data: dict = {}
        if u: data[uf] = u
        if p: data[pf] = p
    elif login_mode == "json":
        # Use the raw JSON body as-is; no credential injection
        raw = auth.get("login_data", "{}")
        try:
            data = json.loads(raw) if isinstance(raw, str) else dict(raw)
        except Exception:
            data = {}
    else:
        # Legacy "merge" behaviour: JSON body with missing creds injected
        raw = auth.get("login_data", "{}")
        try:
            data = json.loads(raw) if isinstance(raw, str) else dict(raw)
        except Exception:
            data = {}
        if u and uf not in data:
            data[uf] = u
        if p and pf not in data:
            data[pf] = p
    ct = auth.get("login_content_type", "application/json")
    try:
        if "json" in ct:
            return sess.post(url, json=data, timeout=timeout)
        return sess.post(url, data=data, timeout=timeout)
    except Exception:
        return None  # caller handles


# ─────────────────────────────────────────────────────────────────────────────
# Auth session builder
# ─────────────────────────────────────────────────────────────────────────────

def build_auth_session(
    auth: dict,
    timeout: int = 10,
    proxy: str = "",
    verify_ssl: bool = False,
) -> tuple[requests.Session, str]:
    """
    Construct an authenticated requests.Session for the given auth config.

    Returns (session, info_message) where info_message describes what was
    configured — suitable for display to the operator.
    """
    sess = _make_session(verify_ssl, proxy)
    method = (auth.get("method") or auth.get("auth_type") or "bearer").strip().lower()

    # ── Bearer ────────────────────────────────────────────────────────────────
    if method == "bearer":
        token = auth.get("auth_token", "").strip()
        if not token:
            return sess, "WARNING: no token provided"
        tt = auth.get("token_type", "Bearer")
        sess.headers["Authorization"] = f"{tt} {token}"
        return sess, f"Authorization: {tt} ***"

    # ── HTTP Basic ────────────────────────────────────────────────────────────
    elif method == "basic":
        user = auth.get("username", "")
        pw   = auth.get("password", "")
        if not user:
            return sess, "WARNING: no username provided"
        sess.auth = (user, pw)
        return sess, f"HTTP Basic: user={user}"

    # ── HTTP Digest ───────────────────────────────────────────────────────────
    elif method == "digest":
        from requests.auth import HTTPDigestAuth
        user = auth.get("username", "")
        pw   = auth.get("password", "")
        if not user:
            return sess, "WARNING: no username provided"
        sess.auth = HTTPDigestAuth(user, pw)
        return sess, f"HTTP Digest: user={user}"

    # ── API Key ───────────────────────────────────────────────────────────────
    elif method == "apikey":
        key    = auth.get("api_key", "").strip()
        header = auth.get("api_key_header", "X-API-Key")
        qparam = auth.get("api_key_query", "")
        if not key:
            return sess, "WARNING: no API key provided"
        info_parts = []
        if header:
            sess.headers[header] = key
            info_parts.append(f"{header}: ***")
        if qparam:
            sess.params = {qparam: key}  # type: ignore[assignment]
            info_parts.append(f"?{qparam}=***")
        return sess, "API Key set — " + ", ".join(info_parts)

    # ── Cookie Login ──────────────────────────────────────────────────────────
    elif method == "cookie_login":
        login_url = auth.get("login_url", "")
        if not login_url:
            return sess, "ERROR: login_url is required for cookie_login"
        resp = _login_post(sess, auth, timeout)
        if resp is None:
            return sess, f"ERROR: POST to {login_url} failed (network/timeout)"
        n = len(sess.cookies)
        return sess, (
            f"POST {login_url} → HTTP {resp.status_code}, "
            f"{n} cookie(s) stored in session"
        )

    # ── Token Login ───────────────────────────────────────────────────────────
    elif method in ("token_login", "form"):
        login_url = auth.get("login_url", "")
        if not login_url:
            return sess, "ERROR: login_url is required for token_login"
        resp = _login_post(sess, auth, timeout)
        if resp is None:
            return sess, f"ERROR: POST to {login_url} failed (network/timeout)"
        try:
            body = resp.json()
        except Exception:
            return sess, f"POST {login_url} → HTTP {resp.status_code} (non-JSON response)"
        # Traverse dot-path (e.g. "data.access_token")
        token_path = auth.get("login_token_path", "token")
        token: object = body
        for part in token_path.split("."):
            token = token.get(part) if isinstance(token, dict) else None
        if not token or not isinstance(token, str):
            # Fallback: look for common key names
            for k in ("token", "access_token", "jwt", "id_token", "auth_token"):
                if k in body:
                    token = body[k]
                    break
        if token and isinstance(token, str):
            tt = auth.get("token_type", "Bearer")
            sess.headers["Authorization"] = f"{tt} {token}"
            return sess, (
                f"POST {login_url} → HTTP {resp.status_code}; "
                f"token extracted via path='{token_path}'"
            )
        return sess, (
            f"POST {login_url} → HTTP {resp.status_code}; "
            f"WARNING: no token found at path='{token_path}'"
        )

    # ── OAuth2 Client Credentials ─────────────────────────────────────────────
    elif method == "oauth2_client_creds":
        token_url     = auth.get("oauth_token_url", "")
        client_id     = auth.get("oauth_client_id", "")
        client_secret = auth.get("oauth_client_secret", "")
        scope         = auth.get("oauth_scope", "")
        if not token_url:
            return sess, "ERROR: oauth_token_url is required"
        if not client_id:
            return sess, "ERROR: oauth_client_id is required"
        data: dict = {
            "grant_type":    "client_credentials",
            "client_id":     client_id,
            "client_secret": client_secret,
        }
        if scope:
            data["scope"] = scope
        try:
            resp = sess.post(token_url, data=data, timeout=timeout)
            body = resp.json()
            token = body.get("access_token", "")
            if token:
                tt = body.get("token_type", "Bearer")
                sess.headers["Authorization"] = f"{tt} {token}"
                return sess, f"OAuth2 token obtained from {token_url} → HTTP {resp.status_code}"
            return sess, (
                f"OAuth2 POST {token_url} → HTTP {resp.status_code}; "
                "WARNING: no access_token in response"
            )
        except Exception as exc:
            return sess, f"ERROR: OAuth2 token request failed: {exc}"

    # ── Custom Headers ────────────────────────────────────────────────────────
    elif method == "header_creds":
        hdrs = auth.get("custom_headers", {})
        if not isinstance(hdrs, dict) or not hdrs:
            return sess, "WARNING: no custom_headers provided"
        sess.headers.update(hdrs)
        names = list(hdrs.keys())
        return sess, f"Set {len(names)} header(s): {', '.join(names)}"

    # ── NTLM ──────────────────────────────────────────────────────────────────
    elif method == "ntlm":
        user   = auth.get("username", "")
        pw     = auth.get("password", "")
        domain = auth.get("domain", "")
        if not user:
            return sess, "ERROR: username is required for NTLM"
        try:
            from requests_ntlm import HttpNtlmAuth  # type: ignore[import]
        except ImportError:
            return sess, "ERROR: NTLM requires 'pip install requests-ntlm'"
        ntlm_user = f"{domain}\\{user}" if domain else user
        sess.auth = HttpNtlmAuth(ntlm_user, pw)
        return sess, f"NTLM: {ntlm_user}"

    return sess, f"WARNING: unknown auth method '{method}'"


# ─────────────────────────────────────────────────────────────────────────────
# Connection test
# ─────────────────────────────────────────────────────────────────────────────

def test_connection(
    url: str,
    auth: dict,
    timeout: int = 10,
    proxy: str = "",
    verify_ssl: bool = False,
) -> dict:
    """
    Authenticate and probe the API base URL.

    Returns::

        {
          "success":     bool,
          "message":     str,   # human-readable outcome
          "status_code": int | None,
          "auth_info":   str,   # what auth was configured
        }
    """
    sess, auth_info = build_auth_session(auth, timeout, proxy, verify_ssl)

    last_exc: str = ""
    for method in ("GET", "HEAD"):
        try:
            resp = sess.request(method, url, timeout=timeout)
            sc = resp.status_code
            if sc == 401:
                msg = "Authentication failed — HTTP 401 Unauthorized (credentials rejected)"
                return {"success": False, "message": msg, "status_code": sc, "auth_info": auth_info}
            if sc == 403:
                msg = "HTTP 403 Forbidden — credentials accepted but access denied"
                return {"success": False, "message": msg, "status_code": sc, "auth_info": auth_info}
            msg = f"Connection successful — HTTP {sc}"
            return {"success": True, "message": msg, "status_code": sc, "auth_info": auth_info}
        except requests.exceptions.SSLError as exc:
            return {
                "success": False,
                "message": f"SSL error: {exc} — try enabling 'verify_ssl: false'",
                "status_code": None,
                "auth_info": auth_info,
            }
        except requests.exceptions.ConnectionError as exc:
            return {
                "success": False,
                "message": f"Connection error: {exc}",
                "status_code": None,
                "auth_info": auth_info,
            }
        except requests.exceptions.Timeout:
            return {
                "success": False,
                "message": f"Request timed out after {timeout}s",
                "status_code": None,
                "auth_info": auth_info,
            }
        except Exception as exc:
            last_exc = str(exc)

    return {
        "success": False,
        "message": f"Request failed: {last_exc}",
        "status_code": None,
        "auth_info": auth_info,
    }


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        prog="testConnection",
        description=f"Siphon v{VERSION} — API Authentication Connection Test",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="\n".join(f"  {k:<25} {v}" for k, v in AUTH_METHODS.items()),
    )
    ap.add_argument("--settings",     metavar="FILE",
                    help="Siphon settings JSON file (reads scan.auth + scan.api_base_url)")
    ap.add_argument("--json",         metavar="JSON",
                    help='Inline config: \'{"url":"...","auth":{...}}\'')
    ap.add_argument("--url",          metavar="URL",   help="API base URL to test")
    ap.add_argument("--auth-method",  metavar="METHOD",
                    choices=list(AUTH_METHODS.keys()), help="Auth method")
    ap.add_argument("--token",        metavar="TOKEN", help="Bearer token")
    ap.add_argument("--token-type",   metavar="TYPE",  default="Bearer",
                    help="Token type prefix (default: Bearer)")
    ap.add_argument("--username",     metavar="USER",  help="Username")
    ap.add_argument("--password",     metavar="PASS",  help="Password")
    ap.add_argument("--domain",       metavar="DOMAIN", help="Domain (NTLM)")
    ap.add_argument("--api-key",      metavar="KEY",   help="API key value")
    ap.add_argument("--api-key-header", metavar="HDR", default="X-API-Key",
                    help="API key header name (default: X-API-Key)")
    ap.add_argument("--login-url",    metavar="URL",   help="Login endpoint URL")
    ap.add_argument("--login-data",   metavar="JSON",  help='Login POST body, e.g. \'{"username":"u","password":"p"}\'')
    ap.add_argument("--login-content-type", metavar="CT", default="application/json",
                    help="Content-Type for login POST (default: application/json)")
    ap.add_argument("--token-path",   metavar="PATH",  default="token",
                    help="Dot-path to token in login JSON response (default: token)")
    ap.add_argument("--oauth-token-url",    metavar="URL")
    ap.add_argument("--oauth-client-id",    metavar="ID")
    ap.add_argument("--oauth-client-secret",metavar="SECRET")
    ap.add_argument("--oauth-scope",        metavar="SCOPE")
    ap.add_argument("--timeout",      type=int, default=10,
                    help="Request timeout in seconds (default: 10)")
    ap.add_argument("--proxy",        metavar="URL",   default="", help="HTTP proxy URL")
    ap.add_argument("--no-verify",    action="store_true",
                    help="Skip TLS certificate verification (insecure)")
    ap.add_argument("--output-json",  action="store_true",
                    help="Print result as JSON (for programmatic use by Crucible)")
    ap.add_argument("--list-methods", action="store_true",
                    help="List supported auth methods and exit")
    args = ap.parse_args()

    if args.list_methods:
        print(f"\nSiphon testConnection v{VERSION} — supported auth methods:\n")
        for k, v in AUTH_METHODS.items():
            print(f"  {k:<25} {v}")
        print()
        sys.exit(0)

    # ── Build config ────────────────────────────────────────────────────────
    url        = ""
    auth: dict = {}
    timeout    = args.timeout
    proxy      = args.proxy
    verify_ssl = not args.no_verify

    if args.settings:
        try:
            cfg = json.loads(open(args.settings).read())
            scan = cfg.get("scan", {})
            url        = scan.get("api_base_url", "")
            auth       = dict(scan.get("auth", {}))
            timeout    = scan.get("timeout", timeout)
            proxy      = scan.get("proxy", proxy)
            verify_ssl = scan.get("verify_ssl", verify_ssl)
        except Exception as exc:
            print(f"ERROR: could not read settings file: {exc}", file=sys.stderr)
            sys.exit(1)

    if args.json:
        try:
            j = json.loads(args.json)
            if "url"        in j: url        = j["url"]
            if "auth"       in j: auth        = j["auth"]
            if "timeout"    in j: timeout     = int(j["timeout"])
            if "proxy"      in j: proxy       = j["proxy"]
            if "verify_ssl" in j: verify_ssl  = bool(j["verify_ssl"])
        except Exception as exc:
            print(f"ERROR: could not parse --json: {exc}", file=sys.stderr)
            sys.exit(1)

    # CLI flags override settings/json
    if args.url:            url = args.url
    if args.auth_method:    auth["method"]               = args.auth_method
    if args.token:          auth["auth_token"]            = args.token
    if args.token_type:     auth["token_type"]            = args.token_type
    if args.username:       auth["username"]              = args.username
    if args.password:       auth["password"]              = args.password
    if args.domain:         auth["domain"]                = args.domain
    if args.api_key:        auth["api_key"]               = args.api_key
    if args.api_key_header: auth["api_key_header"]        = args.api_key_header
    if args.login_url:      auth["login_url"]             = args.login_url
    if args.login_data:     auth["login_data"]            = args.login_data
    if args.login_content_type: auth["login_content_type"] = args.login_content_type
    if args.token_path:     auth["login_token_path"]      = args.token_path
    if args.oauth_token_url:    auth["oauth_token_url"]   = args.oauth_token_url
    if args.oauth_client_id:    auth["oauth_client_id"]   = args.oauth_client_id
    if args.oauth_client_secret: auth["oauth_client_secret"] = args.oauth_client_secret
    if args.oauth_scope:    auth["oauth_scope"]           = args.oauth_scope
    if args.no_verify:      verify_ssl = False

    if not url:
        print("ERROR: no URL specified. Use --url, --settings FILE, or --json '{...}'.",
              file=sys.stderr)
        sys.exit(1)

    if not auth.get("method"):
        auth["method"] = "bearer"

    # ── Run test ────────────────────────────────────────────────────────────
    result = test_connection(url, auth, timeout, proxy, verify_ssl)

    if args.output_json:
        print(json.dumps(result))
        sys.exit(0 if result["success"] else 1)

    method_label = AUTH_METHODS.get(auth.get("method", ""), auth.get("method", ""))
    ok = result["success"]
    icon = "\u2713" if ok else "\u2717"

    print(f"\nSiphon testConnection v{VERSION}")
    print(f"  URL        : {url}")
    print(f"  Method     : {method_label}")
    print(f"  Auth setup : {result['auth_info']}")
    print(f"  Result     : {icon} {result['message']}")
    if result.get("status_code"):
        print(f"  HTTP       : {result['status_code']}")
    print()
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
