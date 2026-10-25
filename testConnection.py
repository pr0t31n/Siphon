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
      --auth-method bearer \\
      --token eyJhbGciOiJSUzI1NiJ9...

  # Probe URL to auto-detect auth method
  python3 testConnection.py --url https://api.example.com --probe

  # List supported auth methods
  python3 testConnection.py --list-methods
"""

import argparse
import base64
import hashlib
import hmac
import json
import sys
import time
import urllib.parse
from datetime import datetime, timezone

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VERSION = "2.0.1"

AUTH_METHODS: dict[str, str] = {
    # ── Token-based ───────────────────────────────────────────────────────────
    "bearer":              "Bearer Token (Authorization: Bearer <token>)",
    "jwt_bearer":          "JWT Bearer — verify/decode JWT, set as Bearer token",
    # ── Credential-based ──────────────────────────────────────────────────────
    "basic":               "HTTP Basic Auth (username / password)",
    "digest":              "HTTP Digest Auth (username / password)",
    # ── Windows / Active Directory ────────────────────────────────────────────
    "ntlm":                "NTLM / Windows Authentication (Active Directory)",
    "ntlm_v2":             "NTLMv2 — extended NTLM with domain negotiation",
    "kerberos":            "Kerberos (GSSAPI / Negotiate) — Kerberos ticket auth",
    "kerberos_delegation": "Kerberos with Constrained Delegation (S4U2Proxy)",
    # ── OAuth / OIDC ──────────────────────────────────────────────────────────
    "oauth2_client_creds": "OAuth2 Client Credentials (machine-to-machine, RFC 6749 §4.4)",
    "oauth2_password":     "OAuth2 Resource Owner Password Credentials (RFC 6749 §4.3)",
    "oauth1a":             "OAuth 1.0a — HMAC-SHA1 signed requests",
    "oidc_token":          "OIDC ID Token — present id_token as Bearer",
    # ── SAML ──────────────────────────────────────────────────────────────────
    "saml_assertion":      "SAML Assertion — POST assertion to token endpoint",
    # ── mTLS ──────────────────────────────────────────────────────────────────
    "mtls":                "Mutual TLS — client certificate + private key",
    # ── MFA ───────────────────────────────────────────────────────────────────
    "totp_mfa":            "TOTP MFA — time-based OTP injected into login flow",
    # ── API Key ───────────────────────────────────────────────────────────────
    "apikey":              "API Key header (X-API-Key or custom header / query param)",
    "apikey_cookie":       "API Key via cookie",
    # ── Session / Cookie ──────────────────────────────────────────────────────
    "cookie_login":        "Cookie Login — POST credentials, use response cookies",
    "session_cookie":      "Session Cookie — CSRF prefetch + form POST, use cookies",
    # ── Token Login ───────────────────────────────────────────────────────────
    "token_login":         "Token Login — POST credentials, extract token from JSON response",
    # ── Signature-based ───────────────────────────────────────────────────────
    "hmac_signature":      "HMAC Signature — sign requests with shared secret",
    "aws_sigv4":           "AWS Signature Version 4 — AWS SigV4 signed requests",
    # ── Custom ────────────────────────────────────────────────────────────────
    "header_creds":        "Custom Headers — static key-value credential headers",
    # ── Fingerprint (cross-tool) ──────────────────────────────────────────────
    "fingerprint":         "Fingerprint — replays auth recipe from auth_fingerprint.json (forwarded from Fracture)",
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


def _csrf_prefetch(
    sess: requests.Session,
    login_url: str,
    csrf_field: str,
    csrf_header: str,
    timeout: int,
) -> tuple[str, str]:
    """
    GET the login page and extract a CSRF token.
    Returns (token_value, post_url) — empty strings on failure.
    """
    try:
        resp = sess.get(login_url, timeout=timeout)
        body = resp.text
        # 1. Look for the CSRF field in the response body
        if csrf_field:
            import re
            pat = re.compile(
                rf'<input[^>]+name=["\']?{re.escape(csrf_field)}["\']?[^>]+value=["\']([^"\']+)["\']',
                re.IGNORECASE,
            )
            m = pat.search(body)
            if not m:
                pat2 = re.compile(
                    rf'<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\']?{re.escape(csrf_field)}["\']?',
                    re.IGNORECASE,
                )
                m = pat2.search(body)
            if m:
                return m.group(1), resp.url
        # 2. Check response header
        if csrf_header:
            hval = resp.headers.get(csrf_header, "")
            if hval:
                return hval, resp.url
        # 3. Check cookies
        for ck in sess.cookies:
            if "csrf" in ck.name.lower() or "xsrf" in ck.name.lower():
                return ck.value, resp.url
    except Exception:
        pass
    return "", login_url


def _login_post(
    sess: requests.Session,
    auth: dict,
    timeout: int,
) -> tuple["requests.Response | None", str]:
    """
    POST to login_url, building the body according to login_mode.
    Returns (response, post_url). Performs CSRF prefetch when configured.
    """
    url = auth.get("login_url", "")
    if not url:
        return None, url

    # CSRF prefetch
    csrf_field  = auth.get("csrf_field", "")
    csrf_header = auth.get("csrf_header", "")
    post_url    = url
    csrf_token  = ""
    if csrf_field or csrf_header:
        csrf_token, post_url = _csrf_prefetch(sess, url, csrf_field, csrf_header, timeout)
    if not post_url:
        post_url = url

    login_mode = auth.get("login_mode", "merge")
    uf = auth.get("login_username_field", "username")
    pf = auth.get("login_password_field", "password")
    u  = auth.get("username", "")
    p  = auth.get("password", "")

    if login_mode == "fields":
        data: dict = {}
        if u:           data[uf] = u
        if p:           data[pf] = p
        if csrf_token and csrf_field:
            data[csrf_field] = csrf_token
    elif login_mode == "json":
        raw = auth.get("login_data", "{}")
        try:
            data = json.loads(raw) if isinstance(raw, str) else dict(raw)
        except Exception:
            data = {}
    else:
        raw = auth.get("login_data", "{}")
        try:
            data = json.loads(raw) if isinstance(raw, str) else dict(raw)
        except Exception:
            data = {}
        if u and uf not in data:
            data[uf] = u
        if p and pf not in data:
            data[pf] = p
        if csrf_token and csrf_field and csrf_field not in data:
            data[csrf_field] = csrf_token

    ct = auth.get("login_content_type", "application/json")
    try:
        if csrf_header and csrf_token:
            sess.headers[csrf_header] = csrf_token
        if "json" in ct:
            return sess.post(post_url, json=data, timeout=timeout), post_url
        return sess.post(post_url, data=data, timeout=timeout), post_url
    except Exception:
        return None, post_url


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
    method = (auth.get("method") or auth.get("auth_method") or auth.get("auth_type") or "bearer").strip().lower()

    # ── Bearer ────────────────────────────────────────────────────────────────
    if method == "bearer":
        token = auth.get("auth_token", "").strip()
        if not token:
            return sess, "WARNING: no token provided"
        tt = auth.get("token_type", "Bearer")
        sess.headers["Authorization"] = f"{tt} {token}"
        return sess, f"Authorization: {tt} ***"

    # ── JWT Bearer ────────────────────────────────────────────────────────────
    elif method == "jwt_bearer":
        token = auth.get("auth_token", "").strip()
        if not token:
            return sess, "WARNING: no JWT token provided"
        # Decode header/payload for display (no verification)
        try:
            parts = token.split(".")
            if len(parts) >= 2:
                pad = lambda s: s + "=" * (-len(s) % 4)
                payload = json.loads(base64.urlsafe_b64decode(pad(parts[1])).decode())
                sub  = payload.get("sub", "")
                exp  = payload.get("exp", 0)
                info = f"sub={sub}" if sub else "no sub claim"
                if exp:
                    info += f", exp={datetime.fromtimestamp(exp, tz=timezone.utc).isoformat()}"
            else:
                info = "malformed JWT"
        except Exception:
            info = "could not decode"
        sess.headers["Authorization"] = f"Bearer {token}"
        return sess, f"JWT Bearer ({info})"

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

    # ── NTLMv2 ────────────────────────────────────────────────────────────────
    elif method == "ntlm_v2":
        user   = auth.get("username", "")
        pw     = auth.get("password", "")
        domain = auth.get("domain", "")
        if not user:
            return sess, "ERROR: username is required for NTLMv2"
        try:
            from requests_ntlm import HttpNtlmAuth  # type: ignore[import]
        except ImportError:
            return sess, "ERROR: NTLMv2 requires 'pip install requests-ntlm'"
        ntlm_user = f"{domain}\\{user}" if domain else user
        sess.auth = HttpNtlmAuth(ntlm_user, pw, send_cbt=True)
        return sess, f"NTLMv2: {ntlm_user} (CBT enabled)"

    # ── Kerberos ──────────────────────────────────────────────────────────────
    elif method == "kerberos":
        try:
            from requests_kerberos import HTTPKerberosAuth, REQUIRED  # type: ignore[import]
        except ImportError:
            return sess, "ERROR: Kerberos requires 'pip install requests-kerberos'"
        principal = auth.get("kerberos_principal", "")
        mutual    = auth.get("kerberos_mutual_auth", True)
        ma        = REQUIRED if mutual else 1
        sess.auth  = HTTPKerberosAuth(mutual_authentication=ma, principal=principal or None)
        label = f"principal={principal}" if principal else "default principal"
        return sess, f"Kerberos (Negotiate): {label}"

    # ── Kerberos Delegation ───────────────────────────────────────────────────
    elif method == "kerberos_delegation":
        try:
            from requests_kerberos import HTTPKerberosAuth, REQUIRED  # type: ignore[import]
        except ImportError:
            return sess, "ERROR: Kerberos requires 'pip install requests-kerberos'"
        principal = auth.get("kerberos_principal", "")
        sess.auth  = HTTPKerberosAuth(
            mutual_authentication=REQUIRED,
            delegate=True,
            principal=principal or None,
        )
        label = f"principal={principal}" if principal else "default principal"
        return sess, f"Kerberos Delegation: {label}"

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
                return sess, f"OAuth2 CC token from {token_url} → HTTP {resp.status_code}"
            return sess, (
                f"OAuth2 POST {token_url} → HTTP {resp.status_code}; "
                "WARNING: no access_token in response"
            )
        except Exception as exc:
            return sess, f"ERROR: OAuth2 CC token request failed: {exc}"

    # ── OAuth2 Password ───────────────────────────────────────────────────────
    elif method == "oauth2_password":
        token_url     = auth.get("oauth_token_url", "")
        client_id     = auth.get("oauth_client_id", "")
        client_secret = auth.get("oauth_client_secret", "")
        scope         = auth.get("oauth_scope", "")
        user          = auth.get("username", "")
        pw            = auth.get("password", "")
        if not token_url:
            return sess, "ERROR: oauth_token_url is required"
        if not user:
            return sess, "ERROR: username is required for OAuth2 Password flow"
        data = {
            "grant_type": "password",
            "username":   user,
            "password":   pw,
        }
        if client_id:     data["client_id"]     = client_id
        if client_secret: data["client_secret"] = client_secret
        if scope:         data["scope"]         = scope
        try:
            resp = sess.post(token_url, data=data, timeout=timeout)
            body = resp.json()
            token = body.get("access_token", "")
            if token:
                tt = body.get("token_type", "Bearer")
                sess.headers["Authorization"] = f"{tt} {token}"
                return sess, f"OAuth2 Password token from {token_url} → HTTP {resp.status_code}; user={user}"
            return sess, (
                f"OAuth2 Password POST {token_url} → HTTP {resp.status_code}; "
                "WARNING: no access_token in response"
            )
        except Exception as exc:
            return sess, f"ERROR: OAuth2 Password token request failed: {exc}"

    # ── OAuth 1.0a ────────────────────────────────────────────────────────────
    elif method == "oauth1a":
        try:
            from requests_oauthlib import OAuth1  # type: ignore[import]
        except ImportError:
            return sess, "ERROR: OAuth1a requires 'pip install requests-oauthlib'"
        consumer_key    = auth.get("oauth1_consumer_key", "")
        consumer_secret = auth.get("oauth1_consumer_secret", "")
        token           = auth.get("oauth1_token", "")
        token_secret    = auth.get("oauth1_token_secret", "")
        if not consumer_key:
            return sess, "ERROR: oauth1_consumer_key is required"
        sess.auth = OAuth1(
            consumer_key, consumer_secret,
            token or None, token_secret or None,
            signature_method="HMAC-SHA1",
        )
        return sess, f"OAuth1a HMAC-SHA1: consumer_key={consumer_key}"

    # ── OIDC Token ────────────────────────────────────────────────────────────
    elif method == "oidc_token":
        id_token = auth.get("oidc_id_token", "").strip()
        if not id_token:
            # Try to obtain via client creds + OIDC
            token_url     = auth.get("oauth_token_url", "")
            client_id     = auth.get("oauth_client_id", "")
            client_secret = auth.get("oauth_client_secret", "")
            scope         = auth.get("oauth_scope", "openid")
            if not token_url or not client_id:
                return sess, "ERROR: oidc_id_token (or oauth_token_url + oauth_client_id) is required"
            data = {
                "grant_type":    "client_credentials",
                "client_id":     client_id,
                "client_secret": client_secret,
                "scope":         scope,
            }
            try:
                resp = sess.post(token_url, data=data, timeout=timeout)
                body = resp.json()
                id_token = body.get("id_token", body.get("access_token", ""))
                if not id_token:
                    return sess, (
                        f"ERROR: OIDC POST {token_url} → HTTP {resp.status_code}; "
                        "no id_token or access_token in response"
                    )
            except Exception as exc:
                return sess, f"ERROR: OIDC token request failed: {exc}"
        sess.headers["Authorization"] = f"Bearer {id_token}"
        return sess, "OIDC id_token set as Bearer"

    # ── SAML Assertion ────────────────────────────────────────────────────────
    elif method == "saml_assertion":
        assertion = auth.get("saml_assertion", "").strip()
        token_url = auth.get("saml_token_url", "").strip()
        if not assertion:
            return sess, "ERROR: saml_assertion is required"
        if token_url:
            # Exchange SAML assertion for bearer token
            data = {
                "grant_type": "urn:ietf:params:oauth:grant-type:saml2-bearer",
                "assertion":  base64.b64encode(assertion.encode()).decode(),
            }
            client_id = auth.get("oauth_client_id", "")
            if client_id:
                data["client_id"] = client_id
            try:
                resp = sess.post(token_url, data=data, timeout=timeout)
                body = resp.json()
                token = body.get("access_token", "")
                if token:
                    sess.headers["Authorization"] = f"Bearer {token}"
                    return sess, f"SAML→Bearer token from {token_url} → HTTP {resp.status_code}"
                return sess, (
                    f"SAML exchange POST {token_url} → HTTP {resp.status_code}; "
                    "WARNING: no access_token in response"
                )
            except Exception as exc:
                return sess, f"ERROR: SAML assertion exchange failed: {exc}"
        # Direct assertion header
        hdr = auth.get("saml_assertion_header", "Authorization")
        sess.headers[hdr] = f"SAML {assertion[:40]}..."
        return sess, f"SAML assertion set in header '{hdr}'"

    # ── Mutual TLS ────────────────────────────────────────────────────────────
    elif method == "mtls":
        cert_file = auth.get("mtls_cert", "")
        key_file  = auth.get("mtls_key", "")
        if not cert_file:
            return sess, "ERROR: mtls_cert (path to PEM certificate) is required"
        if not key_file:
            return sess, "ERROR: mtls_key (path to PEM private key) is required"
        # Set client certificate on the session
        sess.cert = (cert_file, key_file)
        ca_bundle = auth.get("mtls_ca_bundle", "")
        if ca_bundle:
            sess.verify = ca_bundle
        return sess, f"mTLS: cert={cert_file}"

    # ── TOTP MFA ──────────────────────────────────────────────────────────────
    elif method == "totp_mfa":
        login_url  = auth.get("login_url", "")
        totp_secret = auth.get("totp_secret", "").strip().replace(" ", "").upper()
        if not login_url:
            return sess, "ERROR: login_url is required for totp_mfa"
        if not totp_secret:
            return sess, "ERROR: totp_secret (base32 TOTP secret) is required"
        try:
            import struct
            key  = base64.b32decode(totp_secret)
            step = int(time.time()) // 30
            msg  = struct.pack(">Q", step)
            h    = hmac.new(key, msg, hashlib.sha1).digest()
            off  = h[-1] & 0x0F
            code = str((struct.unpack(">I", h[off:off+4])[0] & 0x7FFFFFFF) % 1_000_000).zfill(6)
        except Exception as exc:
            return sess, f"ERROR: TOTP generation failed: {exc}"

        # Build login payload with OTP injected
        totp_field = auth.get("totp_field", "otp")
        uf = auth.get("login_username_field", "username")
        pf = auth.get("login_password_field", "password")
        u  = auth.get("username", "")
        p  = auth.get("password", "")
        data = {}
        if u: data[uf] = u
        if p: data[pf] = p
        data[totp_field] = code

        ct = auth.get("login_content_type", "application/json")
        try:
            if "json" in ct:
                resp = sess.post(login_url, json=data, timeout=timeout)
            else:
                resp = sess.post(login_url, data=data, timeout=timeout)
        except Exception as exc:
            return sess, f"ERROR: TOTP login POST failed: {exc}"

        if not resp.ok:
            return sess, (
                f"ERROR: TOTP login POST {login_url} → HTTP {resp.status_code} — "
                "login rejected (check credentials / TOTP secret)"
            )
        # Try to extract bearer token
        try:
            body = resp.json()
            token = (
                body.get("access_token") or body.get("token") or
                body.get("jwt") or body.get("id_token") or ""
            )
            if token:
                tt = auth.get("token_type", "Bearer")
                sess.headers["Authorization"] = f"{tt} {token}"
                return sess, (
                    f"TOTP MFA login {login_url} → HTTP {resp.status_code}; "
                    f"token extracted; OTP={code}"
                )
        except Exception:
            pass
        n = len(sess.cookies)
        return sess, (
            f"TOTP MFA login {login_url} → HTTP {resp.status_code}; "
            f"{n} cookie(s) stored; OTP={code}"
        )

    # ── API Key (header / query) ───────────────────────────────────────────────
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

    # ── API Key Cookie ────────────────────────────────────────────────────────
    elif method == "apikey_cookie":
        key         = auth.get("api_key", "").strip()
        cookie_name = auth.get("api_key_cookie_name", "api_key")
        domain      = auth.get("api_key_cookie_domain", "")
        if not key:
            return sess, "WARNING: no API key provided for apikey_cookie"
        sess.cookies.set(cookie_name, key, domain=domain or None)
        return sess, f"API Key cookie '{cookie_name}' set"

    # ── Cookie Login ──────────────────────────────────────────────────────────
    elif method == "cookie_login":
        login_url = auth.get("login_url", "")
        if not login_url:
            return sess, "ERROR: login_url is required for cookie_login"
        resp, post_url = _login_post(sess, auth, timeout)
        if resp is None:
            return sess, f"ERROR: POST to {login_url} failed (network/timeout)"
        if not resp.ok:
            return sess, (
                f"ERROR: POST {post_url} → HTTP {resp.status_code} — "
                "login rejected (check credentials and login URL)"
            )
        n = len(sess.cookies)
        if n == 0:
            return sess, (
                f"WARNING: POST {post_url} → HTTP {resp.status_code} — "
                "login accepted but no session cookies returned"
            )
        return sess, (
            f"POST {post_url} → HTTP {resp.status_code}, "
            f"{n} cookie(s) stored"
        )

    # ── Session Cookie (with CSRF prefetch) ───────────────────────────────────
    elif method == "session_cookie":
        login_url = auth.get("login_url", "")
        if not login_url:
            return sess, "ERROR: login_url is required for session_cookie"
        # Force form content type for session_cookie (CSRF is typically form-based)
        auth_copy = dict(auth)
        if not auth_copy.get("login_content_type"):
            auth_copy["login_content_type"] = "application/x-www-form-urlencoded"
        resp, post_url = _login_post(sess, auth_copy, timeout)
        if resp is None:
            return sess, f"ERROR: session POST to {login_url} failed (network/timeout)"
        if not resp.ok:
            return sess, (
                f"ERROR: POST {post_url} → HTTP {resp.status_code} — "
                "session login rejected"
            )
        n = len(sess.cookies)
        return sess, (
            f"Session login {post_url} → HTTP {resp.status_code}; "
            f"{n} cookie(s) stored"
        )

    # ── Token Login ───────────────────────────────────────────────────────────
    elif method in ("token_login", "form"):
        login_url = auth.get("login_url", "")
        if not login_url:
            return sess, "ERROR: login_url is required for token_login"
        resp, post_url = _login_post(sess, auth, timeout)
        if resp is None:
            return sess, f"ERROR: POST to {login_url} failed (network/timeout)"
        if not resp.ok:
            return sess, (
                f"ERROR: POST {post_url} → HTTP {resp.status_code} — "
                "login rejected (check credentials and login URL)"
            )
        try:
            body = resp.json()
        except Exception:
            return sess, (
                f"ERROR: POST {post_url} → HTTP {resp.status_code} — "
                "response is not JSON; cannot extract token"
            )
        token_path = auth.get("login_token_path", "token")
        token: object = body
        for part in token_path.split("."):
            token = token.get(part) if isinstance(token, dict) else None
        if not token or not isinstance(token, str):
            for k in ("token", "access_token", "jwt", "id_token", "auth_token"):
                if k in body:
                    token = body[k]
                    break
        if token and isinstance(token, str):
            tt = auth.get("token_type", "Bearer")
            sess.headers["Authorization"] = f"{tt} {token}"
            return sess, (
                f"POST {post_url} → HTTP {resp.status_code}; "
                f"token extracted via path='{token_path}'"
            )
        return sess, (
            f"ERROR: POST {post_url} → HTTP {resp.status_code}; "
            f"no token found at path='{token_path}' — "
            "check Token Path in Response"
        )

    # ── HMAC Signature ────────────────────────────────────────────────────────
    elif method == "hmac_signature":
        key_id  = auth.get("hmac_key_id", "").strip()
        secret  = auth.get("hmac_secret", "").strip()
        algo    = auth.get("hmac_algorithm", "sha256").lower()
        hdr_fmt = auth.get("hmac_header", "Authorization")
        if not secret:
            return sess, "ERROR: hmac_secret is required"
        # Store params for per-request signing; attach a custom auth object
        class _HmacAuth(requests.auth.AuthBase):  # type: ignore[misc]
            def __init__(self, _key_id, _secret, _algo, _hdr):
                self._key_id = _key_id
                self._secret = _secret.encode() if isinstance(_secret, str) else _secret
                self._algo   = _algo
                self._hdr    = _hdr

            def __call__(self, r):
                ts      = str(int(time.time()))
                method  = r.method.upper()
                path    = urllib.parse.urlparse(r.url).path or "/"
                body    = (r.body or b"")
                if isinstance(body, str):
                    body = body.encode()
                msg  = f"{method}\n{path}\n{ts}".encode() + b"\n" + body
                h    = getattr(hashlib, self._algo, hashlib.sha256)
                sig  = hmac.new(self._secret, msg, h).hexdigest()
                val  = f'key="{self._key_id}",ts="{ts}",sig="{sig}"' if self._key_id else f'ts="{ts}",sig="{sig}"'
                r.headers[self._hdr] = f"HMAC {val}"
                return r

        sess.auth = _HmacAuth(key_id, secret, algo, hdr_fmt)
        label = f"key_id={key_id}, algo={algo}" if key_id else f"algo={algo}"
        return sess, f"HMAC Signature: {label}"

    # ── AWS SigV4 ─────────────────────────────────────────────────────────────
    elif method == "aws_sigv4":
        access_key = auth.get("aws_access_key_id", "").strip()
        secret_key = auth.get("aws_secret_access_key", "").strip()
        region     = auth.get("aws_region", "us-east-1").strip()
        service    = auth.get("aws_service", "execute-api").strip()
        session_tk = auth.get("aws_session_token", "").strip()
        if not access_key or not secret_key:
            return sess, "ERROR: aws_access_key_id and aws_secret_access_key are required"
        try:
            from aws_requests_auth.aws_auth import AWSRequestsAuth  # type: ignore[import]
            # Determine host from URL — will be overridden per request if needed
            host_hint = auth.get("url_host", "")
            if host_hint:
                aws_auth = AWSRequestsAuth(
                    aws_access_key=access_key,
                    aws_secret_access_key=secret_key,
                    aws_host=host_hint,
                    aws_region=region,
                    aws_service=service,
                    aws_token=session_tk or None,
                )
                sess.auth = aws_auth
            else:
                # Fall back to botocore signing if available
                try:
                    import botocore.auth, botocore.credentials, botocore.awsrequest  # type: ignore[import]
                    sess.auth = None  # will sign per-request below
                    sess.headers["X-Siphon-SigV4-Pending"] = "1"
                except ImportError:
                    pass
        except ImportError:
            # Minimal SigV4 signing without external libraries
            def _sign(key, msg):
                return hmac.new(key, msg.encode(), hashlib.sha256).digest()

            def _get_signature_key(sk, date, reg, svc):
                k = _sign(("AWS4" + sk).encode(), date)
                k = _sign(k, reg)
                k = _sign(k, svc)
                k = _sign(k, "aws4_request")
                return k

            class _SigV4Auth(requests.auth.AuthBase):  # type: ignore[misc]
                def __init__(self, _ak, _sk, _reg, _svc, _stk):
                    self._ak, self._sk, self._reg, self._svc, self._stk = _ak, _sk, _reg, _svc, _stk

                def __call__(self, r):
                    t = datetime.now(tz=timezone.utc)
                    amz_date = t.strftime("%Y%m%dT%H%M%SZ")
                    date_stamp = t.strftime("%Y%m%d")
                    parsed = urllib.parse.urlparse(r.url)
                    host = parsed.netloc
                    path = parsed.path or "/"
                    body = r.body or b""
                    if isinstance(body, str): body = body.encode()
                    payload_hash = hashlib.sha256(body).hexdigest()
                    canonical_headers = f"host:{host}\nx-amz-date:{amz_date}\n"
                    signed_headers = "host;x-amz-date"
                    if self._stk:
                        canonical_headers += f"x-amz-security-token:{self._stk}\n"
                        signed_headers += ";x-amz-security-token"
                    qs = parsed.query
                    canonical_request = "\n".join([
                        r.method, path, qs,
                        canonical_headers, signed_headers, payload_hash,
                    ])
                    cred_scope = f"{date_stamp}/{self._reg}/{self._svc}/aws4_request"
                    string_to_sign = "\n".join([
                        "AWS4-HMAC-SHA256", amz_date, cred_scope,
                        hashlib.sha256(canonical_request.encode()).hexdigest(),
                    ])
                    sig_key = _get_signature_key(self._sk, date_stamp, self._reg, self._svc)
                    sig = hmac.new(sig_key, string_to_sign.encode(), hashlib.sha256).hexdigest()
                    auth_hdr = (
                        f"AWS4-HMAC-SHA256 Credential={self._ak}/{cred_scope},"
                        f"SignedHeaders={signed_headers},Signature={sig}"
                    )
                    r.headers["X-Amz-Date"] = amz_date
                    r.headers["Authorization"] = auth_hdr
                    if self._stk:
                        r.headers["X-Amz-Security-Token"] = self._stk
                    return r

            sess.auth = _SigV4Auth(access_key, secret_key, region, service, session_tk)

        return sess, f"AWS SigV4: key={access_key[:6]}…, region={region}, service={service}"

    # ── Custom Headers ────────────────────────────────────────────────────────
    elif method == "header_creds":
        hdrs = auth.get("custom_headers", {})
        if not isinstance(hdrs, dict) or not hdrs:
            return sess, "WARNING: no custom_headers provided"
        sess.headers.update(hdrs)
        names = list(hdrs.keys())
        return sess, f"Set {len(names)} header(s): {', '.join(names)}"

    # ── Fingerprint (forwarded from Fracture) ────────────────────────────────
    elif method == "fingerprint":
        from pathlib import Path as _FpPath2
        fp_file = auth.get("fingerprint_file", "")
        if not fp_file:
            return sess, "ERROR: fingerprint method requires fingerprint_file path"
        fp_p = _FpPath2(fp_file)
        if not fp_p.is_file():
            return sess, f"ERROR: fingerprint file not found: {fp_file}"
        try:
            import json as _json_fp
            fp_data = _json_fp.loads(fp_p.read_text())
        except Exception as _fe:
            return sess, f"ERROR: failed to parse fingerprint: {_fe}"
        fc = fp_data.get("fracture_auth_config", {})
        if not fc:
            return sess, "ERROR: fingerprint file has no fracture_auth_config"
        replay = dict(auth)
        for k, v in fc.items():
            if k not in ("_auth_recipe", "method"):
                replay[k] = v
        replay["method"] = fc.get("method", "form_login")
        return build_auth_session(replay, timeout, proxy, verify_ssl)

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
          "message":     str,
          "status_code": int | None,
          "auth_info":   str,
        }
    """
    sess, auth_info = build_auth_session(auth, timeout, proxy, verify_ssl)
    auth_method = (auth.get("method") or auth.get("auth_type") or "bearer").strip().lower()

    # Login-based methods: the POST outcome is authoritative
    if auth_method in (
        "cookie_login", "token_login", "form", "session_cookie",
        "oauth2_client_creds", "oauth2_password", "oidc_token",
        "saml_assertion", "totp_mfa",
    ):
        failed = auth_info.startswith("ERROR:")
        return {
            "success": not failed,
            "message": auth_info,
            "status_code": None,
            "auth_info": auth_info,
        }

    if auth_info.startswith("ERROR:"):
        return {"success": False, "message": auth_info, "status_code": None, "auth_info": auth_info}

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
# AuthProbe integration
# ─────────────────────────────────────────────────────────────────────────────

def run_probe(url: str, timeout: int, proxy: str, verify_ssl: bool) -> dict:
    """Run AuthProbe against the URL and return its result dict."""
    try:
        import sys as _sys
        import os as _os
        _ap_path = "/opt/pr0t31n/AuthProbe"
        if _ap_path not in _sys.path:
            _sys.path.insert(0, _ap_path)
        from authprobe import AuthProbe  # type: ignore[import]
        ap = AuthProbe(timeout=timeout, proxy=proxy, verify_ssl=verify_ssl)
        return ap.probe(url)
    except ImportError:
        return {"error": "AuthProbe not available at /opt/pr0t31n/AuthProbe"}
    except Exception as exc:
        return {"error": str(exc)}


def _print_probe_result(result: dict) -> None:
    print(f"\n[AuthProbe] URL type  : {result.get('url_type','?')} "
          f"(confidence {result.get('url_type_confidence',0)}%)")
    sw = result.get("software", [])
    if sw:
        for s in sw:
            print(f"[AuthProbe] Software  : {s['name']} (conf {s.get('confidence',0)}%)")
    methods = result.get("auth_methods", [])
    if methods:
        print("[AuthProbe] Auth methods detected:")
        for m in methods:
            print(f"  • {m['method']:<25} confidence={m.get('confidence',0)}% — {m.get('reason','')}")
    recs = result.get("recommendations", [])
    if recs:
        print(f"[AuthProbe] Recommendation: {recs[0]}")
    print()


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
    ap.add_argument("--probe",        action="store_true",
                    help="Run AuthProbe to auto-detect auth method for the URL")
    ap.add_argument("--auth-method",  metavar="METHOD",
                    choices=list(AUTH_METHODS.keys()), help="Auth method")
    # ── Token/Bearer ──────────────────────────────────────────────────────────
    ap.add_argument("--token",        metavar="TOKEN", help="Bearer / JWT token")
    ap.add_argument("--token-type",   metavar="TYPE",  default="Bearer",
                    help="Token type prefix (default: Bearer)")
    # ── Credentials ───────────────────────────────────────────────────────────
    ap.add_argument("--username",     metavar="USER",  help="Username")
    ap.add_argument("--password",     metavar="PASS",  help="Password")
    ap.add_argument("--domain",       metavar="DOMAIN", help="Domain (NTLM/Kerberos)")
    # ── API key ───────────────────────────────────────────────────────────────
    ap.add_argument("--api-key",      metavar="KEY",   help="API key value")
    ap.add_argument("--api-key-header", metavar="HDR", default="X-API-Key",
                    help="API key header name (default: X-API-Key)")
    ap.add_argument("--api-key-query", metavar="PARAM",
                    help="Query parameter name for API key")
    ap.add_argument("--api-key-cookie", metavar="NAME",
                    help="Cookie name for apikey_cookie method")
    # ── Login ─────────────────────────────────────────────────────────────────
    ap.add_argument("--login-url",    metavar="URL",   help="Login endpoint URL")
    ap.add_argument("--login-data",   metavar="JSON",  help='Login POST body JSON')
    ap.add_argument("--login-content-type", metavar="CT", default="application/json",
                    help="Content-Type for login POST (default: application/json)")
    ap.add_argument("--token-path",   metavar="PATH",  default="token",
                    help="Dot-path to token in login JSON response (default: token)")
    ap.add_argument("--csrf-field",   metavar="FIELD", help="CSRF hidden field name for prefetch")
    ap.add_argument("--csrf-header",  metavar="HDR",   help="CSRF response header name")
    # ── OAuth2 ────────────────────────────────────────────────────────────────
    ap.add_argument("--oauth-token-url",    metavar="URL")
    ap.add_argument("--oauth-client-id",    metavar="ID")
    ap.add_argument("--oauth-client-secret", metavar="SECRET")
    ap.add_argument("--oauth-scope",        metavar="SCOPE")
    # ── OAuth1a ───────────────────────────────────────────────────────────────
    ap.add_argument("--oauth1-consumer-key",    metavar="KEY")
    ap.add_argument("--oauth1-consumer-secret", metavar="SECRET")
    ap.add_argument("--oauth1-token",           metavar="TOKEN")
    ap.add_argument("--oauth1-token-secret",    metavar="SECRET")
    # ── OIDC ──────────────────────────────────────────────────────────────────
    ap.add_argument("--oidc-id-token", metavar="TOKEN",
                    help="OIDC id_token to use directly as Bearer")
    # ── SAML ──────────────────────────────────────────────────────────────────
    ap.add_argument("--saml-assertion",  metavar="XML")
    ap.add_argument("--saml-token-url",  metavar="URL",
                    help="Token exchange URL for SAML→Bearer")
    # ── mTLS ──────────────────────────────────────────────────────────────────
    ap.add_argument("--mtls-cert", metavar="FILE", help="mTLS client certificate PEM file")
    ap.add_argument("--mtls-key",  metavar="FILE", help="mTLS client private key PEM file")
    ap.add_argument("--mtls-ca",   metavar="FILE", help="mTLS CA bundle PEM file")
    # ── TOTP ──────────────────────────────────────────────────────────────────
    ap.add_argument("--totp-secret", metavar="SECRET",
                    help="Base32 TOTP secret for totp_mfa method")
    ap.add_argument("--totp-field",  metavar="FIELD", default="otp",
                    help="Form field name for OTP (default: otp)")
    # ── HMAC ──────────────────────────────────────────────────────────────────
    ap.add_argument("--hmac-key-id",    metavar="ID")
    ap.add_argument("--hmac-secret",    metavar="SECRET")
    ap.add_argument("--hmac-algorithm", metavar="ALGO", default="sha256")
    # ── AWS SigV4 ─────────────────────────────────────────────────────────────
    ap.add_argument("--aws-access-key",    metavar="KEY")
    ap.add_argument("--aws-secret-key",    metavar="SECRET")
    ap.add_argument("--aws-region",        metavar="REGION", default="us-east-1")
    ap.add_argument("--aws-service",       metavar="SVC",    default="execute-api")
    ap.add_argument("--aws-session-token", metavar="TOKEN")
    # ── Kerberos ──────────────────────────────────────────────────────────────
    ap.add_argument("--kerberos-principal", metavar="PRINC",
                    help="Kerberos principal (optional, uses default if omitted)")
    # ── Network ───────────────────────────────────────────────────────────────
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
    if args.url:                    url = args.url
    if args.auth_method:            auth["method"]                  = args.auth_method
    if args.token:                  auth["auth_token"]              = args.token
    if args.token_type:             auth["token_type"]              = args.token_type
    if args.username:               auth["username"]                = args.username
    if args.password:               auth["password"]                = args.password
    if args.domain:                 auth["domain"]                  = args.domain
    if args.api_key:                auth["api_key"]                 = args.api_key
    if args.api_key_header:         auth["api_key_header"]          = args.api_key_header
    if args.api_key_query:          auth["api_key_query"]           = args.api_key_query
    if args.api_key_cookie:         auth["api_key_cookie_name"]     = args.api_key_cookie
    if args.login_url:              auth["login_url"]               = args.login_url
    if args.login_data:             auth["login_data"]              = args.login_data
    if args.login_content_type:     auth["login_content_type"]      = args.login_content_type
    if args.token_path:             auth["login_token_path"]        = args.token_path
    if args.csrf_field:             auth["csrf_field"]              = args.csrf_field
    if args.csrf_header:            auth["csrf_header"]             = args.csrf_header
    if args.oauth_token_url:        auth["oauth_token_url"]         = args.oauth_token_url
    if args.oauth_client_id:        auth["oauth_client_id"]         = args.oauth_client_id
    if args.oauth_client_secret:    auth["oauth_client_secret"]     = args.oauth_client_secret
    if args.oauth_scope:            auth["oauth_scope"]             = args.oauth_scope
    if args.oauth1_consumer_key:    auth["oauth1_consumer_key"]     = args.oauth1_consumer_key
    if args.oauth1_consumer_secret: auth["oauth1_consumer_secret"]  = args.oauth1_consumer_secret
    if args.oauth1_token:           auth["oauth1_token"]            = args.oauth1_token
    if args.oauth1_token_secret:    auth["oauth1_token_secret"]     = args.oauth1_token_secret
    if args.oidc_id_token:          auth["oidc_id_token"]           = args.oidc_id_token
    if args.saml_assertion:         auth["saml_assertion"]          = args.saml_assertion
    if args.saml_token_url:         auth["saml_token_url"]          = args.saml_token_url
    if args.mtls_cert:              auth["mtls_cert"]               = args.mtls_cert
    if args.mtls_key:               auth["mtls_key"]                = args.mtls_key
    if args.mtls_ca:                auth["mtls_ca_bundle"]          = args.mtls_ca
    if args.totp_secret:            auth["totp_secret"]             = args.totp_secret
    if args.totp_field:             auth["totp_field"]              = args.totp_field
    if args.hmac_key_id:            auth["hmac_key_id"]             = args.hmac_key_id
    if args.hmac_secret:            auth["hmac_secret"]             = args.hmac_secret
    if args.hmac_algorithm:         auth["hmac_algorithm"]          = args.hmac_algorithm
    if args.aws_access_key:         auth["aws_access_key_id"]       = args.aws_access_key
    if args.aws_secret_key:         auth["aws_secret_access_key"]   = args.aws_secret_key
    if args.aws_region:             auth["aws_region"]              = args.aws_region
    if args.aws_service:            auth["aws_service"]             = args.aws_service
    if args.aws_session_token:      auth["aws_session_token"]       = args.aws_session_token
    if args.kerberos_principal:     auth["kerberos_principal"]      = args.kerberos_principal
    if args.no_verify:              verify_ssl = False

    if not url:
        print("ERROR: no URL specified. Use --url, --settings FILE, or --json '{...}'.",
              file=sys.stderr)
        sys.exit(1)

    # ── AuthProbe ────────────────────────────────────────────────────────────
    if args.probe:
        probe_result = run_probe(url, timeout, proxy, verify_ssl)
        if args.output_json:
            print(json.dumps({"probe": probe_result}))
            sys.exit(0)
        _print_probe_result(probe_result)
        if not (auth.get("method") or auth.get("auth_method")):
            methods = probe_result.get("auth_methods", [])
            if methods:
                suggested = methods[0]["method"]
                auth["method"] = suggested
                print(f"[AuthProbe] Using suggested method: {suggested}\n")

    if not (auth.get("method") or auth.get("auth_method")):
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
