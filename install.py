#!/usr/bin/env python3
"""
install.py — Siphon dependency installer

Installs Python packages, Go-based tools, git-cloned utilities, and
system packages required by siphon.py for full functionality.

Supported platforms: macOS (Homebrew), Debian/Ubuntu/Kali (apt),
                     RHEL/CentOS/Fedora/Rocky (dnf), openSUSE (zypper).
"""

import argparse
import os
import platform
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

VERSION = "1.2.0"

# ---------------------------------------------------------------------------
# ANSI colours (same convention as Fracture)
# ---------------------------------------------------------------------------
R = "\033[1;31m"
G = "\033[1;32m"
Y = "\033[1;33m"
B = "\033[1;34m"
C = "\033[1;36m"
W = "\033[0m"


def banner(msg):  print(f"\n{B}{'='*60}{W}\n{C}  {msg}{W}\n{B}{'='*60}{W}")
def info(msg):    print(f"{G}[+]{W} {msg}")
def warn(msg):    print(f"{Y}[!]{W} {msg}")
def error(msg):   print(f"{R}[x]{W} {msg}")
def step(msg):    print(f"{B}[>]{W} {msg}")


# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------

def detect_os() -> str:
    system = platform.system()
    if system == "Darwin":
        return "macos"
    if system == "Windows":
        return "windows"
    try:
        with open("/etc/os-release") as f:
            data = f.read().lower()
    except FileNotFoundError:
        return "linux-unknown"
    if "kali" in data or "debian" in data or "ubuntu" in data:
        return "apt"
    if "rhel" in data or "centos" in data or "rocky" in data or "fedora" in data:
        return "dnf"
    if "suse" in data or "opensuse" in data:
        return "zypper"
    return "linux-unknown"


OS = detect_os()


# ---------------------------------------------------------------------------
# Privilege helpers
# ---------------------------------------------------------------------------

def is_root() -> bool:
    return os.getuid() == 0 if hasattr(os, "getuid") else False


def get_sudo_user() -> str:
    return os.environ.get("SUDO_USER", "")


def require_root() -> None:
    """Re-execute under sudo if not already root (Unix only)."""
    if platform.system() == "Windows":
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                error("This installer requires Administrator privileges.")
                error("Right-click the terminal and choose 'Run as administrator'.")
                sys.exit(1)
        except Exception:
            warn("Could not verify Windows admin status — continuing.")
        return
    if not is_root():
        warn("Installer requires root privileges. Re-running with sudo ...")
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run(cmd, check: bool = True, capture: bool = False,
        env=None, cwd=None) -> subprocess.CompletedProcess:
    step(" ".join(cmd) if isinstance(cmd, list) else cmd)
    kwargs: dict = {"check": check}
    if capture:
        kwargs["capture_output"] = True
        kwargs["text"] = True
    if env:
        kwargs["env"] = env
    if cwd:
        kwargs["cwd"] = cwd
    return subprocess.run(cmd, **kwargs)


# ---------------------------------------------------------------------------
# Homebrew helper — never run as root
# ---------------------------------------------------------------------------

def brew_install(pkg: str) -> bool:
    brew_path = shutil.which("brew")
    if not brew_path:
        for p in ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]:
            if os.path.isfile(p):
                brew_path = p
                break
    if not brew_path:
        warn(f"brew not found — skipping {pkg}")
        return False
    cmd = [brew_path, "install", pkg]
    if is_root():
        sudo_user = get_sudo_user()
        if not sudo_user:
            warn(f"Running as root without SUDO_USER — cannot run brew safely. Skipping {pkg}.")
            return False
        cmd = ["sudo", "-u", sudo_user] + cmd
    try:
        run(cmd, check=False)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Package managers
# ---------------------------------------------------------------------------

_apt_updated = False


def apt_install(packages: list) -> None:
    global _apt_updated
    if not _apt_updated:
        info("Running apt-get update ...")
        run(["apt-get", "update", "-y"])
        _apt_updated = True
    run(["apt-get", "install", "-y"] + packages)


def dnf_install(packages: list) -> None:
    run(["dnf", "install", "-y"] + packages)


def zypper_install(packages: list) -> None:
    run(["zypper", "install", "-y"] + packages)


# ---------------------------------------------------------------------------
# System packages
# ---------------------------------------------------------------------------

APT_PACKAGES = [
    "sslscan",
    "curl",
    "jq",
    "python3-pip",
    "python3-dev",
    "git",
    "golang-go",
    "feroxbuster",
    "ffuf",
]

DNF_PACKAGES = [
    "sslscan",
    "curl",
    "jq",
    "python3-pip",
    "python3-devel",
    "git",
    "golang",
]

BREW_PACKAGES = [
    "sslscan",
    "curl",
    "jq",
    "git",
    "ffuf",
    "feroxbuster",
]


def install_system() -> None:
    banner("Phase: system packages")
    if OS == "apt":
        apt_install(APT_PACKAGES)
    elif OS == "dnf":
        dnf_install(DNF_PACKAGES)
        # feroxbuster/ffuf not in default dnf repos — install via go
        go_bin = find_go()
        if go_bin:
            env = os.environ.copy()
            env["GOBIN"] = "/usr/local/bin"
            if not shutil.which("ffuf"):
                run([go_bin, "install", "github.com/ffuf/ffuf/v2@latest"], check=False, env=env)
    elif OS == "zypper":
        zypper_install(["sslscan", "curl", "jq", "python3-pip", "git", "golang"])
    elif OS == "macos":
        for pkg in BREW_PACKAGES:
            brew_install(pkg)
    elif OS == "windows":
        warn("Windows: install sslscan, curl, jq, ffuf manually.")
    else:
        warn(f"Unknown OS '{OS}' — skipping system packages.")


# ---------------------------------------------------------------------------
# pip packages
# ---------------------------------------------------------------------------

PIP_PACKAGES = [
    "requests>=2.28.0",      # HTTP client — required
    "colorama>=0.4.6",       # ANSI colour output — required
    "pyyaml>=6.0.0",         # YAML parser for OpenAPI/Swagger spec ingestion — required
    "beautifulsoup4>=4.12.0", # HTML parser for response analysis — required
    "sqlmap",                 # SQL injection testing — required
    "termcolor>=2.0.0",       # terminal colour output — required
    "websocket-client>=1.6.0",# WebSocket handshake/passive checks (Phase 21) — optional
]

OFFLINE_BUNDLE_URLS = {
    "beautifulsoup4": "https://raw.githubusercontent.com/pr0t31n/OfflineInstallers/main/beautifulsoup4_offline_kali.tar.gz",
    "selenium":       "https://raw.githubusercontent.com/pr0t31n/OfflineInstallers/main/selenium_offline_kali.tar.gz",
    "sqlmap":         "https://raw.githubusercontent.com/pr0t31n/OfflineInstallers/main/sqlmap_offline_kali.tar.gz",
}

_OFFLINE_REPO_DIR = "/opt/OfflineInstallers"
_OFFLINE_REPO_URL = "https://github.com/pr0t31n/OfflineInstallers"

GIT_PIP_URLS = {
    "termcolor": "https://github.com/termcolor/termcolor",
}


def _install_from_git_pip(pkg_name: str, repo_url: str) -> bool:
    """Clone a Python package from GitHub and install it with pip."""
    _git = shutil.which("git")
    if not _git:
        warn(f"git not found — cannot install {pkg_name} from source")
        return False
    info(f"Installing {pkg_name} from git source ...")
    _clone_dir = f"/tmp/_gitpip_{pkg_name}"
    if os.path.isdir(_clone_dir):
        shutil.rmtree(_clone_dir, ignore_errors=True)
    r_clone = subprocess.run([_git, "clone", "--depth=1", repo_url, _clone_dir], check=False)
    if r_clone.returncode != 0:
        warn(f"git clone failed for {pkg_name}")
        shutil.rmtree(_clone_dir, ignore_errors=True)
        return False
    r_pip = subprocess.run(
        [sys.executable, "-m", "pip", "install", "--break-system-packages", _clone_dir],
        check=False,
    )
    shutil.rmtree(_clone_dir, ignore_errors=True)
    if r_pip.returncode == 0:
        info(f"{pkg_name} installed from git source")
        return True
    warn(f"git source install failed for {pkg_name}")
    return False


def _install_from_local_repo(pkg_name: str, tarball: str) -> bool:
    """Copy/reassemble a bundle from the already-cloned OfflineInstallers repo.
    Returns True if *tarball* was written successfully."""
    _local_tar = os.path.join(_OFFLINE_REPO_DIR, f"{pkg_name}_offline_kali.tar.gz")
    if os.path.isfile(_local_tar):
        shutil.copy2(_local_tar, tarball)
        return True
    _repo_parts = sorted([
        os.path.join(_OFFLINE_REPO_DIR, f)
        for f in os.listdir(_OFFLINE_REPO_DIR)
        if f.startswith(f"{pkg_name}_offline_kali.part.")
    ])
    if _repo_parts:
        info(f"  Reassembling {len(_repo_parts)} part(s) from cloned repo ...")
        with open(tarball, "wb") as _out:
            for _p in _repo_parts:
                with open(_p, "rb") as _f:
                    _out.write(_f.read())
        return True
    warn(f"{pkg_name} not found in cloned OfflineInstallers repo")
    return False


def _install_from_bundle(pkg_name: str, url: str) -> bool:
    """Download a pre-built offline bundle from GitHub and run install_offline.sh.
    Handles both single .tar.gz files and split .part.* files.
    If the OfflineInstallers repo is already cloned at /opt/OfflineInstallers, installs
    directly from there without attempting any network downloads."""
    _tmp = f"/tmp/_offline_bundle_{pkg_name}"
    if os.path.isdir(_tmp):
        shutil.rmtree(_tmp, ignore_errors=True)
    os.makedirs(_tmp)
    _tarball = os.path.join(_tmp, f"{pkg_name}_offline_kali.tar.gz")
    _downloaded = False

    # Fast path: OfflineInstallers repo already cloned — skip all network attempts
    if os.path.isdir(os.path.join(_OFFLINE_REPO_DIR, ".git")):
        info(f"OfflineInstallers repo already cloned — installing {pkg_name} directly ...")
        _downloaded = _install_from_local_repo(pkg_name, _tarball)
    else:
        info(f"Downloading offline bundle for {pkg_name} ...")
        try:
            urllib.request.urlretrieve(url, _tarball)
            _downloaded = True
        except Exception:
            # Single file unavailable — try split parts (.part.aa, .part.ab, ...)
            _base = url.rsplit("/", 1)[0]
            _parts = []
            _found_gap = False
            for _a in "abcdefghijklmnopqrstuvwxyz":
                if _found_gap:
                    break
                for _b in "abcdefghijklmnopqrstuvwxyz":
                    _sfx = _a + _b
                    _pu = f"{_base}/{pkg_name}_offline_kali.part.{_sfx}"
                    _pp = os.path.join(_tmp, f"part.{_sfx}")
                    try:
                        urllib.request.urlretrieve(_pu, _pp)
                        _parts.append(_pp)
                    except Exception:
                        _found_gap = True
                        break
            if _parts:
                info(f"  Reassembling {len(_parts)} part(s) ...")
                with open(_tarball, "wb") as _out:
                    for _p in sorted(_parts):
                        with open(_p, "rb") as _f:
                            _out.write(_f.read())
                _downloaded = True

        if not _downloaded:
            # Final fallback: clone the OfflineInstallers repo to /opt/ and install from there
            _git = shutil.which("git")
            if _git:
                info("githubusercontent.com inaccessible — cloning OfflineInstallers to /opt/ ...")
                if os.path.isdir(os.path.join(_OFFLINE_REPO_DIR, ".git")):
                    subprocess.run([_git, "-C", _OFFLINE_REPO_DIR, "pull", "--ff-only"], check=False)
                else:
                    subprocess.run([_git, "clone", "--depth=1", _OFFLINE_REPO_URL, _OFFLINE_REPO_DIR], check=False)
                if os.path.isdir(_OFFLINE_REPO_DIR):
                    _downloaded = _install_from_local_repo(pkg_name, _tarball)

    if not _downloaded:
        warn(f"Could not download offline bundle for {pkg_name}")
        shutil.rmtree(_tmp, ignore_errors=True)
        return False

    if subprocess.run(["tar", "xzf", _tarball, "-C", _tmp], check=False).returncode != 0:
        warn(f"Failed to extract offline bundle for {pkg_name}")
        shutil.rmtree(_tmp, ignore_errors=True)
        return False

    _install_sh = None
    for _root, _dirs, _files in os.walk(_tmp):
        if "install_offline.sh" in _files:
            _install_sh = os.path.join(_root, "install_offline.sh")
            break

    if not _install_sh:
        warn(f"install_offline.sh not found in {pkg_name} bundle")
        shutil.rmtree(_tmp, ignore_errors=True)
        return False

    os.chmod(_install_sh, 0o755)
    _ok = subprocess.run(["bash", _install_sh], check=False).returncode == 0
    shutil.rmtree(_tmp, ignore_errors=True)
    if _ok:
        info(f"{pkg_name} installed from offline bundle")
    else:
        warn(f"Offline bundle install failed for {pkg_name}")
    return _ok


def install_pip() -> None:
    banner("Phase: pip packages")
    for _pkg in PIP_PACKAGES:
        _r = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--break-system-packages", _pkg],
            check=False,
        )
        if _r.returncode != 0:
            _name = _pkg.split(">=")[0].split("==")[0].split("[")[0].strip()
            if _name in OFFLINE_BUNDLE_URLS:
                warn(f"pip install failed for {_name} — trying offline bundle ...")
                _install_from_bundle(_name, OFFLINE_BUNDLE_URLS[_name])
            elif _name in GIT_PIP_URLS:
                warn(f"pip install failed for {_name} — trying git source ...")
                _install_from_git_pip(_name, GIT_PIP_URLS[_name])
            else:
                warn(f"pip install failed for {_name}")


def install_selenium() -> None:
    """
    Install the Selenium Python binding using the best available method.

    Priority order:
      1. GitHub source — pip install git+https://github.com/seleniumhq/selenium.git#subdirectory=py
      2. pip (PyPI)    — pip install selenium>=4.0.0
      3. System pkg    — apt-get / dnf / zypper (last resort)

    webdriver-manager is not available in any system repo; it is always
    installed via pip after the Selenium binding is in place.
    """
    banner("Phase: Selenium (browser-assisted login)")

    # Check if already importable
    try:
        import selenium as _sel
        info(f"selenium already installed ({_sel.__version__}) — checking webdriver-manager")
        _sel_installed = True
    except ImportError:
        _sel_installed = False

    if not _sel_installed:
        _installed = False

        # 1. GitHub source via git clone → pip install local py/ subdir
        _git = shutil.which("git")
        if _git:
            info("Trying selenium from GitHub source (git clone) ...")
            _clone_dir = "/tmp/_selenium_src"
            if os.path.isdir(_clone_dir):
                shutil.rmtree(_clone_dir, ignore_errors=True)
            r_clone = subprocess.run(
                [_git, "clone", "--depth=1",
                 "https://github.com/seleniumhq/selenium.git", _clone_dir],
                check=False,
            )
            if r_clone.returncode == 0:
                subprocess.run(
                    [sys.executable, "-m", "pip", "install",
                     "--break-system-packages", "--quiet", "hatchling"],
                    check=False,
                )
                r_pip = subprocess.run(
                    [sys.executable, "-m", "pip", "install",
                     "--break-system-packages",
                     os.path.join(_clone_dir, "py")],
                    check=False,
                )
                if r_pip.returncode == 0:
                    _installed = True
                    info("selenium installed from GitHub source")
            shutil.rmtree(_clone_dir, ignore_errors=True)
        else:
            warn("git not found — skipping GitHub source install")

        # 2. pip (PyPI)
        if not _installed:
            warn("GitHub source install failed — trying pip (PyPI) ...")
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "--break-system-packages",
                 "selenium>=4.0.0"],
                check=False,
            )
            if result.returncode == 0:
                _installed = True
                info("selenium installed via pip (PyPI)")

        # 3. System package manager (last resort)
        if not _installed:
            if OS == "apt" and shutil.which("apt-get"):
                warn("pip install failed — trying apt-get (last resort) ...")
                global _apt_updated
                if not _apt_updated:
                    run(["apt-get", "update", "-y"], check=False)
                    _apt_updated = True
                result = subprocess.run(
                    ["apt-get", "install", "-y", "python3-selenium"],
                    check=False,
                )
                if result.returncode == 0:
                    _installed = True
                    info("python3-selenium installed via apt-get")
            elif OS == "dnf" and shutil.which("dnf"):
                warn("pip install failed — trying dnf (last resort) ...")
                result = subprocess.run(
                    ["dnf", "install", "-y", "python3-selenium"],
                    check=False,
                )
                if result.returncode == 0:
                    _installed = True
                    info("python3-selenium installed via dnf")
            elif OS == "zypper" and shutil.which("zypper"):
                warn("pip install failed — trying zypper (last resort) ...")
                result = subprocess.run(
                    ["zypper", "install", "-y", "python3-selenium"],
                    check=False,
                )
                if result.returncode == 0:
                    _installed = True
                    info("python3-selenium installed via zypper")

        if not _installed:
            warn("All selenium install methods failed — trying offline bundle ...")
            _installed = _install_from_bundle("selenium", OFFLINE_BUNDLE_URLS["selenium"])
        if not _installed:
            warn("selenium unavailable — browser-assisted login will not work")

    # webdriver-manager is pip-only (not in any system repo)
    try:
        import webdriver_manager  # noqa: F401
        info("webdriver-manager already installed — skipping")
    except ImportError:
        info("Installing webdriver-manager via pip ...")
        _wdm_r = subprocess.run(
            [sys.executable, "-m", "pip", "install",
             "--break-system-packages", "webdriver-manager>=4.0.0"],
            check=False,
        )
        if _wdm_r.returncode != 0:
            warn("pip install failed for webdriver-manager — trying selenium offline bundle ...")
            _install_from_bundle("selenium", OFFLINE_BUNDLE_URLS["selenium"])


# ---------------------------------------------------------------------------
# Go tools
# ---------------------------------------------------------------------------

GO_TOOLS = [
    (
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "nuclei",
        "nuclei",       # brew formula
    ),
    (
        "github.com/ffuf/ffuf/v2@latest",
        "ffuf",
        "ffuf",         # brew formula
    ),
    (
        "github.com/fullstorydev/grpcurl/cmd/grpcurl@latest",
        "grpcurl",      # gRPC reflection enumeration (Phase 21)
        "grpcurl",      # brew formula
    ),
]


def find_go() -> str | None:
    go = shutil.which("go")
    if go:
        return go
    for p in ["/usr/local/go/bin/go", "/usr/lib/go/bin/go"]:
        if os.path.isfile(p):
            return p
    return None


def install_go() -> None:
    banner("Phase: Go tools")
    go_bin = find_go()
    if not go_bin:
        warn("go not found in PATH — skipping Go tool installation.")
        warn("Install Go from https://go.dev/dl/ and re-run with --skip-go")
        return
    env = os.environ.copy()
    env["GOBIN"] = "/usr/local/bin"
    for pkg, name, brew_name in GO_TOOLS:
        if shutil.which(name):
            info(f"{name} already installed — skipping")
            continue
        # macOS: prefer Homebrew if available
        if OS == "macos" and brew_name:
            if brew_install(brew_name):
                continue
        info(f"Installing {name} via go install ...")
        run([go_bin, "install", pkg], check=False, env=env)


# ---------------------------------------------------------------------------
# Git tools
# ---------------------------------------------------------------------------

def git_clone_or_update(url: str, dest: str) -> None:
    if os.path.isdir(dest):
        info(f"Updating existing clone: {dest}")
        run(["git", "-C", dest, "pull", "--ff-only"], check=False)
    else:
        run(["git", "clone", url, dest])


def symlink_force(src: str, dest: str) -> None:
    try:
        if os.path.islink(dest) or os.path.exists(dest):
            os.remove(dest)
        os.symlink(src, dest)
        info(f"Symlink: {dest} -> {src}")
    except PermissionError:
        warn(f"Cannot create symlink {dest} — not root.")
    except Exception as e:
        warn(f"Symlink {dest} failed: {e}")


def install_git() -> None:
    banner("Phase: git tools")

    # testssl.sh — TLS analysis (used by phase_tls)
    git_clone_or_update("https://github.com/drwetter/testssl.sh.git", "/opt/testssl.sh")
    testssl_bin = "/opt/testssl.sh/testssl.sh"
    if os.path.isfile(testssl_bin):
        os.chmod(testssl_bin, 0o755)
        symlink_force(testssl_bin, "/usr/local/bin/testssl.sh")
        info("testssl.sh symlinked to /usr/local/bin/testssl.sh")

    # jwt_tool — JWT testing utility (complements Siphon's JWT phases)
    git_clone_or_update("https://github.com/ticarpi/jwt_tool.git", "/opt/jwt_tool")
    jwt_bin = "/opt/jwt_tool/jwt_tool.py"
    if os.path.isfile(jwt_bin):
        os.chmod(jwt_bin, 0o755)
        symlink_force(jwt_bin, "/usr/local/bin/jwt_tool")
        info("jwt_tool symlinked to /usr/local/bin/jwt_tool")
        req = "/opt/jwt_tool/requirements.txt"
        if os.path.isfile(req):
            run(
                [sys.executable, "-m", "pip", "install",
                 "--break-system-packages", "-r", req],
                check=False,
            )

    # nuclei-templates
    git_clone_or_update(
        "https://github.com/projectdiscovery/nuclei-templates.git",
        "/opt/nuclei-templates",
    )

    # dirsearch — Python web path scanner
    git_clone_or_update("https://github.com/maurosoria/dirsearch.git", "/opt/dirsearch")
    ds_req = "/opt/dirsearch/requirements.txt"
    if os.path.isfile(ds_req):
        run(
            [sys.executable, "-m", "pip", "install",
             "--break-system-packages", "-r", ds_req],
            check=False,
        )
    ds_bin = "/opt/dirsearch/dirsearch.py"
    if os.path.isfile(ds_bin):
        os.chmod(ds_bin, 0o755)
        symlink_force(ds_bin, "/usr/local/bin/dirsearch")
        info("dirsearch symlinked to /usr/local/bin/dirsearch")

    # Kiterunner — API route brute-forcer (requires Go to build)
    git_clone_or_update("https://github.com/assetnote/kiterunner.git", "/opt/kiterunner")
    kr_dist = "/opt/kiterunner/dist/kr"
    if not os.path.isfile(kr_dist):
        go_bin = find_go()
        if go_bin:
            info("Building kiterunner (make build) ...")
            run(["make", "build"], check=False, cwd="/opt/kiterunner")
        else:
            warn("Go not found — cannot build kiterunner. Install Go then run: cd /opt/kiterunner && make build")
    if os.path.isfile(kr_dist):
        os.chmod(kr_dist, 0o755)
        symlink_force(kr_dist, "/usr/local/bin/kr")
        info("kiterunner (kr) symlinked to /usr/local/bin/kr")
    # On macOS, try brew if build failed
    elif OS == "macos":
        info("Attempting kiterunner via brew tap ...")
        brew_install("assetnote/tap/kiterunner")


# ---------------------------------------------------------------------------
# Symlinks
# ---------------------------------------------------------------------------

APP_DIR  = str(Path(__file__).parent.resolve())
APP_FILE = str(Path(APP_DIR) / "siphon.py")
SYMLINKS = {
    "/usr/local/bin/siphon": APP_FILE,
}


def install_symlinks() -> None:
    banner("Creating symlinks")
    if not os.path.isfile(APP_FILE):
        warn(f"{APP_FILE} not found — symlink will point to a missing target.")
    for dest, src in SYMLINKS.items():
        symlink_force(src, dest)


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

VERIFY_PYTHON = ["requests", "colorama", "yaml", "selenium"]

VERIFY_CLI = [
    ("sslscan",     "TLS scanner"),
    ("testssl.sh",  "TLS scanner (testssl)"),
    ("jwt_tool",    "JWT testing utility"),
    ("nuclei",      "Vulnerability scanner"),
    ("kr",          "Kiterunner API route brute-forcer"),
    ("ffuf",        "Fast web fuzzer (FFUF)"),
    ("feroxbuster", "Recursive web content discovery"),
    ("dirsearch",   "Web path scanner (dirsearch)"),
    ("curl",        "HTTP client"),
    ("jq",          "JSON processor"),
]

VERIFY_GIT = [
    ("/opt/testssl.sh",       "testssl.sh"),
    ("/opt/jwt_tool",         "jwt_tool"),
    ("/opt/nuclei-templates", "nuclei-templates"),
    ("/opt/dirsearch",        "dirsearch"),
    ("/opt/kiterunner",       "kiterunner"),
]


def run_check() -> None:
    banner("Post-install verification")

    print(f"\n{C}Python imports:{W}")
    for pkg in VERIFY_PYTHON:
        try:
            __import__(pkg)
            info(f"{pkg:30s} {G}OK{W}")
        except ImportError:
            warn(f"{pkg:30s} {Y}MISSING{W}")

    print(f"\n{C}CLI tools:{W}")
    for tool, desc in VERIFY_CLI:
        found = shutil.which(tool)
        if found:
            info(f"{tool:30s} {G}FOUND{W} ({found})")
        else:
            warn(f"{tool:30s} {Y}NOT FOUND{W}  ({desc})")

    print(f"\n{C}Git clones:{W}")
    for path, label in VERIFY_GIT:
        if os.path.isdir(path):
            info(f"{label:30s} {G}PRESENT{W} ({path})")
        else:
            warn(f"{label:30s} {Y}NOT FOUND{W}")

    print(f"\n{C}Siphon:{W}")
    if os.path.isfile(APP_FILE):
        info(f"siphon.py found at {APP_FILE}")
    else:
        error(f"siphon.py not found at {APP_FILE}")


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def print_summary(skips: set) -> None:
    banner("Post-install summary")
    info(f"Application : Siphon — API Penetration Testing Orchestrator")
    info(f"Location    : {APP_DIR}")
    info(f"Symlink     : siphon → {APP_FILE}")
    info(f"OS detected : {OS}")
    print()
    phases = ["system", "pip", "go", "git"]
    for p in phases:
        status = f"{Y}SKIPPED{W}" if p in skips else f"{G}DONE{W}"
        print(f"  {p:10s} {status}")
    print()
    info("Run: siphon --help")
    warn("testssl.sh    installed from git (/opt/testssl.sh).")
    warn("jwt_tool      installed from git (/opt/jwt_tool).")
    warn("nuclei-templates cloned to /opt/nuclei-templates.")
    warn("dirsearch     installed from git (/opt/dirsearch) — available as /usr/local/bin/dirsearch.")
    warn("kiterunner    installed from git (/opt/kiterunner) — available as /usr/local/bin/kr.")
    warn("ffuf          installed via go/brew — available as /usr/local/bin/ffuf.")
    warn("feroxbuster   installed via apt/brew — available as feroxbuster.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Siphon installer")
    parser.add_argument("--skip-system", "--skip-apt", dest="skip_system", action="store_true",
                        help="Skip system package installation")
    parser.add_argument("--skip-pip",    action="store_true",
                        help="Skip pip package installation")
    parser.add_argument("--skip-go",     action="store_true",
                        help="Skip Go tool installation")
    parser.add_argument("--skip-git",    action="store_true",
                        help="Skip git-cloned tool installation")
    parser.add_argument("--check",       action="store_true",
                        help="Verify installation only, make no changes")
    args = parser.parse_args()

    require_root()

    banner("Siphon — API Penetration Testing Orchestrator — Installer")
    info(f"Detected OS : {OS}")
    info(f"Python      : {sys.executable}")
    info(f"Running as  : {'root' if is_root() else os.environ.get('USER', '?')}")

    if args.check:
        run_check()
        return

    skips: set = set()

    if not args.skip_system:
        install_system()
    else:
        skips.add("system")
        warn("Skipping system packages.")

    if not args.skip_pip:
        install_pip()
    else:
        skips.add("pip")
        warn("Skipping pip packages.")

    install_selenium()

    if not args.skip_go:
        install_go()
    else:
        skips.add("go")
        warn("Skipping Go tools.")

    if not args.skip_git:
        install_git()
    else:
        skips.add("git")
        warn("Skipping git tools.")

    install_symlinks()
    run_check()
    print_summary(skips)


if __name__ == "__main__":
    main()
