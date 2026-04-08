#!/usr/bin/env python3
"""
install.py — Siphon dependency installer

Installs Python packages, Go-based tools, and system utilities
required by siphon.py for full functionality.
"""

import sys
import os
import subprocess
import platform
import shutil
from pathlib import Path

VERSION = "1.0.1"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd: list, check: bool = True, capture: bool = False, **kwargs) -> subprocess.CompletedProcess:
    """Run a subprocess command with optional output capture."""
    kwargs.setdefault("timeout", 300)
    if capture:
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
        kwargs["text"]   = True
    return subprocess.run(cmd, check=check, **kwargs)


def _which(name: str) -> str | None:
    return shutil.which(name)


def _is_root() -> bool:
    return os.getuid() == 0 if hasattr(os, "getuid") else False


def _sudo_user() -> str:
    return os.environ.get("SUDO_USER", "")


def _brew_install(pkg: str) -> bool:
    """Run 'brew install pkg', dropping to SUDO_USER when running as root."""
    brew_path = shutil.which("brew")
    if not brew_path:
        for p in ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]:
            if os.path.isfile(p):
                brew_path = p
                break
    if not brew_path:
        _print_err(f"brew not found — skipping {pkg}")
        return False
    cmd = [brew_path, "install", pkg]
    if _is_root():
        user = _sudo_user()
        if not user:
            _print_err(f"Running as root without SUDO_USER — cannot run brew safely. Skipping {pkg}.")
            return False
        cmd = ["sudo", "-u", user] + cmd
    try:
        _run(cmd)
        return True
    except subprocess.CalledProcessError:
        return False


def _os_name() -> str:
    s = platform.system().lower()
    if s == "darwin":
        return "macos"
    if s == "windows":
        return "windows"
    return "linux"


def _pip(*packages: str) -> bool:
    """Install one or more pip packages."""
    try:
        _run([sys.executable, "-m", "pip", "install", "--upgrade"] + list(packages))
        return True
    except subprocess.CalledProcessError:
        return False


def _print_ok(msg: str) -> None:
    print(f"  [OK] {msg}")


def _print_skip(msg: str) -> None:
    print(f"  [--] {msg} (already installed)")


def _print_err(msg: str) -> None:
    print(f"  [!!] {msg}", file=sys.stderr)


def _print_section(title: str) -> None:
    bar = "-" * 50
    print(f"\n{bar}\n  {title}\n{bar}")


# ---------------------------------------------------------------------------
# Python packages
# ---------------------------------------------------------------------------

PYTHON_PACKAGES = [
    ("requests",  "requests>=2.28.0",  "HTTP client library"),
    ("colorama",  "colorama>=0.4.6",   "ANSI color output"),
    ("yaml",      "pyyaml>=6.0.0",     "YAML parser for OpenAPI specs"),
]


def install_python_packages() -> None:
    _print_section("Python Packages")
    import importlib.util
    for module, pkg_spec, desc in PYTHON_PACKAGES:
        if importlib.util.find_spec(module):
            _print_skip(f"{pkg_spec} ({desc})")
        else:
            print(f"  Installing {pkg_spec} ({desc}) …")
            if _pip(pkg_spec):
                _print_ok(pkg_spec)
            else:
                _print_err(f"Failed to install {pkg_spec}")


# ---------------------------------------------------------------------------
# Go tools (via go install or binary download)
# ---------------------------------------------------------------------------

GO_TOOLS = [
    {
        "name":    "nuclei",
        "check":   "nuclei",
        "go_path": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "desc":    "Vulnerability scanner (ProjectDiscovery)",
        "brew":    "nuclei",
    },
]


def _install_go_tool(tool: dict) -> bool:
    """Install a Go-based tool."""
    os_name = _os_name()

    # macOS Homebrew
    if os_name == "macos" and _which("brew"):
        brew_name = tool.get("brew")
        if brew_name and _brew_install(brew_name):
            return True

    # go install
    if _which("go"):
        try:
            _run(["go", "install", tool["go_path"]])
            return True
        except subprocess.CalledProcessError:
            pass

    # Linux apt
    if os_name == "linux":
        apt_name = tool.get("apt")
        if apt_name and _which("apt-get"):
            try:
                _run(["sudo", "apt-get", "install", "-y", apt_name])
                return True
            except subprocess.CalledProcessError:
                pass

    return False


def install_go_tools() -> None:
    _print_section("Go / Binary Tools")
    for tool in GO_TOOLS:
        if _which(tool["check"]):
            _print_skip(f"{tool['name']} ({tool['desc']})")
        else:
            print(f"  Installing {tool['name']} ({tool['desc']}) …")
            if _install_go_tool(tool):
                _print_ok(tool["name"])
            else:
                _print_err(
                    f"Could not auto-install {tool['name']}. "
                    f"Install manually: go install {tool['go_path']}"
                )


# ---------------------------------------------------------------------------
# System utilities
# ---------------------------------------------------------------------------

SYSTEM_TOOLS = [
    {
        "name":    "curl",
        "check":   "curl",
        "desc":    "HTTP client",
        "brew":    "curl",
        "apt":     "curl",
    },
    {
        "name":    "jq",
        "check":   "jq",
        "desc":    "JSON processor",
        "brew":    "jq",
        "apt":     "jq",
    },
]


def _install_system_tool(tool: dict) -> bool:
    os_name = _os_name()
    if os_name == "macos" and _which("brew"):
        brew = tool.get("brew")
        if brew and _brew_install(brew):
            return True
    elif os_name == "linux":
        apt_name = tool.get("apt")
        if apt_name and _which("apt-get"):
            try:
                _run(["sudo", "apt-get", "install", "-y", apt_name])
                return True
            except subprocess.CalledProcessError:
                pass
        yum_name = tool.get("yum", tool.get("apt"))
        if yum_name and _which("yum"):
            try:
                _run(["sudo", "yum", "install", "-y", yum_name])
                return True
            except subprocess.CalledProcessError:
                pass
    return False


def install_system_tools() -> None:
    _print_section("System Utilities")
    for tool in SYSTEM_TOOLS:
        if _which(tool["check"]):
            _print_skip(f"{tool['name']} ({tool['desc']})")
        else:
            print(f"  Installing {tool['name']} ({tool['desc']}) …")
            if _install_system_tool(tool):
                _print_ok(tool["name"])
            else:
                _print_err(
                    f"Could not auto-install {tool['name']}. "
                    f"Please install '{tool['name']}' manually."
                )


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify_installation() -> None:
    _print_section("Verification")
    import importlib.util

    all_ok = True

    # Python imports
    for module, pkg_spec, desc in PYTHON_PACKAGES:
        if importlib.util.find_spec(module):
            _print_ok(f"Python: {module}")
        else:
            _print_err(f"Python: {module} NOT found — run: pip install {pkg_spec}")
            all_ok = False

    # CLI tools
    cli_tools = [
        ("nuclei", "Vulnerability scanner"),
        ("curl",   "HTTP client"),
        ("jq",     "JSON processor"),
    ]
    for tool, desc in cli_tools:
        path = _which(tool)
        if path:
            _print_ok(f"CLI: {tool} ({path})")
        else:
            print(f"  [??] CLI: {tool} not found ({desc}) — optional but recommended")

    # Siphon self-check
    siphon_path = Path(__file__).parent / "siphon.py"
    if siphon_path.exists():
        _print_ok(f"siphon.py found at {siphon_path}")
    else:
        _print_err(f"siphon.py not found at {siphon_path}")
        all_ok = False

    print()
    if all_ok:
        print("  All required dependencies installed.")
        print("  Run: python3 siphon.py --help")
    else:
        print("  Some dependencies are missing. See errors above.")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Siphon installer")
    parser.add_argument("--skip-apt",  "--skip-system", dest="skip_system", action="store_true")
    parser.add_argument("--skip-pip",  action="store_true")
    parser.add_argument("--skip-go",   action="store_true")
    parser.add_argument("--skip-git",  action="store_true", help="No-op (reserved for Arsenal compatibility)")
    parser.add_argument("--check",     action="store_true", help="Verify installation only")
    args = parser.parse_args()

    print(f"\nSiphon v{VERSION} — Dependency Installer")
    print("=" * 50)
    print(f"Platform : {platform.system()} {platform.machine()}")
    print(f"Python   : {sys.version.split()[0]}")

    if args.check:
        verify_installation()
        return

    if not args.skip_pip:
        install_python_packages()
    if not args.skip_go:
        install_go_tools()
    if not args.skip_system:
        install_system_tools()
    verify_installation()


if __name__ == "__main__":
    main()
