#!/usr/bin/env python3
"""chrome-sandbox-check: is your browser patched against CVE-2026-134401?

CVE-2026-134401 is an improper input validation flaw in Chrome's
Variations component. A crafted HTML page could let a remote attacker
execute arbitrary code outside the browser sandbox (Chromium severity:
Critical, CVSS 9.6). Google fixed it in the Stable channel update of
2026-11-23: desktop Chrome 158.0.8127.88 (Windows/Mac also shipped
158.0.8127.89) and Android 158.0.8127.92.

This tool only reads each installed Chromium-family browser's
self-reported version and compares it with the fixed version. It makes
no network calls, runs no exploit, and probes nothing.

Exit codes:
    0  every browser found is patched (or no Chromium browser found)
    1  at least one browser is vulnerable, or a version could not be read
    2  usage error (bad arguments)

Usage:
    python3 chrome_sandbox_check.py          # scan this machine
    python3 chrome_sandbox_check.py --demo   # reproducible fixture demo
"""

import argparse
import os
import re
import shutil
import subprocess
import sys

CVE_ID = "CVE-2026-134401"
FIXED_VERSION = "158.0.8127.88"
FIXED_TUPLE = (158, 0, 8127, 88)

# (display name, binary names to look up on PATH, well-known install paths)
CANDIDATES = [
    ("Chrome", ["google-chrome", "google-chrome-stable"],
     ["/usr/bin/google-chrome", "/usr/bin/google-chrome-stable",
      "/opt/google/chrome/chrome",
      "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
      r"C:\Program Files\Google\Chrome\Application\chrome.exe",
      r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"]),
    ("Chromium", ["chromium", "chromium-browser"],
     ["/usr/bin/chromium", "/usr/bin/chromium-browser",
      "/usr/lib/chromium/chromium",
      "/Applications/Chromium.app/Contents/MacOS/Chromium"]),
    ("Edge", ["microsoft-edge", "microsoft-edge-stable"],
     ["/usr/bin/microsoft-edge", "/usr/bin/microsoft-edge-stable",
      "/opt/microsoft/msedge/msedge",
      "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
      r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"]),
    ("Brave", ["brave-browser", "brave"],
     ["/usr/bin/brave-browser", "/usr/bin/brave",
      "/opt/brave.com/brave/brave",
      "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
      r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"]),
]

# Built-in fixture data for --demo: NOT this machine, reproducible anywhere.
DEMO_ROWS = [
    ("Chrome", "157.0.8103.78"),
    ("Edge", "158.0.8127.88"),
    ("Brave", "157.0.8127.57"),
    ("Chromium", "158.0.8127.88"),
]

_VERSION_RE = re.compile(r"(\d+(?:\.\d+)*)")


def parse_version(text):
    """Extract the first dotted version number from text.

    Returns a tuple of ints, or None if no version number is present.
    Leading zeros are ignored numerically: "1.02.3" -> (1, 2, 3).
    """
    if not text:
        return None
    match = _VERSION_RE.search(text)
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def compare_versions(a, b):
    """Numeric per-component comparison of two version tuples.

    Shorter tuples are padded with zeros, so (158,) == (158, 0, 0, 0).
    Returns -1, 0, or 1.
    """
    length = max(len(a), len(b))
    a = a + (0,) * (length - len(a))
    b = b + (0,) * (length - len(b))
    if a < b:
        return -1
    if a > b:
        return 1
    return 0


def verdict_for(version_tuple):
    """PATCHED if version >= fixed version, VULNERABLE if below.

    Returns "UNKNOWN" when the version could not be parsed.
    """
    if version_tuple is None:
        return "UNKNOWN"
    return "PATCHED" if compare_versions(version_tuple, FIXED_TUPLE) >= 0 else "VULNERABLE"


def _read_version(executable):
    """Run `<executable> --version` and parse the version, or None."""
    try:
        proc = subprocess.run(
            [executable, "--version"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return parse_version(proc.stdout.strip() or proc.stderr.strip())


def detect_browsers(candidates=None):
    """Find installed Chromium-family browsers and their versions.

    Returns a list of (name, version_string_or_None, executable_path).
    A browser is listed once, from the first working lookup that yields it.
    """
    found = []
    for name, binaries, paths in (candidates if candidates is not None else CANDIDATES):
        executable = None
        for binary in binaries:
            executable = shutil.which(binary)
            if executable:
                break
        if executable is None:
            for path in paths:
                if os.path.isfile(path) and os.access(path, os.X_OK):
                    executable = path
                    break
        if executable is None:
            continue
        version = _read_version(executable)
        found.append((name, version, executable))
    return found


def _colour(verdict, stream):
    """Green PATCHED / red VULNERABLE, but only on a real terminal."""
    if not stream.isatty():
        return verdict
    if verdict == "PATCHED":
        return "\033[32mPATCHED\033[0m"
    if verdict == "VULNERABLE":
        return "\033[31mVULNERABLE\033[0m"
    return verdict


def format_table(rows, stream):
    """Render the per-browser table. rows: [(name, version_str, verdict)]."""
    lines = [
        "Browser    Version          Verdict",
        "---------  ---------------  -----------",
    ]
    for name, version, verdict in rows:
        lines.append(f"{name:<10} {version:<15} {_colour(verdict, stream)}")
    return "\n".join(lines)


def run_demo():
    """Deterministic showcase from built-in fixture data. Always exit 0."""
    rows = [(name, version, verdict_for(parse_version(version)))
            for name, version in DEMO_ROWS]
    patched = sum(1 for _, _, v in rows if v == "PATCHED")
    vulnerable = sum(1 for _, _, v in rows if v == "VULNERABLE")
    out = [
        "chrome-sandbox-check -- demo (fixture data, not this machine)",
        f"{CVE_ID} — fixed in Chrome {FIXED_VERSION} (Stable, 2026-11-23)",
        "",
        format_table(rows, sys.stdout),
        "",
        f"Summary: {patched} patched, {vulnerable} vulnerable — "
        f"update to {FIXED_VERSION} or later.",
    ]
    print("\n".join(out))
    return 0


def run_scan():
    """Scan this machine and print the verdict table. Returns exit code."""
    print(f"{CVE_ID} — fixed in Chrome {FIXED_VERSION} (Stable, 2026-11-23)")
    print("Checking installed Chromium-family browsers (version only, "
          "no network, no probing)...")
    print()
    found = detect_browsers()
    if not found:
        print("No Chromium-family browser found on this machine.")
        print("Nothing to update here — exit 0.")
        return 0
    rows = []
    for name, version_tuple, _exe in found:
        version_str = ".".join(str(n) for n in version_tuple) if version_tuple else "unknown"
        rows.append((name, version_str, verdict_for(version_tuple)))
    print(format_table(rows, sys.stdout))
    print()
    patched = sum(1 for _, _, v in rows if v == "PATCHED")
    vulnerable = sum(1 for _, _, v in rows if v == "VULNERABLE")
    unknown = sum(1 for _, _, v in rows if v == "UNKNOWN")
    if vulnerable or unknown:
        print(f"Summary: {patched} patched, {vulnerable} vulnerable"
              + (f", {unknown} unreadable" if unknown else "")
              + f" — update to {FIXED_VERSION} or later, then restart the browser.")
        return 1
    print(f"Summary: {patched} patched, 0 vulnerable — all browsers are up to date.")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=f"Check installed browsers against {CVE_ID} "
                    f"(fixed in {FIXED_VERSION}).")
    parser.add_argument("--demo", action="store_true",
                        help="show a deterministic demo from fixture data")
    args = parser.parse_args(argv)
    if args.demo:
        return run_demo()
    return run_scan()


if __name__ == "__main__":
    sys.exit(main())
