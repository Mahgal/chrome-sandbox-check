#!/usr/bin/env python3
"""Unit tests for chrome_sandbox_check.py (stdlib unittest only).

Run:  python3 tests/run_tests.py
"""
import io
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from chrome_sandbox_check import (  # noqa: E402
    FIXED_VERSION, compare_versions, detect_browsers, parse_version,
    run_demo, verdict_for,
)

TOOL = os.path.join(os.path.dirname(__file__), "..", "chrome_sandbox_check.py")


class TestParseVersion(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(parse_version("158.0.8127.88"), (158, 0, 8127, 88))

    def test_embedded_in_output(self):
        self.assertEqual(parse_version("Google Chrome 157.0.8103.78"),
                         (157, 0, 8103, 78))

    def test_short_version(self):
        self.assertEqual(parse_version("158"), (158,))

    def test_leading_zeros(self):
        self.assertEqual(parse_version("1.02.003"), (1, 2, 3))

    def test_v_prefix(self):
        self.assertEqual(parse_version("v158.0.8127.88"), (158, 0, 8127, 88))

    def test_empty(self):
        self.assertIsNone(parse_version(""))
        self.assertIsNone(parse_version(None))

    def test_no_digits(self):
        self.assertIsNone(parse_version("no version here"))


class TestCompareVersions(unittest.TestCase):
    def test_equal(self):
        self.assertEqual(compare_versions((158, 0, 8127, 88),
                                          (158, 0, 8127, 88)), 0)

    def test_less(self):
        self.assertEqual(compare_versions((157, 0, 8103, 78),
                                          (158, 0, 8127, 88)), -1)

    def test_greater(self):
        self.assertEqual(compare_versions((158, 0, 8127, 89),
                                          (158, 0, 8127, 88)), 1)

    def test_shorter_equal_after_padding(self):
        self.assertEqual(compare_versions((158,), (158, 0, 0, 0)), 0)

    def test_shorter_less(self):
        self.assertEqual(compare_versions((157, 9), (158,)), -1)

    def test_numeric_not_lexicographic(self):
        # 9 < 10 numerically, but "9" > "10" as strings.
        self.assertEqual(compare_versions((158, 0, 9, 0),
                                          (158, 0, 10, 0)), -1)

    def test_leading_zeros_equal(self):
        self.assertEqual(compare_versions(parse_version("1.02.3"),
                                          (1, 2, 3)), 0)


class TestVerdict(unittest.TestCase):
    def test_fixed_minus_one(self):
        self.assertEqual(verdict_for((158, 0, 8127, 87)), "VULNERABLE")

    def test_fixed_exact(self):
        self.assertEqual(verdict_for((158, 0, 8127, 88)), "PATCHED")

    def test_fixed_plus_one(self):
        self.assertEqual(verdict_for((158, 0, 8127, 89)), "PATCHED")

    def test_old_major(self):
        self.assertEqual(verdict_for((157, 0, 8103, 78)), "VULNERABLE")

    def test_newer_major(self):
        self.assertEqual(verdict_for((159, 0, 0, 0)), "PATCHED")

    def test_unknown(self):
        self.assertEqual(verdict_for(None), "UNKNOWN")


class TestDemo(unittest.TestCase):
    def _run_demo_subprocess(self):
        proc = subprocess.run([sys.executable, TOOL, "--demo"],
                              capture_output=True, text=True, timeout=30)
        return proc

    def test_demo_exit_zero(self):
        self.assertEqual(self._run_demo_subprocess().returncode, 0)

    def test_demo_deterministic(self):
        a = self._run_demo_subprocess().stdout
        b = self._run_demo_subprocess().stdout
        self.assertEqual(a, b, "two --demo runs must be byte-identical")

    def test_demo_contains_expected_rows(self):
        out = self._run_demo_subprocess().stdout
        self.assertIn("157.0.8103.78", out)
        self.assertIn("158.0.8127.88", out)
        self.assertIn("VULNERABLE", out)
        self.assertIn("PATCHED", out)
        self.assertIn("2 patched, 2 vulnerable", out)
        self.assertIn("CVE-2026-134401", out)

    def test_demo_line_budget(self):
        out = self._run_demo_subprocess().stdout
        self.assertLessEqual(len(out.rstrip("\n").split("\n")), 34)


class TestDetection(unittest.TestCase):
    def test_no_candidates(self):
        self.assertEqual(detect_browsers(candidates=[]), [])

    def test_fake_browser_on_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = os.path.join(tmp, "google-chrome")
            with open(fake, "w") as fh:
                fh.write("#!/bin/sh\necho 'Google Chrome 157.0.8103.78'\n")
            os.chmod(fake, 0o755)
            old_path = os.environ.get("PATH", "")
            os.environ["PATH"] = tmp + os.pathsep + old_path
            try:
                found = detect_browsers()
            finally:
                os.environ["PATH"] = old_path
            self.assertEqual(len(found), 1)
            name, version, _exe = found[0]
            self.assertEqual(name, "Chrome")
            self.assertEqual(version, (157, 0, 8103, 78))
            self.assertEqual(verdict_for(version), "VULNERABLE")

    def test_malformed_version_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = os.path.join(tmp, "brave-browser")
            with open(fake, "w") as fh:
                fh.write("#!/bin/sh\necho 'totally not a version'\n")
            os.chmod(fake, 0o755)
            old_path = os.environ.get("PATH", "")
            os.environ["PATH"] = tmp + os.pathsep + old_path
            try:
                found = detect_browsers()
            finally:
                os.environ["PATH"] = old_path
            brave = [f for f in found if f[0] == "Brave"]
            self.assertEqual(len(brave), 1)
            self.assertIsNone(brave[0][1])
            self.assertEqual(verdict_for(brave[0][1]), "UNKNOWN")

    def test_scan_exit_zero_when_no_browser(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ, PATH=tmp)
            proc = subprocess.run(
                [sys.executable, TOOL], capture_output=True, text=True,
                timeout=30, env=env)
            self.assertEqual(proc.returncode, 0)
            self.assertIn("No Chromium-family browser found", proc.stdout)

    def test_scan_exit_one_when_vulnerable(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = os.path.join(tmp, "google-chrome")
            with open(fake, "w") as fh:
                fh.write("#!/bin/sh\necho 'Google Chrome 157.0.8103.78'\n")
            os.chmod(fake, 0o755)
            env = dict(os.environ, PATH=tmp + os.pathsep + os.environ["PATH"])
            proc = subprocess.run(
                [sys.executable, TOOL], capture_output=True, text=True,
                timeout=30, env=env)
            self.assertEqual(proc.returncode, 1)
            self.assertIn("VULNERABLE", proc.stdout)

    def test_usage_error_exit_two(self):
        proc = subprocess.run([sys.executable, TOOL, "--bogus-flag"],
                              capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
