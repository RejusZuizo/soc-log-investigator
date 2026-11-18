"""
Unit tests for the SOC Log Investigator.

Run with:  python -m unittest discover -s tests -v
"""

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from log_investigator.config import load_settings  # noqa: E402
from log_investigator.detections import (  # noqa: E402
    busiest_window, detect_brute_force, detect_port_scan, detect_success_after_failures,
)
from log_investigator.parsers import (  # noqa: E402
    LogFileError, load_log, load_watchlist, parse_auth_line, parse_firewall_line,
)
from log_investigator.risk import classify_risk  # noqa: E402
import investigate  # noqa: E402

SETTINGS, _ = load_settings()
START = datetime(2026, 10, 12, 9, 0, 0)


def auth_event(minute, event, user="admin", src="203.0.113.5"):
    return {"timestamp": START + timedelta(minutes=minute), "event": event,
            "user": user, "src": src, "host": "vpn01", "method": "password"}


class ParserTests(unittest.TestCase):

    def test_valid_firewall_line(self):
        record, error = parse_firewall_line(
            "2026-10-12 08:00:00 BLOCKED src=203.0.113.55 dst=10.0.0.12 proto=TCP port=22 bytes=0")
        self.assertIsNone(error)
        self.assertEqual(record["action"], "BLOCKED")
        self.assertEqual(record["port"], 22)

    def test_firewall_rejects_bad_port(self):
        record, error = parse_firewall_line(
            "2026-10-16 08:00:00 ALLOWED src=192.168.1.12 dst=10.0.0.8 proto=TCP port=notaport bytes=250")
        self.assertIsNone(record)
        self.assertIn("invalid port", error)

    def test_firewall_rejects_empty_src(self):
        _, error = parse_firewall_line(
            "2026-10-13 09:44:11 BLOCKED src= dst=10.0.0.8 proto=TCP port=22")
        self.assertIn("src", error)

    def test_firewall_rejects_unknown_action(self):
        _, error = parse_firewall_line(
            "2026-10-15 12:00:00 UNKNOWN src=192.168.1.14 dst=10.0.0.9 proto=TCP port=9999 bytes=1")
        self.assertIn("unknown action", error)

    def test_bad_timestamp(self):
        _, error = parse_auth_line(
            "2026-10-15 BADTIME LOGIN_SUCCESS user=alice src=192.168.1.20 host=web01 method=sso")
        self.assertEqual(error, "invalid timestamp")

    def test_auth_rejects_empty_user(self):
        _, error = parse_auth_line(
            "2026-10-14 09:00:00 LOGIN_FAILED user= src=198.51.100.88 host=web01 method=password")
        self.assertIn("user", error)

    def test_garbage_line(self):
        record, error = parse_auth_line("MALFORMED AUTH LINE")
        self.assertIsNone(record)
        self.assertIsNotNone(error)

    def test_load_log_skips_bad_lines(self):
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as handle:
            handle.write("2026-10-12 08:00:00 BLOCKED src=1.2.3.4 dst=10.0.0.1 proto=TCP port=22 bytes=0\n")
            handle.write("garbage\n\n")
            path = handle.name
        try:
            log = load_log(path, parse_firewall_line)
            self.assertEqual(len(log["records"]), 1)
            self.assertEqual(len(log["rejected"]), 1)
            self.assertEqual(log["blank_lines"], 1)
        finally:
            os.remove(path)

    def test_missing_file_raises_clear_error(self):
        with self.assertRaises(LogFileError) as context:
            load_log("does_not_exist.log", parse_firewall_line)
        self.assertIn("File not found", str(context.exception))

    def test_watchlist_dedup_and_invalid(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
            handle.write("203.0.113.5\n203.0.113.5\nnot-an-ip\n# comment\n")
            path = handle.name
        try:
            watchlist, invalid = load_watchlist(path)
            self.assertEqual(watchlist, ["203.0.113.5"])
            self.assertEqual(len(invalid), 1)
        finally:
            os.remove(path)


class DetectionTests(unittest.TestCase):

    def test_busiest_window(self):
        times = [START + timedelta(minutes=m) for m in (0, 1, 2, 100, 101)]
        count, _, _ = busiest_window(times, 10)
        self.assertEqual(count, 3)

    def test_brute_force_detected(self):
        records = [auth_event(i, "LOGIN_FAILED") for i in range(12)]
        findings = detect_brute_force(records, SETTINGS)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["ip"], "203.0.113.5")

    def test_slow_failures_not_brute_force(self):
        # 12 failures, but one every 2 hours: below the per-window threshold.
        records = [auth_event(i * 120, "LOGIN_FAILED") for i in range(12)]
        self.assertEqual(detect_brute_force(records, SETTINGS), [])

    def test_success_after_failures_is_critical(self):
        records = [auth_event(i, "LOGIN_FAILED") for i in range(6)]
        records.append(auth_event(7, "LOGIN_SUCCESS"))
        findings = detect_success_after_failures(records, SETTINGS)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "CRITICAL")

    def test_port_scan_detected(self):
        records = [{"timestamp": START + timedelta(minutes=i), "action": "BLOCKED",
                    "src": "203.0.113.9", "dst": "10.0.0.1", "proto": "TCP",
                    "port": 1000 + i, "bytes": 0} for i in range(12)]
        findings = detect_port_scan(records, SETTINGS)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["evidence"]["distinct_ports"], 12)


class RiskAndConfigTests(unittest.TestCase):

    def test_classify_risk_levels(self):
        levels = SETTINGS["risk_levels"]
        self.assertEqual(classify_risk(100, levels), "CRITICAL")
        self.assertEqual(classify_risk(50, levels), "HIGH")
        self.assertEqual(classify_risk(20, levels), "MEDIUM")
        self.assertEqual(classify_risk(0, levels), "NONE")

    def test_bad_config_falls_back_to_defaults(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            handle.write("{ not valid json")
            path = handle.name
        try:
            settings, warnings = load_settings(path)
            self.assertEqual(settings["brute_force_threshold"], 10)
            self.assertTrue(warnings)
        finally:
            os.remove(path)

    def test_config_override_and_wrong_type(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump({"brute_force_threshold": 5, "top_n": "ten"}, handle)
            path = handle.name
        try:
            settings, warnings = load_settings(path)
            self.assertEqual(settings["brute_force_threshold"], 5)
            self.assertEqual(settings["top_n"], 5)
            self.assertEqual(len(warnings), 1)
        finally:
            os.remove(path)


class EndToEndTests(unittest.TestCase):

    def test_full_run_on_supplied_data(self):
        root = os.path.join(os.path.dirname(__file__), "..")
        with tempfile.TemporaryDirectory() as output:
            code = investigate.main([
                "--firewall", os.path.join(root, "data", "firewall.log"),
                "--auth", os.path.join(root, "data", "authentication.log"),
                "--watchlist", os.path.join(root, "data", "suspicious_ips.txt"),
                "--output", output, "--quiet",
            ])
            self.assertEqual(code, 0)
            for name in ("investigation_report.txt", "investigation_report.json",
                         "ip_risk_ranking.csv", "findings.csv"):
                self.assertTrue(os.path.exists(os.path.join(output, name)))

    def test_both_logs_missing_returns_error(self):
        code = investigate.main(["--firewall", "nope.log", "--auth", "nope2.log", "--quiet"])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
