#!/usr/bin/env python3
"""
SOC Log Investigator - COMP H2702 Scenario A (Security Log Investigation)

Reads a firewall log and an authentication log, finds attack patterns,
scores each suspicious IP, and writes an investigation report to the
console plus TXT, JSON and CSV files.

Usage:
    python investigate.py
    python investigate.py --firewall data/firewall.log --auth data/authentication.log
    python investigate.py --config settings.example.json --output results
    python investigate.py --help
"""

import argparse
import sys
from datetime import datetime

from log_investigator.analysis import analyse_auth, analyse_firewall
from log_investigator.config import load_settings
from log_investigator.detections import run_all_detections
from log_investigator.parsers import (
    LogFileError, load_log, load_watchlist, parse_auth_line, parse_firewall_line,
)
from log_investigator.report import build_observations, build_text_report, write_reports
from log_investigator.risk import score_ips


def parse_arguments(argv=None):
    """Define and read the command-line options."""
    parser = argparse.ArgumentParser(
        description="Analyse firewall and authentication logs and produce a SOC investigation report.",
    )
    parser.add_argument("--firewall", default="data/firewall.log",
                        help="path to the firewall log (default: data/firewall.log)")
    parser.add_argument("--auth", default="data/authentication.log",
                        help="path to the authentication log (default: data/authentication.log)")
    parser.add_argument("--watchlist", default="data/suspicious_ips.txt",
                        help="suspicious IP list, use --watchlist '' to skip (default: data/suspicious_ips.txt)")
    parser.add_argument("--config", default=None,
                        help="optional JSON file that overrides detection thresholds")
    parser.add_argument("--output", default="output",
                        help="folder for the saved reports (default: output)")
    parser.add_argument("--quiet", action="store_true",
                        help="do not print the full report, only the saved file paths")
    return parser.parse_args(argv)


def load_inputs(args, warnings):
    """
    Load both logs and the watchlist.

    One missing log is a warning (the other is still analysed). Both
    missing is fatal because there would be nothing to investigate.
    """
    logs = {}
    for name, path, parser in (("firewall", args.firewall, parse_firewall_line),
                               ("auth", args.auth, parse_auth_line)):
        try:
            logs[name] = load_log(path, parser)
        except LogFileError as error:
            warnings.append(f"{name} log skipped: {error}")
            logs[name] = None

    if logs["firewall"] is None and logs["auth"] is None:
        raise LogFileError("Neither log file could be loaded, nothing to analyse.")

    watchlist = []
    if args.watchlist:
        try:
            watchlist, invalid = load_watchlist(args.watchlist)
            for bad in invalid:
                warnings.append(f"Watchlist line {bad['line']} is not a valid IP: '{bad['value']}'")
        except LogFileError as error:
            warnings.append(f"Watchlist skipped: {error}")

    return logs, watchlist


def investigate(args):
    """Run the full pipeline and return the results dictionary."""
    settings, warnings = load_settings(args.config)
    logs, watchlist = load_inputs(args, warnings)

    fw_records = logs["firewall"]["records"] if logs["firewall"] else []
    auth_records = logs["auth"]["records"] if logs["auth"] else []

    findings = run_all_detections(fw_records, auth_records, watchlist, settings)
    ranked, watchlist_status = score_ips(findings, fw_records, auth_records, watchlist, settings)

    def quality(log):
        if not log:
            return None
        return {"total_lines": log["total_lines"], "valid": len(log["records"]),
                "blank_lines": log["blank_lines"], "rejected": log["rejected"]}

    results = {
        "meta": {
            "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "firewall_path": args.firewall,
            "auth_path": args.auth,
            "watchlist_path": args.watchlist,
            "settings": settings,
        },
        "firewall": analyse_firewall(fw_records, settings) if logs["firewall"] else None,
        "auth": analyse_auth(auth_records, settings) if logs["auth"] else None,
        "findings": findings,
        "ranked_ips": ranked,
        "watchlist_status": watchlist_status,
        "firewall_quality": quality(logs["firewall"]),
        "auth_quality": quality(logs["auth"]),
        "warnings": warnings,
    }
    results["observations"] = build_observations(results)
    return results


def main(argv=None):
    """Entry point. Returns an exit code (0 = ok, 1 = error)."""
    args = parse_arguments(argv)

    try:
        results = investigate(args)
    except LogFileError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        print("Check the --firewall and --auth paths and try again.", file=sys.stderr)
        return 1

    text = build_text_report(results)
    if not args.quiet:
        print("\n".join(text))
    for warning in results["warnings"]:
        print(f"WARNING: {warning}", file=sys.stderr)

    try:
        written = write_reports(results, text, args.output)
    except OSError as error:
        print(f"ERROR: could not save reports: {error}", file=sys.stderr)
        return 1

    print("Reports saved:")
    for path in written:
        print(f"  {path}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user.", file=sys.stderr)
        sys.exit(130)
