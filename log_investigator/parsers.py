"""
Loading and parsing of the firewall and authentication logs.

Each log line looks like:
    2026-10-12 08:00:00 BLOCKED src=203.0.113.55 dst=10.0.0.12 proto=TCP port=22 bytes=0
    2026-10-12 08:51:52 LOGIN_FAILED user=admin src=192.0.2.28 host=db01 method=password

Parsing approach: split the line on whitespace, read the timestamp and
event type from fixed positions, then turn the remaining key=value tokens
into a dictionary. Every field is validated, and a bad line is recorded
with a reason instead of stopping the program.
"""

import ipaddress
from datetime import datetime

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"

FIREWALL_ACTIONS = {"ALLOWED", "BLOCKED"}
FIREWALL_FIELDS = ["src", "dst", "proto", "port", "bytes"]

AUTH_EVENTS = {"LOGIN_SUCCESS", "LOGIN_FAILED", "ACCOUNT_LOCKED", "LOGOUT"}
AUTH_FIELDS = ["user", "src", "host", "method"]


class LogFileError(Exception):
    """Raised when a whole log file cannot be read."""


def read_lines(path):
    """
    Read a text file and return its lines.

    File-level problems (missing file, no permission, a folder instead of a
    file) are turned into one LogFileError with a clear message so the
    caller can decide what to do.
    """
    try:
        # errors="replace" means odd bytes become a placeholder character
        # instead of crashing the whole read.
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read().splitlines()
    except FileNotFoundError:
        raise LogFileError(f"File not found: {path}")
    except IsADirectoryError:
        raise LogFileError(f"Expected a file but got a folder: {path}")
    except PermissionError:
        raise LogFileError(f"Permission denied when reading: {path}")
    except OSError as error:
        raise LogFileError(f"Could not read {path}: {error}")


def _split_line(line):
    """
    Split a raw line into (timestamp, event, fields).

    Raises ValueError with a short reason if the basic layout is wrong.
    """
    tokens = line.split()
    if len(tokens) < 3:
        raise ValueError("too few fields")

    try:
        timestamp = datetime.strptime(f"{tokens[0]} {tokens[1]}", TIMESTAMP_FORMAT)
    except ValueError:
        raise ValueError("invalid timestamp")

    event = tokens[2]
    fields = {}
    for token in tokens[3:]:
        if "=" not in token:
            raise ValueError(f"unexpected token '{token}'")
        key, value = token.split("=", 1)
        fields[key] = value

    return timestamp, event, fields


def _require_fields(fields, required):
    """Raise ValueError naming the first required field that is missing or empty."""
    for name in required:
        if not fields.get(name):
            raise ValueError(f"missing or empty '{name}'")


def _validate_ip(value, field_name):
    """Return the IP as a string, or raise ValueError if it is not a valid address."""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise ValueError(f"invalid IP in '{field_name}': {value}")


def parse_firewall_line(line):
    """
    Parse one firewall line.

    Returns (record, None) on success or (None, reason) on failure.
    """
    try:
        timestamp, action, fields = _split_line(line)

        if action not in FIREWALL_ACTIONS:
            raise ValueError(f"unknown action '{action}'")
        _require_fields(fields, FIREWALL_FIELDS)

        port = int(fields["port"]) if fields["port"].isdigit() else -1
        if not 1 <= port <= 65535:
            raise ValueError(f"invalid port '{fields['port']}'")
        if not fields["bytes"].isdigit():
            raise ValueError(f"invalid byte count '{fields['bytes']}'")

        record = {
            "timestamp": timestamp,
            "action": action,
            "src": _validate_ip(fields["src"], "src"),
            "dst": _validate_ip(fields["dst"], "dst"),
            "proto": fields["proto"].upper(),
            "port": port,
            "bytes": int(fields["bytes"]),
        }
        return record, None
    except ValueError as error:
        return None, str(error)


def parse_auth_line(line):
    """
    Parse one authentication line.

    Returns (record, None) on success or (None, reason) on failure.
    """
    try:
        timestamp, event, fields = _split_line(line)

        if event not in AUTH_EVENTS:
            raise ValueError(f"unknown event '{event}'")
        _require_fields(fields, AUTH_FIELDS)

        record = {
            "timestamp": timestamp,
            "event": event,
            "user": fields["user"],
            "src": _validate_ip(fields["src"], "src"),
            "host": fields["host"],
            "method": fields["method"],
        }
        return record, None
    except ValueError as error:
        return None, str(error)


def load_log(path, parser):
    """
    Read a log file and parse every line with the given parser function.

    Returns a dictionary with the valid records plus a list of rejected
    lines (line number, reason, raw text) for the data-quality section of
    the report. Blank lines are counted but not reported as errors.
    """
    lines = read_lines(path)
    records = []
    rejected = []
    blank = 0

    for number, line in enumerate(lines, start=1):
        if not line.strip():
            blank += 1
            continue

        record, reason = parser(line)
        if record is not None:
            records.append(record)
        else:
            rejected.append({"line": number, "reason": reason, "raw": line.strip()})

    # Keep events in time order so the time-window detections work.
    records.sort(key=lambda item: item["timestamp"])

    return {
        "path": str(path),
        "total_lines": len(lines),
        "blank_lines": blank,
        "records": records,
        "rejected": rejected,
    }


def load_watchlist(path):
    """
    Load the suspicious IP list (one IP per line, # for comments).

    Invalid entries are skipped and reported. Duplicates are removed while
    keeping the original order.
    """
    lines = read_lines(path)
    watchlist = []
    invalid = []

    for number, line in enumerate(lines, start=1):
        entry = line.split("#", 1)[0].strip()
        if not entry:
            continue
        try:
            ip = str(ipaddress.ip_address(entry))
        except ValueError:
            invalid.append({"line": number, "value": entry})
            continue
        if ip not in watchlist:
            watchlist.append(ip)

    return watchlist, invalid
