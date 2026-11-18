"""
Security detections.

Each detection looks for one attack pattern and returns a list of
"findings". A finding is a dictionary with the same keys every time so
the risk and report modules can treat all findings the same way:

    id, title, severity, ip, count, first_seen, last_seen,
    evidence (dict), explanation, recommendation
"""

from collections import defaultdict
from datetime import timedelta

from .analysis import is_internal

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def make_finding(finding_id, title, severity, ip, timestamps, evidence,
                 explanation, recommendation):
    """Build a finding dictionary in the standard shape."""
    return {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "ip": ip,
        "count": len(timestamps),
        "first_seen": min(timestamps) if timestamps else None,
        "last_seen": max(timestamps) if timestamps else None,
        "evidence": evidence,
        "explanation": explanation,
        "recommendation": recommendation,
    }


def busiest_window(timestamps, minutes):
    """
    Find the time window with the most events.

    Uses a sliding window over sorted timestamps: the right edge moves
    forward one event at a time and the left edge catches up whenever the
    gap is bigger than the window. Returns (count, window_start, window_end).
    """
    if not timestamps:
        return 0, None, None

    times = sorted(timestamps)
    window = timedelta(minutes=minutes)
    best = (1, times[0], times[0])
    left = 0

    for right in range(len(times)):
        while times[right] - times[left] > window:
            left += 1
        count = right - left + 1
        if count > best[0]:
            best = (count, times[left], times[right])

    return best


def group_by_source(records, condition):
    """Return {src_ip: [records]} for records where condition(record) is True."""
    groups = defaultdict(list)
    for record in records:
        if condition(record):
            groups[record["src"]].append(record)
    return groups


# Authentication detections

def detect_brute_force(auth_records, settings):
    """Many failed logins from one IP in a short time."""
    findings = []
    threshold = settings["brute_force_threshold"]
    minutes = settings["brute_force_window_minutes"]
    failures = group_by_source(auth_records, lambda r: r["event"] == "LOGIN_FAILED")

    for ip, records in failures.items():
        times = [record["timestamp"] for record in records]
        peak, start, end = busiest_window(times, minutes)
        if peak < threshold:
            continue

        users = sorted({record["user"] for record in records})
        hosts = sorted({record["host"] for record in records})
        findings.append(make_finding(
            "AUTH-BRUTE-FORCE", "Brute-force login attempts", "HIGH", ip, times,
            {
                "total_failures": len(records),
                "peak_failures_in_window": peak,
                "window_minutes": minutes,
                "peak_window": f"{start:%Y-%m-%d %H:%M} to {end:%H:%M}",
                "targeted_users": users,
                "targeted_hosts": hosts,
            },
            f"{peak} failed logins inside {minutes} minutes is far above normal "
            f"user error and points to an automated password-guessing tool.",
            "Block the source IP at the perimeter, confirm the targeted accounts "
            "use strong passwords or MFA, and check for any later successful login.",
        ))
    return findings


def detect_password_spray(auth_records, settings):
    """One IP failing against several different accounts."""
    findings = []
    min_users = settings["spray_min_users"]
    min_failures = settings["brute_force_threshold"]
    failures = group_by_source(auth_records, lambda r: r["event"] == "LOGIN_FAILED")

    for ip, records in failures.items():
        users = sorted({record["user"] for record in records})
        # Requiring a minimum number of failures stops a staff member who
        # mistyped three different usernames from being flagged.
        if len(users) < min_users or len(records) < min_failures:
            continue

        per_user = defaultdict(int)
        for record in records:
            per_user[record["user"]] += 1

        findings.append(make_finding(
            "AUTH-PASSWORD-SPRAY", "Password spraying across multiple accounts", "HIGH",
            ip, [record["timestamp"] for record in records],
            {"distinct_users": len(users), "failures_per_user": dict(per_user)},
            f"One source tried {len(users)} different accounts. Targeting several "
            f"privileged or generic names (admin, root, service accounts) is a "
            f"classic spraying pattern used to avoid per-account lockouts.",
            "Block the IP, review whether any of the targeted accounts should be "
            "reachable remotely, and disable or rename unused generic accounts.",
        ))
    return findings


def detect_success_after_failures(auth_records, settings):
    """A successful login shortly after repeated failures from the same IP."""
    findings = []
    threshold = settings["success_after_failures_threshold"]
    window = timedelta(minutes=settings["success_after_failures_window_minutes"])

    by_source = group_by_source(
        auth_records, lambda r: r["event"] in ("LOGIN_FAILED", "LOGIN_SUCCESS")
    )

    for ip, records in by_source.items():
        for index, record in enumerate(records):
            if record["event"] != "LOGIN_SUCCESS":
                continue
            # Records are already sorted by time, so only look backwards.
            earlier_failures = [
                previous for previous in records[:index]
                if previous["event"] == "LOGIN_FAILED"
                and record["timestamp"] - previous["timestamp"] <= window
            ]
            if len(earlier_failures) < threshold:
                continue

            same_user = sum(1 for f in earlier_failures if f["user"] == record["user"])
            times = [f["timestamp"] for f in earlier_failures] + [record["timestamp"]]
            findings.append(make_finding(
                "AUTH-SUCCESS-AFTER-FAILURES", "Successful login after repeated failures",
                "CRITICAL", ip, times,
                {
                    "failures_before_success": len(earlier_failures),
                    "failures_for_same_user": same_user,
                    "compromised_user": record["user"],
                    "host": record["host"],
                    "method": record["method"],
                    "success_time": f"{record['timestamp']:%Y-%m-%d %H:%M:%S}",
                },
                f"'{record['user']}' logged in to {record['host']} after "
                f"{len(earlier_failures)} failures from the same IP. The attacker "
                f"most likely guessed the password, so treat this as a probable "
                f"account compromise until proven otherwise.",
                f"Disable or reset '{record['user']}' now, terminate active sessions "
                f"on {record['host']}, and review everything this account did after "
                f"{record['timestamp']:%H:%M}.",
            ))
    return findings


def detect_account_lockouts(auth_records, settings):
    """Accounts that were locked, grouped by user and source."""
    findings = []
    lockouts = defaultdict(list)
    for record in auth_records:
        if record["event"] == "ACCOUNT_LOCKED":
            lockouts[(record["user"], record["src"])].append(record)

    for (user, ip), records in lockouts.items():
        days = sorted({f"{record['timestamp']:%Y-%m-%d}" for record in records})
        findings.append(make_finding(
            "AUTH-ACCOUNT-LOCKOUT", "Account lockouts", "MEDIUM", ip,
            [record["timestamp"] for record in records],
            {"user": user, "lockouts": len(records), "days": days},
            f"'{user}' was locked {len(records)} time(s) on {len(days)} different "
            f"day(s) because of this IP. Lockouts show the control is working, but "
            f"repeated lockouts can also be used to deny service to the real user.",
            "Confirm with the account owner, and consider blocking the source "
            "rather than relying on lockout alone.",
        ))
    return findings


def detect_watchlist_logins(auth_records, watchlist):
    """Successful logins from IPs on the supplied suspicious list."""
    findings = []
    watched = set(watchlist)
    successes = group_by_source(
        auth_records, lambda r: r["event"] == "LOGIN_SUCCESS" and r["src"] in watched
    )

    for ip, records in successes.items():
        users = sorted({record["user"] for record in records})
        findings.append(make_finding(
            "AUTH-WATCHLIST-LOGIN", "Successful login from watchlisted IP", "MEDIUM", ip,
            [record["timestamp"] for record in records],
            {"users": users, "hosts": sorted({record["host"] for record in records})},
            f"A suspicious-list IP successfully authenticated as {', '.join(users)}. "
            f"This may be legitimate, but it needs to be confirmed.",
            "Verify the login with the account owner and check that the "
            "credential (password or SSH key) has not been exposed.",
        ))
    return findings


# Firewall detections

def detect_port_scan(firewall_records, settings):
    """One IP hitting many different ports in a short time."""
    findings = []
    min_ports = settings["port_scan_min_ports"]
    window = timedelta(minutes=settings["port_scan_window_minutes"])
    by_source = group_by_source(firewall_records, lambda r: True)

    for ip, records in by_source.items():
        # Slide a window over this IP's events and track distinct ports.
        best_ports = set()
        best_records = []
        left = 0
        for right in range(len(records)):
            while records[right]["timestamp"] - records[left]["timestamp"] > window:
                left += 1
            current = records[left:right + 1]
            ports = {record["port"] for record in current}
            if len(ports) > len(best_ports):
                best_ports, best_records = ports, current

        if len(best_ports) < min_ports:
            continue

        blocked = sum(1 for record in best_records if record["action"] == "BLOCKED")
        findings.append(make_finding(
            "FW-PORT-SCAN", "Port scan", "HIGH", ip,
            [record["timestamp"] for record in best_records],
            {
                "distinct_ports": len(best_ports),
                "ports": sorted(best_ports),
                "targets": sorted({record["dst"] for record in best_records}),
                "blocked": blocked,
                "window_minutes": settings["port_scan_window_minutes"],
            },
            f"{len(best_ports)} different ports probed inside "
            f"{settings['port_scan_window_minutes']} minutes. This is reconnaissance: "
            f"the attacker is mapping which services are running.",
            "Block the IP and check whether any probed port was ALLOWED, because "
            "those services are now known to the attacker.",
        ))
    return findings


def detect_repeated_blocks(firewall_records, settings):
    """IPs that keep hitting the firewall and getting blocked."""
    findings = []
    threshold = settings["repeated_block_threshold"]
    sensitive = settings["sensitive_ports"]
    blocked = group_by_source(firewall_records, lambda r: r["action"] == "BLOCKED")

    for ip, records in blocked.items():
        if len(records) < threshold:
            continue
        ports = defaultdict(int)
        for record in records:
            ports[record["port"]] += 1
        main_port = max(ports, key=ports.get)
        service = sensitive.get(str(main_port), "")
        label = f"{main_port}/{service}" if service else str(main_port)

        # Only name a "main" port if it really dominates, otherwise the
        # traffic is spread out (typical of a scan) and we say so.
        if ports[main_port] >= len(records) / 2:
            focus = f"mostly to port {label}"
        else:
            focus = f"spread across {len(ports)} different ports"

        findings.append(make_finding(
            "FW-REPEATED-BLOCKS", "Repeated blocked connections", "MEDIUM", ip,
            [record["timestamp"] for record in records],
            {
                "blocked_events": len(records),
                "main_port": main_port,
                "main_port_hits": ports[main_port],
                "targets": sorted({record["dst"] for record in records}),
            },
            f"{len(records)} blocked connections, {focus}. The firewall is "
            f"stopping it, but the source is persistent and deliberately "
            f"targeting the network.",
            "Add the IP to a perimeter deny list and make sure the targeted "
            "service is not exposed anywhere else.",
        ))
    return findings


def detect_external_sensitive_access(firewall_records, settings, hostile_ips):
    """
    External traffic ALLOWED through to sensitive ports.

    Two levels, to avoid flooding the report with one-off connections:
      - one exposure finding per service (a firewall policy problem), which
        is not tied to a single IP so it does not inflate IP scores
      - a per-IP HIGH finding only when the source is already hostile
        somewhere else (another finding or on the suspicious list)
    """
    findings = []
    sensitive = settings["sensitive_ports"]
    internal = settings["internal_networks"]

    by_port = defaultdict(list)
    for record in firewall_records:
        if (record["action"] == "ALLOWED"
                and str(record["port"]) in sensitive
                and not is_internal(record["src"], internal)):
            by_port[record["port"]].append(record)

    for port, records in sorted(by_port.items()):
        service = sensitive[str(port)]
        sources = sorted({record["src"] for record in records})
        findings.append(make_finding(
            "FW-SENSITIVE-SERVICE-EXPOSED", f"{service} reachable from the internet",
            "MEDIUM", f"{len(sources)} sources", [record["timestamp"] for record in records],
            {
                "port": port,
                "external_sources": len(sources),
                "targets": sorted({record["dst"] for record in records}),
            },
            f"The firewall allowed {len(records)} external connection(s) to {service} "
            f"(port {port}) from {len(sources)} different address(es). Each one alone "
            f"looks harmless, but together they show the rule is open to anyone, "
            f"which is the real problem.",
            f"Restrict {service} to VPN or internal ranges only.",
        ))

        # Escalate the sources that are also attacking us in other ways.
        for ip in sources:
            if ip not in hostile_ips:
                continue
            hits = [record for record in records if record["src"] == ip]
            findings.append(make_finding(
                "FW-HOSTILE-SENSITIVE-ALLOWED", f"Hostile IP reached {service}", "HIGH",
                ip, [record["timestamp"] for record in hits],
                {
                    "port": port,
                    "targets": sorted({record["dst"] for record in hits}),
                    "bytes": sum(record["bytes"] for record in hits),
                },
                f"This IP is already flagged for other hostile activity and was "
                f"ALLOWED through to {service}. A successful connection from a known "
                f"attacker to a remote-access or file-sharing service is a possible "
                f"foothold.",
                f"Check {service} session logs on the target host for this time and "
                f"block the IP.",
            ))
    return findings


def run_all_detections(firewall_records, auth_records, watchlist, settings):
    """Run every detection and return findings sorted by severity then size."""
    findings = []
    findings += detect_success_after_failures(auth_records, settings)
    findings += detect_brute_force(auth_records, settings)
    findings += detect_password_spray(auth_records, settings)
    findings += detect_account_lockouts(auth_records, settings)
    findings += detect_port_scan(firewall_records, settings)
    findings += detect_repeated_blocks(firewall_records, settings)

    # A watchlist login is already covered if the same IP is a probable
    # compromise, so only add it for IPs without that finding.
    compromised = {f["ip"] for f in findings if f["id"] == "AUTH-SUCCESS-AFTER-FAILURES"}
    findings += [f for f in detect_watchlist_logins(auth_records, watchlist)
                 if f["ip"] not in compromised]

    # Needs the earlier findings to know which IPs are already hostile.
    hostile_ips = {f["ip"] for f in findings} | set(watchlist)
    findings += detect_external_sensitive_access(firewall_records, settings, hostile_ips)

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), -f["count"]))
    return findings
