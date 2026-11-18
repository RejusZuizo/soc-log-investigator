"""
Per-IP risk scoring.

Every IP that triggered a finding gets a score:
    + points for each finding, based on its severity
    + bonus if the IP is on the supplied suspicious list
    + bonus if the IP shows hostile activity in BOTH logs (correlation)

The score is then mapped to CRITICAL / HIGH / MEDIUM / LOW using the
thresholds in the settings, and the list is sorted highest first so an
analyst knows where to start.
"""

import ipaddress
from collections import defaultdict


def _is_ip(value):
    """True if value is a valid IP address string."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def classify_risk(score, levels):
    """Return the risk level for a score, checking the highest level first."""
    for level, minimum in sorted(levels.items(), key=lambda item: item[1], reverse=True):
        if score >= minimum:
            return level
    return "NONE"


def activity_by_ip(firewall_records, auth_records):
    """Count the events per IP in each log so the report can show context."""
    activity = defaultdict(lambda: {
        "fw_events": 0, "fw_blocked": 0, "fw_allowed": 0,
        "auth_failed": 0, "auth_success": 0, "auth_locked": 0,
    })
    for record in firewall_records:
        entry = activity[record["src"]]
        entry["fw_events"] += 1
        if record["action"] == "BLOCKED":
            entry["fw_blocked"] += 1
        else:
            entry["fw_allowed"] += 1
    for record in auth_records:
        entry = activity[record["src"]]
        if record["event"] == "LOGIN_FAILED":
            entry["auth_failed"] += 1
        elif record["event"] == "LOGIN_SUCCESS":
            entry["auth_success"] += 1
        elif record["event"] == "ACCOUNT_LOCKED":
            entry["auth_locked"] += 1
    return activity


def score_ips(findings, firewall_records, auth_records, watchlist, settings):
    """
    Build the ranked list of risky IPs.

    Returns (ranked_ips, watchlist_status). watchlist_status records
    whether each supplied suspicious IP was actually seen in the logs.
    """
    points = settings["severity_points"]
    activity = activity_by_ip(firewall_records, auth_records)
    watched = set(watchlist)

    # Group findings per IP. Policy-level findings (e.g. "RDP reachable from
    # the internet") are not about one address, so they are not scored here.
    findings_by_ip = defaultdict(list)
    for finding in findings:
        if _is_ip(finding["ip"]):
            findings_by_ip[finding["ip"]].append(finding)

    # Watchlisted IPs with hostile activity are scored even without a finding.
    candidates = set(findings_by_ip)
    for ip in watched:
        info = activity.get(ip)
        if info and (info["fw_blocked"] or info["auth_failed"]):
            candidates.add(ip)

    ranked = []
    for ip in candidates:
        info = dict(activity.get(ip, {}))
        ip_findings = findings_by_ip.get(ip, [])
        score = sum(points.get(f["severity"], 0) for f in ip_findings)
        reasons = [f["title"] for f in ip_findings]

        on_watchlist = ip in watched
        if on_watchlist:
            score += settings["watchlist_points"]
            reasons.append("On suspicious IP list")

        # Hostile in both logs = the same actor is probing the network AND
        # attacking logins, which is stronger evidence than either alone.
        hostile_fw = info.get("fw_blocked", 0) > 0
        hostile_auth = info.get("auth_failed", 0) > 0 or info.get("auth_locked", 0) > 0
        correlated = hostile_fw and hostile_auth
        if correlated:
            score += settings["cross_log_points"]
            reasons.append("Hostile in both firewall and auth logs")

        ranked.append({
            "ip": ip,
            "score": score,
            "risk": classify_risk(score, settings["risk_levels"]),
            "on_watchlist": on_watchlist,
            "cross_log": correlated,
            "finding_count": len(ip_findings),
            "reasons": reasons,
            **{key: info.get(key, 0) for key in (
                "fw_events", "fw_blocked", "fw_allowed",
                "auth_failed", "auth_success", "auth_locked")},
        })

    ranked.sort(key=lambda item: (-item["score"], item["ip"]))

    watchlist_status = []
    for ip in watchlist:
        info = activity.get(ip)
        seen = info is not None
        watchlist_status.append({
            "ip": ip,
            "seen_in_logs": seen,
            "fw_events": info["fw_events"] if seen else 0,
            "auth_events": (info["auth_failed"] + info["auth_success"] + info["auth_locked"]) if seen else 0,
        })

    return ranked, watchlist_status
