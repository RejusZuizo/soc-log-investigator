"""
Summary statistics for each log.

These functions answer the "what happened" questions (counts, top
talkers, top ports). The detections module answers "what looks malicious".
"""

import ipaddress
from collections import Counter


def is_internal(ip, internal_networks):
    """Return True if the IP falls inside one of the configured internal networks."""
    address = ipaddress.ip_address(ip)
    for network in internal_networks:
        try:
            if address in ipaddress.ip_network(network, strict=False):
                return True
        except ValueError:
            # A bad network string in the config should not stop the run.
            continue
    return False


def analyse_firewall(records, settings):
    """Build the firewall summary from parsed firewall records."""
    top_n = settings["top_n"]
    internal = settings["internal_networks"]
    sensitive = settings["sensitive_ports"]

    actions = Counter(record["action"] for record in records)
    protocols = Counter(record["proto"] for record in records)
    all_ports = Counter(record["port"] for record in records)

    blocked = [record for record in records if record["action"] == "BLOCKED"]
    blocked_sources = Counter(record["src"] for record in blocked)
    blocked_ports = Counter(record["port"] for record in blocked)

    sources = {record["src"] for record in records}
    external_sources = {ip for ip in sources if not is_internal(ip, internal)}

    # Blocked traffic aimed at services that should never face the internet.
    sensitive_blocked = Counter(
        record["port"] for record in blocked if str(record["port"]) in sensitive
    )

    def port_rows(counter):
        """Turn a port Counter into rows with a service name where we know it."""
        return [
            {"port": port, "service": sensitive.get(str(port), ""), "count": count}
            for port, count in counter.most_common(top_n)
        ]

    timestamps = [record["timestamp"] for record in records]

    return {
        "valid_events": len(records),
        "allowed": actions.get("ALLOWED", 0),
        "blocked": actions.get("BLOCKED", 0),
        "block_rate": round(100 * actions.get("BLOCKED", 0) / len(records), 1) if records else 0.0,
        "unique_sources": len(sources),
        "unique_external_sources": len(external_sources),
        "unique_destinations": len({record["dst"] for record in records}),
        "protocols": dict(protocols),
        "top_blocked_sources": [
            {"ip": ip, "count": count, "external": ip in external_sources}
            for ip, count in blocked_sources.most_common(top_n)
        ],
        "top_targeted_ports": port_rows(all_ports),
        "top_blocked_ports": port_rows(blocked_ports),
        "sensitive_ports_blocked": port_rows(sensitive_blocked),
        "first_event": min(timestamps) if timestamps else None,
        "last_event": max(timestamps) if timestamps else None,
    }


def analyse_auth(records, settings):
    """Build the authentication summary from parsed auth records."""
    top_n = settings["top_n"]

    events = Counter(record["event"] for record in records)
    failed = [record for record in records if record["event"] == "LOGIN_FAILED"]
    locked = [record for record in records if record["event"] == "ACCOUNT_LOCKED"]

    failed_sources = Counter(record["src"] for record in failed)
    failed_users = Counter(record["user"] for record in failed)
    failed_hosts = Counter(record["host"] for record in failed)
    failed_methods = Counter(record["method"] for record in failed)
    locked_users = Counter(record["user"] for record in locked)

    attempts = events.get("LOGIN_SUCCESS", 0) + events.get("LOGIN_FAILED", 0)
    timestamps = [record["timestamp"] for record in records]

    return {
        "valid_events": len(records),
        "login_success": events.get("LOGIN_SUCCESS", 0),
        "login_failed": events.get("LOGIN_FAILED", 0),
        "account_locked": events.get("ACCOUNT_LOCKED", 0),
        "logout": events.get("LOGOUT", 0),
        "failure_rate": round(100 * events.get("LOGIN_FAILED", 0) / attempts, 1) if attempts else 0.0,
        "unique_sources": len({record["src"] for record in records}),
        "top_failed_sources": [
            {"ip": ip, "count": count} for ip, count in failed_sources.most_common(top_n)
        ],
        "top_failed_users": [
            {"user": user, "count": count} for user, count in failed_users.most_common(top_n)
        ],
        "failed_by_host": dict(failed_hosts.most_common()),
        "failed_by_method": dict(failed_methods.most_common()),
        "locked_accounts": [
            {"user": user, "count": count} for user, count in locked_users.most_common()
        ],
        "first_event": min(timestamps) if timestamps else None,
        "last_event": max(timestamps) if timestamps else None,
    }
