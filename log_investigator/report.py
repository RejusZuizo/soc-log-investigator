"""
Report generation: console/TXT text report, JSON and CSV exports.

The text report is built once as a list of lines, then printed to the
console and written to investigation_report.txt, so both always match.
"""

import csv
import json
from datetime import datetime
from pathlib import Path

WIDTH = 78


def _heading(title):
    return ["", "=" * WIDTH, title.upper(), "=" * WIDTH]


def _subheading(title):
    return ["", title, "-" * len(title)]


def _table(headers, rows):
    """Return a simple fixed-width text table as a list of lines."""
    if not rows:
        return ["  (none)"]
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    line = "  " + "  ".join(f"{h:<{widths[i]}}" for i, h in enumerate(headers))
    lines = [line, "  " + "  ".join("-" * w for w in widths)]
    for row in rows:
        lines.append("  " + "  ".join(f"{str(c):<{widths[i]}}" for i, c in enumerate(row)))
    return lines


def _fmt_time(value):
    return value.strftime("%Y-%m-%d %H:%M") if value else "-"


def _wrap(text, indent="    "):
    """Very small word-wrapper so long explanations stay readable."""
    words, lines, current = text.split(), [], indent
    for word in words:
        if len(current) + len(word) + 1 > WIDTH:
            lines.append(current.rstrip())
            current = indent
        current += word + " "
    if current.strip():
        lines.append(current.rstrip())
    return lines


def build_observations(results):
    """
    Produce analyst observations from the actual numbers.

    Nothing here is hard-coded to the sample data: each observation is
    only added if the condition is true in the current results.
    """
    observations = []
    fw = results.get("firewall")
    findings = results["findings"]
    ranked = results["ranked_ips"]

    compromises = [f for f in findings if f["id"] == "AUTH-SUCCESS-AFTER-FAILURES"]
    for f in compromises:
        e = f["evidence"]
        observations.append(
            f"PROBABLE COMPROMISE: {f['ip']} failed {e['failures_before_success']} times "
            f"then logged in as '{e['compromised_user']}' on {e['host']} at "
            f"{e['success_time']}. This is the highest priority item in the report."
        )

    if fw and fw["top_blocked_ports"] and fw["blocked"]:
        top = fw["top_blocked_ports"][0]
        share = round(100 * top["count"] / fw["blocked"], 1)
        name = f" ({top['service']})" if top["service"] else ""
        observations.append(
            f"Port {top['port']}{name} is the most attacked service: {top['count']} of "
            f"{fw['blocked']} blocked events ({share}%). Remote-access services are the "
            f"main target, so they need MFA, key-only auth and source restrictions."
        )

    if fw and fw["top_blocked_sources"] and fw["blocked"]:
        top = fw["top_blocked_sources"][0]
        share = round(100 * top["count"] / fw["blocked"], 1)
        group = fw["top_blocked_sources"]
        group_share = round(100 * sum(r["count"] for r in group) / fw["blocked"], 1)
        observations.append(
            f"Blocked traffic is concentrated: {top['ip']} alone caused {top['count']} "
            f"blocks ({share}%), and the top {len(group)} sources caused {group_share}% "
            f"of the {fw['blocked']} blocks out of {fw['unique_sources']} sources seen. "
            f"Blocking a handful of persistent IPs removes a large share of the noise."
        )

    sprays = [f for f in findings if f["id"] == "AUTH-PASSWORD-SPRAY"]
    if sprays:
        names = ", ".join(sorted({u for f in sprays for u in f["evidence"]["failures_per_user"]}))
        observations.append(
            f"Privileged and generic accounts are targeted ({names}). Attackers try "
            f"names that exist on most systems, so these accounts should be disabled, "
            f"renamed or blocked from remote login."
        )

    correlated = [r for r in ranked if r["cross_log"]]
    if correlated:
        observations.append(
            f"{len(correlated)} IP(s) are hostile in BOTH logs "
            f"({', '.join(r['ip'] for r in correlated)}): blocked at the firewall AND "
            f"failing logins. Each log on its own understates these actors, which is "
            f"why correlating them matters."
        )

    lockouts = [f for f in findings if f["id"] == "AUTH-ACCOUNT-LOCKOUT"]
    for f in lockouts:
        days = len(f["evidence"]["days"])
        if days > 1:
            observations.append(
                f"'{f['evidence']['user']}' was locked out on {days} separate days by "
                f"{f['ip']}. The attacker keeps returning after each lockout resets, so "
                f"lockout slows guessing but does not stop it, and it also locks the real "
                f"user out (a denial-of-service side effect)."
            )

    status = results["watchlist_status"]
    if status:
        seen = sum(1 for s in status if s["seen_in_logs"])
        observations.append(
            f"{seen} of {len(status)} suspicious-list IPs appear in the logs. A list "
            f"match is supporting context, not proof: IPs get reassigned and lists go "
            f"stale, so the behaviour in the logs is what drives the risk score."
        )

    return observations


def build_text_report(results):
    """Build the full human-readable report as a list of lines."""
    lines = []
    meta = results["meta"]
    fw = results.get("firewall")
    auth = results.get("auth")
    findings = results["findings"]
    ranked = results["ranked_ips"]

    lines += ["=" * WIDTH, "SOC LOG INVESTIGATION REPORT".center(WIDTH), "=" * WIDTH]
    lines.append(f"  Generated:      {meta['generated']}")
    lines.append(f"  Firewall log:   {meta['firewall_path']}")
    lines.append(f"  Auth log:       {meta['auth_path']}")
    lines.append(f"  Watchlist:      {meta['watchlist_path'] or 'not used'}")

    # Executive summary
    lines += _heading("Executive summary")
    counts = {level: 0 for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    lines.append(
        f"  Findings: {len(findings)} total  |  "
        + "  ".join(f"{k}: {v}" for k, v in counts.items())
    )
    risky = [r for r in ranked if r["risk"] in ("CRITICAL", "HIGH")]
    lines.append(f"  IPs needing action (CRITICAL/HIGH): {len(risky)}")
    if ranked:
        lines.append("")
        lines.append("  Start here:")
        for i, r in enumerate(ranked[:3], start=1):
            lines.append(f"   {i}. {r['ip']:<16} {r['risk']:<9} score {r['score']:<4} "
                         f"{'; '.join(r['reasons'][:2])}")

    # Firewall summary
    lines += _heading("Firewall log summary")
    if fw:
        lines.append(f"  Valid events:        {fw['valid_events']}")
        lines.append(f"  ALLOWED / BLOCKED:   {fw['allowed']} / {fw['blocked']}  "
                     f"({fw['block_rate']}% blocked)")
        lines.append(f"  Unique source IPs:   {fw['unique_sources']} "
                     f"({fw['unique_external_sources']} external)")
        lines.append(f"  Unique destinations: {fw['unique_destinations']}")
        lines.append("  Protocols:           "
                     + ", ".join(f"{k} {v}" for k, v in fw["protocols"].items()))
        lines.append(f"  Time range:          {_fmt_time(fw['first_event'])} to "
                     f"{_fmt_time(fw['last_event'])}")
        lines += _subheading("Top blocked source IPs")
        lines += _table(["IP", "Blocked", "External"],
                        [[r["ip"], r["count"], "yes" if r["external"] else "no"]
                         for r in fw["top_blocked_sources"]])
        lines += _subheading("Most targeted destination ports (all traffic)")
        lines += _table(["Port", "Service", "Events"],
                        [[r["port"], r["service"] or "-", r["count"]]
                         for r in fw["top_targeted_ports"]])
        lines += _subheading("Most blocked destination ports")
        lines += _table(["Port", "Service", "Blocked"],
                        [[r["port"], r["service"] or "-", r["count"]]
                         for r in fw["top_blocked_ports"]])
    else:
        lines.append("  Firewall log could not be loaded, section skipped.")

    # Authentication summary
    lines += _heading("Authentication log summary")
    if auth:
        lines.append(f"  Valid events:      {auth['valid_events']}")
        lines.append(f"  LOGIN_SUCCESS:     {auth['login_success']}")
        lines.append(f"  LOGIN_FAILED:      {auth['login_failed']}  "
                     f"({auth['failure_rate']}% of login attempts)")
        lines.append(f"  ACCOUNT_LOCKED:    {auth['account_locked']}")
        lines.append(f"  LOGOUT:            {auth['logout']}")
        lines.append(f"  Time range:        {_fmt_time(auth['first_event'])} to "
                     f"{_fmt_time(auth['last_event'])}")
        lines += _subheading("Top failed-login source IPs")
        lines += _table(["IP", "Failures"],
                        [[r["ip"], r["count"]] for r in auth["top_failed_sources"]])
        lines += _subheading("Most targeted usernames")
        lines += _table(["User", "Failures"],
                        [[r["user"], r["count"]] for r in auth["top_failed_users"]])
        lines += _subheading("Locked accounts")
        lines += _table(["User", "Lockouts"],
                        [[r["user"], r["count"]] for r in auth["locked_accounts"]])
        lines += _subheading("Failures by host")
        lines += _table(["Host", "Failures"], [[k, v] for k, v in auth["failed_by_host"].items()])
    else:
        lines.append("  Authentication log could not be loaded, section skipped.")

    # Ranked IPs
    lines += _heading("Ranked IP risk")
    lines += _table(
        ["#", "IP", "Risk", "Score", "FW blk", "Auth fail", "Auth ok", "Watchlist"],
        [[i, r["ip"], r["risk"], r["score"], r["fw_blocked"], r["auth_failed"],
          r["auth_success"], "yes" if r["on_watchlist"] else "no"]
         for i, r in enumerate(ranked, start=1)],
    )

    # Findings
    lines += _heading("Findings (most severe first)")
    if not findings:
        lines.append("  No findings.")
    for i, f in enumerate(findings, start=1):
        lines.append("")
        lines.append(f"  [{i}] {f['severity']} - {f['title']} - {f['ip']}")
        lines.append(f"      Events: {f['count']}   Seen: {_fmt_time(f['first_seen'])} "
                     f"to {_fmt_time(f['last_seen'])}")
        evidence = "; ".join(
            f"{k}={', '.join(map(str, v)) if isinstance(v, list) else v}"
            for k, v in f["evidence"].items() if not isinstance(v, dict)
        )
        lines += _wrap(f"Evidence: {evidence}", indent="      ")
        lines += _wrap(f"Why it matters: {f['explanation']}", indent="      ")
        lines += _wrap(f"Action: {f['recommendation']}", indent="      ")

    # Observations
    lines += _heading("Analyst observations")
    for i, text in enumerate(results["observations"], start=1):
        wrapped = _wrap(text, indent="     ")
        wrapped[0] = f"  {i}. " + wrapped[0].lstrip()
        lines += wrapped

    # Watchlist
    lines += _heading("Suspicious IP list check")
    lines += _table(["IP", "Seen", "FW events", "Auth events"],
                    [[s["ip"], "yes" if s["seen_in_logs"] else "no",
                      s["fw_events"], s["auth_events"]] for s in results["watchlist_status"]])

    # Data quality
    lines += _heading("Data quality")
    for name, key in (("Firewall", "firewall_quality"), ("Auth", "auth_quality")):
        quality = results.get(key)
        if not quality:
            continue
        lines.append(f"  {name}: {quality['total_lines']} lines, "
                     f"{quality['valid']} valid, {len(quality['rejected'])} rejected, "
                     f"{quality['blank_lines']} blank")
        for bad in quality["rejected"]:
            lines.append(f"    line {bad['line']}: {bad['reason']}")
    for warning in results["warnings"]:
        lines.append(f"  WARNING: {warning}")

    lines += _heading("Limitations")
    lines += _wrap(
        "Detections are threshold based, so a slow attack that stays under the "
        "thresholds will be missed (false negative), and a busy legitimate user or "
        "shared NAT address can be flagged (false positive). Source IPs can be "
        "spoofed or shared. Findings should be confirmed against host logs before "
        "action is taken.", indent="  ")
    lines.append("")
    return lines


def _json_default(value):
    """Let json.dump handle datetime objects."""
    if isinstance(value, datetime):
        return value.isoformat(sep=" ")
    raise TypeError(f"Cannot serialise {type(value).__name__}")


def write_reports(results, text_lines, output_dir):
    """
    Save TXT, JSON and CSV reports into output_dir.

    Returns the list of files written. Raises OSError with a clear message
    if the folder cannot be created or written to.
    """
    folder = Path(output_dir)
    try:
        folder.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise OSError(f"Cannot create output folder '{folder}': {error}")

    written = []

    txt_path = folder / "investigation_report.txt"
    txt_path.write_text("\n".join(text_lines), encoding="utf-8")
    written.append(txt_path)

    json_path = folder / "investigation_report.json"
    export = {key: value for key, value in results.items()}
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(export, handle, indent=2, default=_json_default)
    written.append(json_path)

    risk_path = folder / "ip_risk_ranking.csv"
    with open(risk_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["rank", "ip", "risk", "score", "fw_blocked", "fw_allowed",
                         "auth_failed", "auth_success", "auth_locked",
                         "on_watchlist", "cross_log", "reasons"])
        for i, r in enumerate(results["ranked_ips"], start=1):
            writer.writerow([i, r["ip"], r["risk"], r["score"], r["fw_blocked"],
                             r["fw_allowed"], r["auth_failed"], r["auth_success"],
                             r["auth_locked"], r["on_watchlist"], r["cross_log"],
                             " | ".join(r["reasons"])])
    written.append(risk_path)

    findings_path = folder / "findings.csv"
    with open(findings_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["severity", "id", "title", "ip", "events", "first_seen",
                         "last_seen", "explanation", "recommendation"])
        for f in results["findings"]:
            writer.writerow([f["severity"], f["id"], f["title"], f["ip"], f["count"],
                             _fmt_time(f["first_seen"]), _fmt_time(f["last_seen"]),
                             f["explanation"], f["recommendation"]])
    written.append(findings_path)

    return written
