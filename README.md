# SOC Log Investigator

COMP H2702 Scripting for Cybersecurity, Individual Project, **Scenario A: Security Log Investigation**

A Python command-line tool that reads a firewall log and an authentication log, detects attack patterns, ranks the suspicious IPs by risk, and writes an investigation report for a SOC analyst (console + TXT + JSON + CSV).

## What problem it solves

Raw logs are too big to read line by line. A brute-force attack, a port scan and a successful break-in can all be sitting in 1,400 lines next to normal traffic. This tool turns the logs into a short, ranked list of what needs attention first, with the evidence and a recommended action for each finding.

## Features

- Parses both logs from file, validates every field (timestamp, IP, port, action, event) and **skips malformed lines without crashing**, listing each rejected line and the reason in a data-quality section
- Firewall summary: valid events, ALLOWED/BLOCKED counts, unique sources (internal vs external), top blocked source IPs, most targeted and most blocked ports
- Authentication summary: LOGIN_SUCCESS / LOGIN_FAILED / ACCOUNT_LOCKED / LOGOUT counts, failure rate, top failing IPs, most targeted usernames, lockouts, failures per host
- Detections:
  | Detection | Severity | Logic |
  |---|---|---|
  | Successful login after repeated failures | CRITICAL | a success preceded by 5+ failures from the same IP within 60 min |
  | Brute force | HIGH | 10+ failed logins from one IP inside a 60 min sliding window |
  | Password spraying | HIGH | one IP failing against 3+ different accounts (and 10+ failures) |
  | Port scan | HIGH | one IP hitting 10+ distinct ports inside 30 min |
  | Hostile IP reached a sensitive service | HIGH | an already-flagged IP was ALLOWED to RDP/SMB/SSH etc. |
  | Repeated blocked connections | MEDIUM | 20+ blocked events from one IP |
  | Sensitive service reachable from internet | MEDIUM | external traffic allowed to RDP/SMB etc. (firewall policy issue) |
  | Account lockouts | MEDIUM | grouped by user and source |
  | Successful login from watchlisted IP | MEDIUM | success from an IP on `suspicious_ips.txt` |
- Per-IP **risk score** (severity points + watchlist bonus + cross-log correlation bonus) mapped to CRITICAL / HIGH / MEDIUM / LOW and sorted highest first
- **Analyst observations** generated from the actual results, not hard-coded
- All thresholds are configurable through a JSON file, no code changes needed

## Project structure

```
soc-log-investigator/
├── investigate.py              # entry point: CLI arguments, runs the pipeline
├── log_investigator/
│   ├── config.py               # default thresholds + loading a JSON override
│   ├── parsers.py              # reading files, parsing and validating lines
│   ├── analysis.py             # summary statistics for each log
│   ├── detections.py           # attack-pattern detections -> findings
│   ├── risk.py                 # per-IP scoring and ranking
│   └── report.py               # console/TXT report, JSON and CSV export
├── tests/test_investigator.py  # unit + end-to-end tests
├── data/                       # supplied synthetic dataset
│   ├── firewall.log
│   ├── authentication.log
│   └── suspicious_ips.txt
├── settings.example.json       # example threshold override
└── requirements.txt            # standard library only
```

Pipeline: **load + parse** (`parsers.py`) → **summarise** (`analysis.py`) → **detect** (`detections.py`) → **score + rank** (`risk.py`) → **report** (`report.py`).

## Setup

Requires **Python 3.8+**. No third-party packages are needed.

```bash
git clone <this-repo-url>
cd soc-log-investigator
python3 --version
```

## How to run

Run with the supplied data (default paths):

```bash
python3 investigate.py
```

All options:

```bash
python3 investigate.py --firewall data/firewall.log \
                       --auth data/authentication.log \
                       --watchlist data/suspicious_ips.txt \
                       --config settings.example.json \
                       --output output
```

| Option | Default | Purpose |
|---|---|---|
| `--firewall` | `data/firewall.log` | firewall log to analyse |
| `--auth` | `data/authentication.log` | authentication log to analyse |
| `--watchlist` | `data/suspicious_ips.txt` | suspicious IP list (`--watchlist ""` to skip) |
| `--config` | none | JSON file overriding detection thresholds |
| `--output` | `output` | folder for the saved reports |
| `--quiet` | off | only print the saved file paths |

On Windows use `python` instead of `python3`.

## Output

The full report is printed to the console and saved to the output folder:

| File | Contents |
|---|---|
| `investigation_report.txt` | the full readable report (same as console) |
| `investigation_report.json` | everything in structured form, including settings used |
| `ip_risk_ranking.csv` | ranked IPs with score, risk level and activity counts |
| `findings.csv` | every finding with severity, evidence window, explanation and action |

## Input format

```
firewall.log:        <date> <time> <ALLOWED|BLOCKED> src=<IP> dst=<IP> proto=<TCP|UDP> port=<port> bytes=<n>
authentication.log:  <date> <time> <EVENT> user=<name> src=<IP> host=<host> method=<method>
suspicious_ips.txt:  one IP per line, # for comments
```

## Error handling

| Situation | Behaviour |
|---|---|
| Malformed / incomplete line | skipped, line number + reason listed in the Data quality section |
| One log file missing or unreadable | warning, the other log is still analysed |
| Both logs missing | clear error message, exit code 1 |
| Watchlist missing or contains bad IPs | warning, bad entries skipped, duplicates removed |
| Config file missing, invalid JSON, unknown key or wrong type | warning, defaults kept |
| Output folder cannot be created | clear error message, exit code 1 |
| Ctrl+C | clean exit message |

## Tests

```bash
python3 -m unittest discover -s tests -v
```

20 tests cover parsing of valid and malformed lines, missing files, watchlist cleaning, each main detection (including a slow attack that should NOT trigger), risk levels, config fallback, and a full end-to-end run.

## Notes

- All data is synthetic teaching data. The public-looking IPs use documentation ranges and are never contacted. The tool only reads files.
- No API keys, credentials or personal data are used or stored.
- Detections are threshold based: they can miss slow attacks (false negatives) and can flag busy legitimate users or shared NAT addresses (false positives). Findings are leads to confirm, not proof.
