"""
Detection thresholds and risk settings.

All values here are defaults. They can be overridden without touching the
code by passing a JSON file with --config (see settings.example.json).
"""

import json

DEFAULT_SETTINGS = {
    # Networks we treat as "ours". Anything else is external.
    "internal_networks": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],

    # Services that should not normally be reachable from the internet.
    "sensitive_ports": {
        "21": "FTP",
        "22": "SSH",
        "23": "Telnet",
        "445": "SMB",
        "1433": "MSSQL",
        "3306": "MySQL",
        "3389": "RDP",
        "5900": "VNC",
    },

    # Brute force: this many failed logins from one IP inside the window.
    "brute_force_threshold": 10,
    "brute_force_window_minutes": 60,

    # Password spraying: one IP failing against this many different accounts.
    "spray_min_users": 3,

    # Possible compromise: a success that follows at least this many
    # failures from the same IP within the window.
    "success_after_failures_threshold": 5,
    "success_after_failures_window_minutes": 60,

    # Port scan: one IP touching this many different ports inside the window.
    "port_scan_min_ports": 10,
    "port_scan_window_minutes": 30,

    # Repeated blocked traffic from one IP.
    "repeated_block_threshold": 20,

    # How many rows to show in "top N" tables.
    "top_n": 5,

    # Points added to an IP's risk score per finding severity.
    "severity_points": {"CRITICAL": 50, "HIGH": 30, "MEDIUM": 15, "LOW": 5},

    # Extra points for context.
    "watchlist_points": 20,
    "cross_log_points": 10,

    # Score needed to reach each risk level (checked from the top down).
    "risk_levels": {"CRITICAL": 80, "HIGH": 50, "MEDIUM": 20, "LOW": 1},
}


def load_settings(config_path=None):
    """
    Return the settings dictionary.

    Starts from DEFAULT_SETTINGS and applies any overrides found in the
    JSON file. A missing or broken config file is not fatal: we warn and
    keep the defaults so the investigation still runs.
    """
    # Copy so the defaults are never modified by accident.
    settings = json.loads(json.dumps(DEFAULT_SETTINGS))
    warnings = []

    if config_path is None:
        return settings, warnings

    try:
        with open(config_path, "r", encoding="utf-8") as handle:
            overrides = json.load(handle)
    except FileNotFoundError:
        warnings.append(f"Config file '{config_path}' not found, using defaults.")
        return settings, warnings
    except json.JSONDecodeError as error:
        warnings.append(
            f"Config file '{config_path}' is not valid JSON "
            f"(line {error.lineno}), using defaults."
        )
        return settings, warnings
    except OSError as error:
        warnings.append(f"Could not read config '{config_path}': {error}. Using defaults.")
        return settings, warnings

    if not isinstance(overrides, dict):
        warnings.append("Config file must contain a JSON object, using defaults.")
        return settings, warnings

    for key, value in overrides.items():
        if key not in settings:
            warnings.append(f"Unknown config key '{key}' ignored.")
        elif type(value) is not type(settings[key]):
            warnings.append(
                f"Config key '{key}' should be {type(settings[key]).__name__}, "
                f"got {type(value).__name__}. Default kept."
            )
        else:
            settings[key] = value

    return settings, warnings
