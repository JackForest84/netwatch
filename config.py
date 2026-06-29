"""Configuration.

Endpoints/usernames come from environment variables (see `.env.example`).
Credentials are read from files in `CONFIG_DIR` (keep them root-owned, mode 0600)
or from `NETWATCH_*` env vars — so no secret is ever hard-coded or committed.
"""

from __future__ import annotations
import os
import secrets
from pathlib import Path

CONFIG_DIR = Path(os.getenv("NETWATCH_CONFIG_DIR", "/etc/netwatch"))


def _load_secret(name: str) -> str | None:
    """Read a credential from an env var (NETWATCH_<NAME>) or CONFIG_DIR/<name>."""
    env = os.getenv("NETWATCH_" + name.upper().replace(".", "_").replace("-", "_"))
    if env:
        return env
    p = CONFIG_DIR / name
    return p.read_text().strip() if p.exists() else None


def _env(name: str, default: str) -> str:
    return os.getenv(name, default)


# UniFi Network Integration API
UNIFI_URL = _env("UNIFI_URL", "https://192.168.1.1:11443")
UNIFI_API_KEY = _load_secret("unifi.key")
UNIFI_SITE_ID = _env("UNIFI_SITE_ID", "")          # your UniFi site UUID
UNIFI_SITE_NAME = _env("UNIFI_SITE_NAME", "Default")
UNIFI_VERIFY_TLS = _env("UNIFI_VERIFY_TLS", "false").lower() == "true"

# MikroTik RouterOS 7.x REST API
MIKROTIK_URL = _env("MIKROTIK_URL", "https://192.168.1.1")
MIKROTIK_USER = _env("MIKROTIK_USER", "dashboard")  # read-only API user
MIKROTIK_PASS = _load_secret("mikrotik.cred")
MIKROTIK_VERIFY_TLS = _env("MIKROTIK_VERIFY_TLS", "false").lower() == "true"

# UniFi legacy API (cookie-based login) — per-AP signal/retry/DPI
UNIFI_LEGACY_USER = _load_secret("unifi.user")
UNIFI_LEGACY_PASS = _load_secret("unifi.pass")
UNIFI_LEGACY_SITE = _env("UNIFI_LEGACY_SITE", "default")

# Threat intel (free API tiers)
VIRUSTOTAL_API_KEY = _load_secret("vt.key")
ABUSEIPDB_API_KEY = _load_secret("abuseipdb.key")

# Anthropic (optional — AI alert explanations; without a key the feature is off)
ANTHROPIC_API_KEY = _load_secret("anthropic.key")

# ntopng REST API (form-based login)
NTOPNG_URL = _env("NTOPNG_URL", "http://127.0.0.1:3000")
NTOPNG_USER = _env("NTOPNG_USER", "admin")
NTOPNG_PASS = _load_secret("ntopng.cred")
NTOPNG_IFID = int(_env("NTOPNG_IFID", "0"))

# ntfy (self-hosted push)
NTFY_URL = _env("NTFY_URL", "http://127.0.0.1:8090")
NTFY_TOPIC_SECURITY = _env("NTFY_TOPIC_SECURITY", "netwatch-security")
NTFY_TOPIC_INFO = _env("NTFY_TOPIC_INFO", "netwatch-info")
NTFY_USER = _env("NTFY_USER", "admin")
NTFY_PASS = _load_secret("ntfy-admin.pass")

# Persistence (SQLite)
STORE_DB_PATH = Path(_env("NETWATCH_DB_PATH", "/var/lib/netwatch/store.db"))
ALERT_RETENTION_DAYS = int(_env("ALERT_RETENTION_DAYS", "30"))

# AdGuard Home instances — JSON file CONFIG_DIR/adguard.json:
#   {"instances": [{"name": "...", "url": "...", "user": "...", "pass": "..."}]}
import json as _json
_adguard_path = CONFIG_DIR / "adguard.json"
ADGUARD_INSTANCES = []
if _adguard_path.exists():
    try:
        ADGUARD_INSTANCES = _json.loads(_adguard_path.read_text())["instances"]
    except Exception:
        ADGUARD_INSTANCES = []

# App branding
APP_NAME = _env("APP_NAME", "NetWatch")
APP_TAGLINE = _env("APP_TAGLINE", "home network · security · live")

# Dashboard login (form-based, session cookie)
DASHBOARD_USER = _env("DASHBOARD_USER", "admin")
DASHBOARD_PASS = _load_secret("dashboard.cred")

# Session cookie signing — keep a stable secret in CONFIG_DIR/session.key;
# otherwise an ephemeral key is generated (sessions reset on restart).
SESSION_SECRET = _load_secret("session.key") or secrets.token_hex(32)
SESSION_COOKIE = "nw_session"
SESSION_TTL_DAYS = int(_env("SESSION_TTL_DAYS", "30"))

# Poll cadence / tuning
API_POLL_SECONDS = int(_env("API_POLL_SECONDS", "30"))       # UniFi/MikroTik
ADGUARD_POLL_SECONDS = int(_env("ADGUARD_POLL_SECONDS", "30"))
FIREWALL_SYSLOG_PORT = int(_env("FIREWALL_SYSLOG_PORT", "5514"))  # MikroTik remote syslog (ADR 0009)
ENRICH_TTL_HOURS = int(_env("ENRICH_TTL_HOURS", "24"))       # VT/AbuseIPDB cache window
ENRICH_INTERVAL_MIN = int(_env("ENRICH_INTERVAL_MIN", "10")) # background enrich pass
NOTIFY_COOLDOWN_MIN = int(_env("NOTIFY_COOLDOWN_MIN", "30"))
