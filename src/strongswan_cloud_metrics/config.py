import os

DEFAULT_SOCKET = "/var/run/charon.vici"
POLL_INTERVAL = 60
# Connections to exclude from error reporting (e.g. test connections, known-down links).
# Comma-separated names to exclude from error reporting.
# e.g. STRONGSWAN_IGNORE="vpntest,mayoclinic"
IGNORE = [
    c.strip()
    for c in os.environ.get("STRONGSWAN_IGNORE", "vpntest").split(",")
    if c.strip()
]
IGNORE_CHILD_SA_SUFFIXES = [
    c.strip()
    for c in os.environ.get(
        "STRONGSWAN_IGNORE_CHILD_SA_SUFFIXES", "-path-monitor"
    ).split(",")
    if c.strip()
]
# Set STRONGSWAN_REINIT=1 to automatically attempt
# swanctl --initiate on missing child SAs.
# Script must run as root (required for VICI access) so sudo is not needed.
REINIT = os.environ.get("STRONGSWAN_REINIT", "0") == "1"
REINIT_TIMEOUT = int(os.environ.get("STRONGSWAN_REINIT_TIMEOUT", "10"))
# UTC time window during which reinitiation is allowed, e.g. "07:00-08:00".
REINIT_WINDOW = os.environ.get("STRONGSWAN_REINIT_WINDOW", "")
# Minimum seconds between reinitiation attempts for the same child SA.
REINIT_COOLDOWN = int(os.environ.get("STRONGSWAN_REINIT_COOLDOWN", "0"))

# systemd sets STATE_DIRECTORY to the full path when StateDirectory= is configured.
STATE_DIR = os.environ.get(
    "STATE_DIRECTORY", "/var/lib/strongswan-cloud-metrics"
).split()[0]
DB_PATH = os.path.join(STATE_DIR, "state.db")
