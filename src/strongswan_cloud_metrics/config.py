import os

# Path to the strongSwan VICI socket.
DEFAULT_SOCKET = "/var/run/charon.vici"
# Seconds between poll cycles.
POLL_INTERVAL = 60
# Connections to exclude from error reporting (e.g. test connections, known-down links).
# Comma-separated list via STRONGSWAN_IGNORE, e.g. STRONGSWAN_IGNORE="vpntest,mayoclinic".
IGNORE = [c.strip() for c in os.environ.get("STRONGSWAN_IGNORE", "vpntest").split(",") if c.strip()]
# Child SA name suffixes to exclude from missing-child-SA checks.
# Comma-separated list via STRONGSWAN_IGNORE_CHILD_SA_SUFFIXES.
IGNORE_CHILD_SA_SUFFIXES = [
    c.strip() for c in os.environ.get("STRONGSWAN_IGNORE_CHILD_SA_SUFFIXES", "-path-monitor").split(",") if c.strip()
]
# Set STRONGSWAN_CHILD_SA_REINIT=1 to automatically attempt
# swanctl --initiate on missing child SAs.
# Script must run as root (required for VICI access) so sudo is not needed.
CHILD_SA_REINIT = os.environ.get("STRONGSWAN_CHILD_SA_REINIT", "0") == "1"
# Seconds to wait for swanctl --initiate before giving up.
CHILD_SA_REINIT_TIMEOUT = int(os.environ.get("STRONGSWAN_CHILD_SA_REINIT_TIMEOUT", "10"))
# Minimum seconds between reinitiation attempts for the same child SA.
CHILD_SA_REINIT_COOLDOWN = int(os.environ.get("STRONGSWAN_CHILD_SA_REINIT_COOLDOWN", "0"))
# UTC time window during which service restart is allowed, e.g. "07:00-08:00".
# If blank, service restart is disabled. Use "00:00-00:00" to allow at any time.
SERVICE_REINIT_WINDOW = os.environ.get("STRONGSWAN_SERVICE_REINIT_WINDOW", "")
# Minimum seconds between service restarts.
SERVICE_REINIT_COOLDOWN = int(os.environ.get("STRONGSWAN_SERVICE_REINIT_COOLDOWN", "0"))

# systemd sets STATE_DIRECTORY to the full path when StateDirectory= is configured.
STATE_DIR = os.environ.get("STATE_DIRECTORY", "/var/lib/strongswan-cloud-metrics").split()[0]
# SQLite database storing intervention history (reinit timestamps, etc.).
DB_PATH = os.path.join(STATE_DIR, "state.db")
