import datetime
import logging
import os
import socket
import sqlite3
import subprocess
import time

import vici


def _read_int(data, key):
    return int(data.get(key, b"0").decode("utf-8"))


def _read_time(data, key, tref, tdir=1):
    delta = _read_int(data, key)
    if tdir < 0:
        delta = -delta
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(tref + delta)))


def bytes2human(n):
    symbols = ("B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB")
    prefix = {s: 1 << (i + 1) * 10 for i, s in enumerate(symbols[1:])}
    for symbol in reversed(symbols[1:]):
        if n >= prefix[symbol]:
            return "%.1f%s" % (float(n) / prefix[symbol], symbol)
    return "%.1fB" % n


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

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
ch.setFormatter(formatter)
logger.addHandler(ch)


# ---------------------------------------------------------------------------
# SQLite helpers
# ---------------------------------------------------------------------------


def _init_db():
    os.makedirs(STATE_DIR, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS interventions (
                id       INTEGER PRIMARY KEY,
                ts       REAL    NOT NULL,
                ike_key  TEXT    NOT NULL,
                child_sa TEXT    NOT NULL,
                action   TEXT    NOT NULL DEFAULT 'initiate',
                outcome  TEXT
            )
        """)


def _last_reinit_ts(child_sa):
    """Returns unix timestamp of the most recent reinit for child_sa, or None."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute(
                "SELECT ts FROM interventions WHERE child_sa = ? "
                "ORDER BY ts DESC LIMIT 1",
                (child_sa,),
            ).fetchone()
        return row[0] if row else None
    except Exception as exc:
        logger.error("DB read failed: %s", exc)
        return None


def _record_reinit(ike_key, child_sa):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO interventions (ts, ike_key, child_sa) VALUES (?, ?, ?)",
                (time.time(), ike_key, child_sa),
            )
    except Exception as exc:
        logger.error("DB write failed: %s", exc)


# ---------------------------------------------------------------------------
# Reinit scheduling helpers (pure — no I/O, testable)
# ---------------------------------------------------------------------------


def _in_reinit_window(window_str, now=None):
    """Returns True if now (UTC) falls within window_str (HH:MM-HH:MM).

    Returns True when window_str is empty (no restriction).
    Handles windows that cross midnight, e.g. "23:00-01:00".
    """
    if not window_str:
        return True
    if now is None:
        now = datetime.datetime.utcnow().time()
    try:
        start_str, end_str = window_str.split("-", 1)
        start = datetime.datetime.strptime(start_str.strip(), "%H:%M").time()
        end = datetime.datetime.strptime(end_str.strip(), "%H:%M").time()
        if start <= end:
            return start <= now <= end
        # Window crosses midnight
        return now >= start or now <= end
    except Exception:
        logger.error(
            "Invalid STRONGSWAN_REINIT_WINDOW format: %s (expected HH:MM-HH:MM)",
            window_str,
        )
        return False


def _cooldown_elapsed(last_ts, cooldown_secs, now=None):
    """Returns True if at least cooldown_secs have passed since last_ts.

    Returns True when cooldown_secs <= 0 (no restriction) or last_ts is None.
    """
    if cooldown_secs <= 0 or last_ts is None:
        return True
    if now is None:
        now = time.time()
    return (now - last_ts) >= cooldown_secs


# ---------------------------------------------------------------------------
# Core analysis (pure — no I/O, testable)
# ---------------------------------------------------------------------------


def _analyze(conf_ike_map, list_sas, ignore):
    """Pure analysis of VICI data. No I/O or logging.

    Args:
        conf_ike_map: {ike_key: [child_sa_name, ...]} from list_conns()
        list_sas: list of {ike_key: ike_status} from list_sas()
        ignore: list of IKE connection names to exclude from error reporting

    Returns dict with:
        is_ok, possible_conns, active_conns, active_conf_conns,
        missing_conf_conns, errored_conns, missing_tunnels
    """
    active_ike_map = {}
    for ike_blob in list_sas:
        for ike_key, ike_status in ike_blob.items():
            child_sas = ike_status.get("child-sas", {})
            if ike_key not in active_ike_map:
                active_ike_map[ike_key] = []
            for child_sa_key in child_sas:
                if child_sas[child_sa_key].get("state") == b"INSTALLED":
                    child_sa_name = child_sas[child_sa_key].get("name").decode("utf-8")
                    active_ike_map[ike_key].append(child_sa_name)

    possible_conns = set(conf_ike_map.keys())
    active_conns = set(active_ike_map.keys())
    missing_conf_conns = possible_conns - active_conns
    active_conf_conns = active_conns - missing_conf_conns
    errored_conns = missing_conf_conns - set(ignore)

    # For each configured child SA, start as not-established.
    # There may be multiple SAs for the same IKE key (e.g. during rekeying);
    # a connection is ok as long as at least one INSTALLED child SA per name exists.
    established = {}
    for ike_key in conf_ike_map:
        established[ike_key] = {}
        for child_sa_key in conf_ike_map[ike_key]:
            ignore_sa = False
            for ignore_suffix in IGNORE_CHILD_SA_SUFFIXES:
                if child_sa_key.endswith(ignore_suffix):
                    ignore_sa = True
                    break
            if ignore_sa:
                continue
            established[ike_key][child_sa_key] = False

    for ike_blob in list_sas:
        for ike_key, ike_status in ike_blob.items():
            if ike_status["state"] != b"ESTABLISHED":
                continue
            child_sas = ike_status.get("child-sas")
            if child_sas:
                for child_status in child_sas.values():
                    child_key = child_status["name"].decode("utf-8")
                    if child_key in established.get(ike_key, {}):
                        if child_status["state"] == b"INSTALLED":
                            established[ike_key][child_key] = True

    missing_tunnels = []
    is_ok = True
    for ike_key in established:
        for child_sa in established[ike_key]:
            if not established[ike_key][child_sa]:
                ignored = ike_key in ignore
                missing_tunnels.append((ike_key, child_sa, ignored))
                if not ignored:
                    is_ok = False

    if errored_conns:
        is_ok = False

    return {
        "is_ok": is_ok,
        "possible_conns": possible_conns,
        "active_conns": active_conns,
        "active_conf_conns": active_conf_conns,
        "missing_conf_conns": missing_conf_conns,
        "errored_conns": errored_conns,
        "missing_tunnels": missing_tunnels,
    }


# ---------------------------------------------------------------------------
# Main check loop
# ---------------------------------------------------------------------------


def check():
    with socket.socket(socket.AF_UNIX) as s:
        try:
            s.connect(DEFAULT_SOCKET)
        except Exception as exc:
            logger.error("Connection to VICI Socket Failed: %s", exc)
            raise

        session = vici.Session(s)

        conf_ike_map = {}
        for ike_cfg in session.list_conns():
            for ike_key in ike_cfg:
                conf_ike_map[ike_key] = list(
                    ike_cfg[ike_key].get("children", {}).keys()
                )

        list_sas = list(session.list_sas())

    result = _analyze(conf_ike_map, list_sas, IGNORE)

    logger.info("Configured IKE connections (total): %s", len(result["possible_conns"]))
    logger.info(
        "Configured IKE connections (active): %s", len(result["active_conf_conns"])
    )
    logger.info(
        "Configured IKE connections (missing): %s", len(result["missing_conf_conns"])
    )
    logger.info(
        "Configured IKE connections (missing, not ignored): %s",
        len(result["errored_conns"]),
    )
    logger.info("Active IKE connections (total): %s", len(result["active_conns"]))
    logger.info(
        "Active IKE connections list: %s", ", ".join(sorted(result["active_conns"]))
    )

    tref = int(time.time())
    for ike_blob in list_sas:
        for ike_key, ike_status in ike_blob.items():
            if ike_status["state"] != b"ESTABLISHED":
                continue
            try:
                if "rekey-time" not in ike_status and "reauth-time" in ike_status:
                    ike_status["rekey-time"] = ike_status["reauth-time"]
                logger.debug(
                    "IKE %s: established=%s rekey=%s",
                    ike_key,
                    _read_time(ike_status, "established", tref, tdir=-1),
                    _read_time(ike_status, "rekey-time", tref, tdir=1),
                )
            except Exception:
                pass
            child_sas = ike_status.get("child-sas")
            if child_sas:
                for child_status in child_sas.values():
                    child_key = child_status["name"].decode("utf-8")
                    try:
                        logger.debug(
                            "  child %s: in=%s out=%s installed=%s life=%s rekey=%s",
                            child_key,
                            bytes2human(_read_int(child_status, "bytes-in")),
                            bytes2human(_read_int(child_status, "bytes-out")),
                            _read_time(child_status, "install-time", tref, tdir=-1),
                            _read_time(child_status, "life-time", tref, tdir=1),
                            _read_time(child_status, "rekey-time", tref, tdir=1),
                        )
                    except Exception:
                        pass

    for ike_key, child_sa, ignored in result["missing_tunnels"]:
        logger.error(
            "Missing tunnel: %s %s%s",
            ike_key,
            child_sa,
            " (ignored)" if ignored else "",
        )
        if REINIT and not ignored:
            if not _in_reinit_window(REINIT_WINDOW):
                logger.info(
                    "Reinit skipped (outside window %s): %s", REINIT_WINDOW, child_sa
                )
            else:
                last_ts = _last_reinit_ts(child_sa)
                if not _cooldown_elapsed(last_ts, REINIT_COOLDOWN):
                    remaining = REINIT_COOLDOWN - (time.time() - last_ts)
                    logger.info(
                        "Reinit skipped (cooldown, %.0fs remaining): %s",
                        remaining,
                        child_sa,
                    )
                else:
                    logger.info("Attempting to reinitiate child SA: %s", child_sa)
                    try:
                        subprocess.run(
                            ["swanctl", "--initiate", "--child", child_sa],
                            timeout=REINIT_TIMEOUT,
                            capture_output=True,
                            check=False,
                        )
                        _record_reinit(ike_key, child_sa)
                    except Exception as exc:
                        logger.error("Reinitiate failed for %s: %s", child_sa, exc)

    if result["is_ok"]:
        logger.info("No VPN Errors Detected")
        logger.info("Everything is ok.")
    else:
        logger.error("VPN Error Detected")
        logger.error("Everything is NOT ok")


def main():
    _init_db()
    while True:
        try:
            check()
        except Exception:
            logger.error("Check failed")
            logger.exception("Traceback:")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
