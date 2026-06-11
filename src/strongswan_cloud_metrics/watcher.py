import logging
import os
import socket
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
# Set REINIT=True to automatically attempt swanctl --initiate on missing child SAs.
# Script must run as root (required for VICI access) so sudo is not needed.
REINIT = os.environ.get("STRONGSWAN_REINIT", "0") == "1"
REINIT_TIMEOUT = int(os.environ.get("STRONGSWAN_REINIT_TIMEOUT", "10"))

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
ch.setFormatter(formatter)
logger.addHandler(ch)


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
    # IKE key -> list of installed child SA names
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


def check():
    with socket.socket(socket.AF_UNIX) as s:
        try:
            s.connect(DEFAULT_SOCKET)
        except Exception as exc:
            logger.error("Connection to VICI Socket Failed: %s", exc)
            raise

        session = vici.Session(s)

        # IKE key -> list of expected child SA names (from config)
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
                # v5.7 uses reauth-time instead of rekey-time
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
            logger.info("Attempting to reinitiate child SA: %s", child_sa)
            try:
                subprocess.run(
                    ["swanctl", "--initiate", "--child", child_sa],
                    timeout=REINIT_TIMEOUT,
                    capture_output=True,
                    check=False,
                )
            except Exception as exc:
                logger.error("Reinitiate failed for %s: %s", child_sa, exc)

    if result["is_ok"]:
        logger.info("No VPN Errors Detected")
        logger.info("Everything is ok.")
    else:
        logger.error("VPN Error Detected")
        logger.error("Everything is NOT ok")


def main():
    while True:
        try:
            check()
        except Exception:
            logger.error("Check failed")
            logger.exception("Traceback:")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
