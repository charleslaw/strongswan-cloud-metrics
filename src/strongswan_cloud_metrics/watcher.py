import logging
import socket
import subprocess
import time

import vici

from . import config, db
from .analysis import (
    analyze,
    bytes2human,
    cooldown_elapsed,
    in_reinit_window,
    _read_int,
    _read_time,
)

logger = logging.getLogger(__name__.rpartition(".")[2] or __name__)
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setFormatter(logging.Formatter("%(name)s - %(levelname)s - %(message)s"))
logger.addHandler(ch)


def check():
    logger.info("Starting check at %s", time.strftime("%Y-%m-%d %H:%M:%S"))
    with socket.socket(socket.AF_UNIX) as s:
        try:
            s.connect(config.DEFAULT_SOCKET)
        except Exception as exc:
            logger.error("Connection to VICI Socket Failed: %s", exc)
            raise

        session = vici.Session(s)

        conf_ike_map = {}
        for ike_cfg in session.list_conns():
            for ike_key in ike_cfg:
                conf_ike_map[ike_key] = list(ike_cfg[ike_key].get("children", {}).keys())

        list_sas = list(session.list_sas())

    result = analyze(conf_ike_map, list_sas, config.IGNORE, config.IGNORE_CHILD_SA_SUFFIXES)

    logger.info("Configured IKE connections (total): %s", len(result["possible_conns"]))
    logger.info("Configured IKE connections (active): %s", len(result["active_conf_conns"]))
    logger.info("Configured IKE connections (missing): %s", len(result["missing_conf_conns"]))
    logger.info(
        "Configured IKE connections (missing, not ignored): %s",
        len(result["errored_conns"]),
    )
    logger.info("Active IKE connections (total): %s", len(result["active_conns"]))
    logger.info("Active IKE connections list: %s", ", ".join(sorted(result["active_conns"])))

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

    # Note that tunnels are child SA's
    for ike_key, child_sa, ignored in result["missing_tunnels"]:
        logger.error(
            "Missing tunnel: %s %s%s",
            ike_key,
            child_sa,
            " (ignored)" if ignored else "",
        )
        if config.CHILD_SA_REINIT and not ignored:
            last_ts = db.last_reinit_ts(child_sa)
            if not cooldown_elapsed(last_ts, config.CHILD_SA_REINIT_COOLDOWN):
                remaining = config.CHILD_SA_REINIT_COOLDOWN - (time.time() - last_ts)
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
                        timeout=config.CHILD_SA_REINIT_TIMEOUT,
                        capture_output=True,
                        check=False,
                    )
                    db.record_reinit(ike_key, child_sa)
                except Exception as exc:
                    logger.error("Reinitiate failed for %s: %s", child_sa, exc)

    if result["is_ok"]:
        logger.info("No VPN Errors Detected")
        # TODO: Remove this line
        logger.info("Everything is ok.")
    else:
        logger.error("VPN Error Detected")
        # TODO: Remove this line
        logger.error("Everything is NOT ok")
        if not in_reinit_window(config.SERVICE_REINIT_WINDOW):
            logger.info(
                "Service restart skipped (outside window %s)",
                config.SERVICE_REINIT_WINDOW,
            )
        else:
            last_ts = db.last_service_restart_ts()
            if not cooldown_elapsed(last_ts, config.SERVICE_REINIT_COOLDOWN):
                remaining = config.SERVICE_REINIT_COOLDOWN - (time.time() - last_ts)
                logger.info(
                    "Service restart skipped (cooldown, %.0fs remaining)",
                    remaining,
                )
            else:
                logger.info("Attempting service restart: systemctl restart strongswan")
                try:
                    subprocess.run(
                        ["systemctl", "restart", "strongswan"],
                        timeout=30,
                        capture_output=True,
                        check=False,
                    )
                    db.record_service_restart()
                except Exception as exc:
                    logger.error("Service restart failed: %s", exc)


def main():
    db.init_db()
    while True:
        try:
            check()
        except Exception:
            logger.error("Check failed")
            logger.exception("Traceback:")
        time.sleep(config.POLL_INTERVAL)


if __name__ == "__main__":
    main()
