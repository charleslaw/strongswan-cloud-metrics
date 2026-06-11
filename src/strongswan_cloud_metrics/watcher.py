import logging
import socket
import time

import vici

DEFAULT_SOCKET = "/var/run/charon.vici"
POLL_INTERVAL = 60

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
ch.setFormatter(formatter)
logger.addHandler(ch)


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
                conf_ike_map[ike_key] = list(ike_cfg[ike_key].get("children", {}).keys())

        list_sas = list(session.list_sas())

        # IKE key -> list of installed child SA names (from active state)
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

        logger.info("Configured IKE connections (total): %s", len(possible_conns))
        logger.info("Configured IKE connections (active): %s", len(active_conf_conns))
        logger.info("Configured IKE connections (missing): %s", len(missing_conf_conns))
        logger.info("Active IKE connections (total): %s", len(active_conns))
        logger.info("Active IKE connections list: %s", ", ".join(sorted(active_conns)))

        # For each configured child SA, start as not-established.
        # There may be multiple SAs for the same IKE key (e.g. during rekeying);
        # a connection is ok as long as at least one INSTALLED child SA per name exists.
        established = {}
        for ike_key in conf_ike_map:
            established[ike_key] = {}
            for child_sa_key in conf_ike_map[ike_key]:
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

        is_ok = True
        for ike_key in established:
            for child_sa in established[ike_key]:
                if not established[ike_key][child_sa]:
                    logger.error("Missing tunnel: %s %s", ike_key, child_sa)
                    is_ok = False

        if missing_conf_conns:
            is_ok = False

        if is_ok:
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
