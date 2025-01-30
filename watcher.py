from datetime import datetime
import logging
import socket
import time


import vici


DEFAULT_SOCKET = "/var/run/charon.vici"

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
ch.setFormatter(formatter)
logger.addHandler(ch)


def main():
    with socket.socket(socket.AF_UNIX) as s:
        try:
            s.connect(DEFAULT_SOCKET)
        except Exception as exc:
            logger.error("Connection to VICI Socket Failed: %s", exc)
            raise

        vici_session = vici.Session(s)

        # https://github.com/strongswan/strongswan/blob/master/src/libcharon/plugins/vici/README.md#a-request-with-response-iteration
        # TODO: Confirm if there is ever more than 1 key per connection. It
        # looks a lot like each connection has a single key
        # list_conns lists connections specified in the VPN configuration
        conn_keys_config = []
        for conn in vici_session.list_conns():
            for key in conn:
                conn_keys_config.append(key)

        list_sas = list(vici_session.list_sas())

        error = False

        # analyze data
        conn_keys_active = []
        conn_connecting = []
        for conn in list_sas:
            for key, sas_info in conn.items():
                conn_keys_active.append(key)

                # TODO: Get a more complete list of states
                if sas_info.get("state") != b"ESTABLISHED":
                    if sas_info.get("state") == b"CONNECTING":
                        conn_connecting.append(key)
                    else:
                        error = True
                        continue

                # TODO: Find a way to see if a connection is resetting
                # frequently and has a perpetually low established time

                # Must exist and be non-empty
                children = None
                if sas_info.get("child-sas"):
                    children = sas_info["child-sas"]

                if not children:
                    error = True
                    continue

        if conn_keys_config != conn_keys_active:
            error = True

        # Simple logs
        logger.info("Configured connections (total): %s", len(conn_keys_config))
        active_conns_config = set(conn_keys_config).intersect(set(conn_keys_active))
        logger.info("Configured connections (active): %s", len(active_conns_config))
        missing_keys = set(conn_keys_config) - set(conn_keys_active)
        logger.info("Configured connections (missing): %s", len(missing_keys))
        logger.info("Active connections (total): %s", len(conn_keys_active))
        logger.info("Active connections: %s", list(sorted(conn_keys_active)))
        # Trigger alerts if this persists
        logger.info("Connections connecting: %s", len(conn_connecting))
        if error:
            # Trigger alerts on this
            logger.erro("VPN Error Detected")
        else:
            logger.info("No VPN Errors Detected")


if __name__ == "__main__":
    try:
        main()
    except:
        logger.error("Failed to run monitor")
        logger.exception("Traceback:")
