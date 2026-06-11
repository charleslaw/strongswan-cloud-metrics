import datetime
import logging
import time

logger = logging.getLogger(__name__)


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


def in_reinit_window(window_str, now=None):
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
            "Invalid STRONGSWAN_SERVICE_REINIT_WINDOW format: %s (expected HH:MM-HH:MM)",
            window_str,
        )
        return False


def cooldown_elapsed(last_ts, cooldown_secs, now=None):
    """Returns True if at least cooldown_secs have passed since last_ts.

    Returns True when cooldown_secs <= 0 (no restriction) or last_ts is None.
    """
    if cooldown_secs <= 0 or last_ts is None:
        return True
    if now is None:
        now = time.time()
    return (now - last_ts) >= cooldown_secs


def analyze(conf_ike_map, list_sas, ignore, ignore_child_sa_suffixes):
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
            for ignore_suffix in ignore_child_sa_suffixes:
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
