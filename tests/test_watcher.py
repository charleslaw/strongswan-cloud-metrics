from strongswan_cloud_metrics.watcher import _analyze, bytes2human


def sa(name, state=b"INSTALLED"):
    return {"name": name.encode(), "state": state}


def ike(state=b"ESTABLISHED", children=None):
    return {"state": state, "child-sas": children or {}}


def test_all_ok():
    conf = {"healthie": ["healthie-child"]}
    sas = [{"healthie": ike(children={"1": sa("healthie-child")})}]
    result = _analyze(conf, sas, ignore=[])
    assert result["is_ok"] is True
    assert result["missing_tunnels"] == []


def test_missing_ike_connection():
    conf = {"healthie": ["healthie-child"], "missing-conn": ["missing-child"]}
    sas = [{"healthie": ike(children={"1": sa("healthie-child")})}]
    result = _analyze(conf, sas, ignore=[])
    assert result["is_ok"] is False
    assert "missing-conn" in result["errored_conns"]


def test_missing_child_sa():
    conf = {"healthie": ["healthie-child"]}
    sas = [{"healthie": ike(children={})}]
    result = _analyze(conf, sas, ignore=[])
    assert result["is_ok"] is False
    assert ("healthie", "healthie-child", False) in result["missing_tunnels"]


def test_child_sa_not_installed():
    conf = {"healthie": ["healthie-child"]}
    sas = [{"healthie": ike(children={"1": sa("healthie-child", state=b"REKEYING")})}]
    result = _analyze(conf, sas, ignore=[])
    assert result["is_ok"] is False
    assert ("healthie", "healthie-child", False) in result["missing_tunnels"]


def test_ignored_ike_missing():
    conf = {"vpntest": ["vpntest-child"]}
    sas = []
    result = _analyze(conf, sas, ignore=["vpntest"])
    assert result["is_ok"] is True
    assert result["errored_conns"] == set()


def test_ignored_child_sa_missing():
    conf = {"vpntest": ["vpntest-child"]}
    sas = [{"vpntest": ike(children={})}]
    result = _analyze(conf, sas, ignore=["vpntest"])
    assert result["is_ok"] is True
    assert result["missing_tunnels"] == [("vpntest", "vpntest-child", True)]


def test_path_monitor_skipped():
    conf = {"healthie": ["healthie-child", "healthie-path-monitor"]}
    sas = [{"healthie": ike(children={"1": sa("healthie-child")})}]
    result = _analyze(conf, sas, ignore=[])
    assert result["is_ok"] is True
    assert result["missing_tunnels"] == []


def test_stuck_connection_ok():
    # Two SAs for the same IKE key (e.g. during rekeying): one good, one stuck.
    conf = {"healthie": ["healthie-child"]}
    sas = [
        {"healthie": ike(children={"1": sa("healthie-child")})},
        {"healthie": ike(state=b"CONNECTING", children={})},
    ]
    result = _analyze(conf, sas, ignore=[])
    assert result["is_ok"] is True


def test_ike_not_established_does_not_mark_children():
    # IKE in CONNECTING state — child SAs should not count toward established.
    conf = {"healthie": ["healthie-child"]}
    sas = [{"healthie": ike(state=b"CONNECTING", children={"1": sa("healthie-child")})}]
    result = _analyze(conf, sas, ignore=[])
    assert result["is_ok"] is False


def test_multiple_connections_all_ok():
    conf = {"healthie": ["healthie-child"], "norwayhealth": ["norwayhealth-child"]}
    sas = [
        {"healthie": ike(children={"1": sa("healthie-child")})},
        {"norwayhealth": ike(children={"1": sa("norwayhealth-child")})},
    ]
    result = _analyze(conf, sas, ignore=[])
    assert result["is_ok"] is True
    assert len(result["possible_conns"]) == 2
    assert len(result["active_conf_conns"]) == 2


def test_duplicate_ike_one_copy_fully_up():
    # Two IKE SAs for "john": one has both child SAs down, other has both up.
    # Should be OK since at least one copy of each child SA is INSTALLED.
    conf = {"john": ["john-stg", "john-prod"]}
    sas = [
        {
            "john": ike(
                children={
                    "1": sa("john-stg"),
                    "2": sa("john-prod"),
                }
            )
        },
        {
            "john": ike(
                children={
                    "3": sa("john-stg", state=b"REKEYING"),
                    "4": sa("john-prod", state=b"REKEYING"),
                }
            )
        },
    ]
    result = _analyze(conf, sas, ignore=[])
    assert result["is_ok"] is True
    assert result["missing_tunnels"] == []


def test_duplicate_ike_one_child_sa_down_everywhere():
    # Two IKE SAs for "john": john-stg is down in both copies, john-prod is up in both.
    # Should fail since no copy of john-stg is INSTALLED.
    conf = {"john": ["john-stg", "john-prod"]}
    sas = [
        {
            "john": ike(
                children={
                    "1": sa("john-stg", state=b"REKEYING"),
                    "2": sa("john-prod"),
                }
            )
        },
        {
            "john": ike(
                children={
                    "3": sa("john-stg", state=b"REKEYING"),
                    "4": sa("john-prod"),
                }
            )
        },
    ]
    result = _analyze(conf, sas, ignore=[])
    assert result["is_ok"] is False
    assert ("john", "john-stg", False) in result["missing_tunnels"]
    assert not any(t[1] == "john-prod" for t in result["missing_tunnels"])


def test_bytes2human():
    assert bytes2human(0) == "0.0B"
    assert bytes2human(1023) == "1023.0B"
    assert bytes2human(1024) == "1.0KiB"
    assert bytes2human(1024**2) == "1.0MiB"
    assert bytes2human(1024**3) == "1.0GiB"
