# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A daemon (`src/strongswan_cloud_metrics/watcher.py`) that polls strongSwan's VICI control socket every 60 seconds, compares configured VPN connections against active security associations (SAs), and logs counts/errors. Logs are intended to be ingested by CloudWatch (with log filters for alerting); native CloudWatch metrics, other clouds, and Prometheus support are planned but not yet implemented (see README "Plan").

An active intervention mode is also planned — the daemon will detect problems and attempt to remediate them (e.g., restart connections), with history stored in SQLite at `/var/lib/strongswan-cloud-metrics/state.db`.

## Project structure

```
src/strongswan_cloud_metrics/
    __init__.py
    config.py       # all env var constants (IGNORE, REINIT_*, STATE_DIR, etc.)
    db.py           # SQLite helpers (init_db, last_reinit_ts, record_reinit)
    analysis.py     # pure functions: analyze(), in_reinit_window(), cooldown_elapsed(), bytes2human()
    watcher.py      # daemon entry point: check(), main(), logging setup
strongswan-cloud-metrics.service   # systemd unit
pyproject.toml
```

## Installation

Requires a Linux host running strongSwan — connects to `/var/run/charon.vici` (requires root).

```sh
# Install
sudo uv tool install strongswan-cloud-metrics   # installs to /usr/local/bin/

# Deploy systemd service
sudo cp strongswan-cloud-metrics.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now strongswan-cloud-metrics
```

There are currently no tests, linting, or CI — adding them is on the README roadmap.

## How watcher.py works

- `check()` runs one poll cycle: connects to VICI, reads configured connections and active SAs, logs results, disconnects. Called by `main()` in a `while True` loop with `POLL_INTERVAL = 60` seconds between iterations.
- A new socket connection is made each cycle — this handles strongSwan restarts cleanly.
- `vici_session.list_conns()` yields configured connections; `list_sas()` yields active SAs. Connection names are the dict keys of each yielded item.
- All VICI string values are bytes (e.g. state is `b"ESTABLISHED"`, not `"ESTABLISHED"`) — compare against bytes.
- An error is flagged when: an SA is in a state other than ESTABLISHED/CONNECTING, an established SA has no child SAs, or the set of configured connection names doesn't match the active ones.
- Output is structured log lines on stderr; alerting is done downstream by filtering these logs, so log message wording is load-bearing — changing it can break CloudWatch filters.

## VICI reference

Protocol/API docs: https://github.com/strongswan/strongswan/blob/master/src/libcharon/plugins/vici/README.md
