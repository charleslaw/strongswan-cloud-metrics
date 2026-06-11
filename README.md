# strongswan-cloud-metrics

A daemon that monitors strongSwan VPN connections and emits structured logs for ingestion by CloudWatch (or similar monitoring services).

Note that this requires root permissions to connect to the VICI socket (`/var/run/charon.vici`).

## Plan

* Build something that can detect issues even if it's not that polished
* Work on outputting metrics that can go into cloudwatch
* Make it installable and make it easy to deploy
* Add CI, tests, formatting, etc.
* Make the output metrics work with monitoring services from other clouds and Prometheus or similar tools
* Active intervention mode: detect problems and attempt remediation (e.g. restart connections), with history persisted to SQLite

## Installation

Requires [uv](https://docs.astral.sh/uv/getting-started/installation/). Please refer to the official installation instructions there; typically it follows a command like:

```sh
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Install the package and deploy the systemd service:

```sh
sudo uv tool install strongswan-cloud-metrics
sudo cp strongswan-cloud-metrics.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now strongswan-cloud-metrics
```

Check logs:

```sh
journalctl -u strongswan-cloud-metrics -f
```

## How it works

The daemon connects to strongSwan's VICI socket every 60 seconds, compares configured connections against active security associations, and logs the results. Alerting is done downstream — configure CloudWatch Metric Filters on the log group to turn log patterns (e.g. "VPN Error Detected") into metrics and alarms.
