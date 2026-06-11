# strongswan-cloud-metrics

[![CI](https://github.com/charleslaw/strongswan-cloud-metrics/actions/workflows/ci.yml/badge.svg)](https://github.com/charleslaw/strongswan-cloud-metrics/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

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

Requires [uv](https://docs.astral.sh/uv/getting-started/installation/). Please refer to the official installation instructions there; typically it follows a command like (install systemwide):

```sh
curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR="/usr/local/bin" sudo -E sh
```

Install the package and deploy the systemd service:

```sh
sudo UV_TOOL_BIN_DIR=/usr/local/bin uv tool install .
sudo cp strongswan-cloud-metrics.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now strongswan-cloud-metrics
```

## Configuration

Configuration is read from `/etc/strongswan-cloud-metrics/env`. Create it if it doesn't exist:

```sh
sudo mkdir -p /etc/strongswan-cloud-metrics
sudo nano /etc/strongswan-cloud-metrics/env
```

Available settings:

```sh
# Comma-separated IKE connection names to exclude from error reporting
STRONGSWAN_IGNORE=vpntest

# Comma-separated IKE connection names to exclude from error reporting
STRONGSWAN_IGNORE_CHILD_SA_SUFFIXES=-path-monitor

# Set to 1 to automatically reinitiate missing child SAs via swanctl
STRONGSWAN_REINIT=0

# Timeout in seconds for swanctl reinitiate calls
STRONGSWAN_REINIT_TIMEOUT=10
```

After editing, restart the service to pick up changes:

```sh
sudo systemctl restart strongswan-cloud-metrics
```

## Logs

```sh
journalctl -u strongswan-cloud-metrics -f
```

## How it works

The daemon connects to strongSwan's VICI socket every 60 seconds, compares configured connections against active security associations, and logs the results. Alerting is done downstream — configure CloudWatch Metric Filters on the log group to turn log patterns (e.g. "VPN Error Detected") into metrics and alarms.
