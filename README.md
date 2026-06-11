# strongswan-cloud-metrics

[![CI](https://github.com/charleslaw/strongswan-cloud-metrics/actions/workflows/ci.yml/badge.svg)](https://github.com/charleslaw/strongswan-cloud-metrics/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

A daemon that monitors strongSwan VPN connections and emits structured logs for ingestion by CloudWatch (or similar monitoring services).

Note that this requires root permissions to connect to the VICI socket (`/var/run/charon.vici`).

## Roadmap

- [x] Build something that can detect issues even if it's not that polished
- [x] Output metrics into cloudwatch as logs
- [x] Make it installable and easy to deploy
- [x] Add CI, tests, formatting, etc.
- [ ] Make the output metrics output to cloudwatch metrics directly for better information
- [ ] Make the output metrics work with monitoring services from other clouds and Prometheus or similar tools
- [x] Active intervention mode: detect problems and attempt remediation (e.g. restart connections), with history persisted to SQLite

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
STRONGSWAN_CHILD_SA_REINIT=0

# Timeout in seconds for swanctl reinitiate calls
STRONGSWAN_CHILD_SA_REINIT_TIMEOUT=10

# Minimum seconds between reinitiation attempts for the same child SA
# Set to 0 to disable (reinitiate every cycle if the tunnel is down)
STRONGSWAN_CHILD_SA_REINIT_COOLDOWN=3600

# UTC time window during which automatic service restart is allowed (HH:MM-HH:MM)
# Leave unset (or blank) to disable service restart entirely.
# Use 00:00-00:00 to allow restart at any time.
STRONGSWAN_SERVICE_REINIT_WINDOW=07:00-08:00

# Minimum seconds between service restarts
# Set to 0 to disable (restart every cycle if VPN errors are detected)
STRONGSWAN_SERVICE_REINIT_COOLDOWN=3600
```

**Tip: limiting restarts to once per day** — set `STRONGSWAN_SERVICE_REINIT_WINDOW` to a short daily window and `STRONGSWAN_SERVICE_REINIT_COOLDOWN` to a value larger than the window duration. For example, a window of `07:00-08:00` (3600 seconds wide) with a cooldown of `7200` seconds means at most one service restart per day, even if the daemon keeps seeing VPN errors.

After editing, restart the service to pick up changes:

```sh
sudo systemctl restart strongswan-cloud-metrics
```

## AWS Setup

### Capturing logs in CloudWatch

1. **Create a log group** — in the CloudWatch console under Log Management, create a log group (e.g. `VPN_WATCHER_LOGS`).

2. **Install the CloudWatch agent** on the instance:
   ```sh
   wget https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb
   sudo dpkg -i amazon-cloudwatch-agent.deb
   ```

3. **Attach the IAM policy** — add `CloudWatchAgentServerPolicy` to the IAM role attached to the instance.

4. **Enable log file output** — create the log file, uncomment the `StandardOutput`/`StandardError` lines in the service file, then reload and restart:
   ```sh
   sudo mkdir -p /var/log/vpn && sudo touch /var/log/vpn/strongswan-cloud-metrics.log
   sudo systemctl daemon-reload
   sudo systemctl restart strongswan-cloud-metrics
   ```

5. **Set up log rotation** — create `/etc/logrotate.d/strongswan-cloud-metrics`:
   ```
   /var/log/vpn/strongswan-cloud-metrics.log {
       daily
       rotate 7
       compress
       missingok
       notifempty
       copytruncate
   }
   ```
   Verify the config is valid:
   ```sh
   sudo logrotate --debug /etc/logrotate.d/strongswan-cloud-metrics
   ```

6. **Configure the CloudWatch agent** — add the log file to your agent config (typically `/etc/amazon/amazon-cloudwatch-agent/amazon-cloudwatch-agent.d/file_config.json`) under `logs.logs_collected.files.collect_list`:
   ```json
   {
       "file_path": "/var/log/vpn/strongswan-cloud-metrics.log",
       "log_group_name": "VPN_WATCHER_LOGS",
       "log_stream_name": "{instance_id}",
       "log_group_class": "STANDARD",
       "retention_in_days": -1
   }
   ```
   Then load the config:
   ```sh
   sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
     -a fetch-config -m ec2 -s \
     -c file:/etc/amazon/amazon-cloudwatch-agent/amazon-cloudwatch-agent.d/file_config.json
   ```

## Logs

```sh
journalctl -u strongswan-cloud-metrics -f
```

## How it works

The daemon connects to strongSwan's VICI socket every 60 seconds, compares configured connections against active security associations, and logs the results. Alerting is done downstream — configure CloudWatch Metric Filters on the log group to turn log patterns (e.g. "VPN Error Detected") into metrics and alarms.
