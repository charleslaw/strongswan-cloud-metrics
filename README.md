# strongswan-cloud-metrics

Set up a service to send strongswan metrics to a monitoring service like cloudwatch

Note that this requires sudo permissions to connect to vici/strongswan.

## Plan

The rough idea is as follows:

* Build something that can detect issues even if it's not that polished
* Work on outputting metrics that can go into cloudwatch
* Make it installable and make it easy to deploy
* Add CI, tests, formatting, etc.
* Make the output metrics work with monitoring services from other clouds and Prometheus or similar tools

## Current Setup

* Download the repo to /home/ubuntu/strongswan-cloud-metrics
* Define a location for virtualenvs if one does not already exist. We will assume /home/ubuntu/venvs
* `python -m venv /home/ubuntu/venvs/sscloud_venv/
* `/home/ubuntu/venvs/sscloud_venv/pip install -r requirements.txt`
* Set up a systemd timer/service to run this every minute
* Have cloudwatch ingest the logs and filter the logs for errors (details possibly TBD, unless metrics work is done soon)
