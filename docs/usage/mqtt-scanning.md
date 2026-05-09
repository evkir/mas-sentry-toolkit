# MQTT Scanning Guide

## Quick Start
```bash
mas-sentry scan --target 192.168.1.100 --protocol mqtt
```

## Options
- `--port` — broker port (default: 1883)
- `--timeout` — connection timeout seconds
- `--output` — report format: json/html/markdown

## What it detects
- Anonymous authentication
- Wildcard topic enumeration
- Retained message poisoning
- Agent impersonation via client_id
