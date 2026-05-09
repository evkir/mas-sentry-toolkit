# ABFP Fingerprinting Guide

## Overview
Agent Behavioral Fingerprint Profiling (ABFP) passively observes
MAS agent communication patterns to build behavioral baselines.

## Usage
```bash
# Collect baseline (60 seconds)
mas-sentry abfp --target 192.168.1.100 --duration 60

# Compare against baseline
mas-sentry abfp --target 192.168.1.100 --compare baseline.json
```

## Anomaly Scores
| Score | Severity | Action |
|-------|----------|--------|
| 0-30  | LOW      | Log only |
| 31-60 | MEDIUM   | Alert |
| 61-80 | HIGH     | Block |
| 81-100| CRITICAL | Immediate response |
