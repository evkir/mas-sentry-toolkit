#!/bin/bash
# MAS-Sentry Full Audit Script
# Usage: ./scripts/run_full_audit.sh [TARGET_IP]

TARGET=${1:-127.0.0.1}
PORT=${2:-1883}
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUT_DIR="reports/audit_${TIMESTAMP}"

echo "[*] MAS-Sentry Full Audit"
echo "[*] Target: ${TARGET}:${PORT}"
mkdir -p "${OUT_DIR}"

echo "[*] Step 1: Broker fingerprint..."
python3 -m mas_sentry fingerprint --broker ${TARGET} --port ${PORT}

echo "[*] Step 2: Topic walk 20s..."
python3 -m mas_sentry walk --broker ${TARGET} --port ${PORT} --duration 20

echo "[*] Step 3: ABFP collection 60s..."
python3 -m mas_sentry abfp --broker ${TARGET} --port ${PORT} --duration 60 --output ${OUT_DIR}/abfp.json

echo "[*] Step 4: Full audit report..."
python3 -m mas_sentry audit --broker ${TARGET} --port ${PORT} --output audit.html

echo "[+] Done! Open: reports/audit.html"
