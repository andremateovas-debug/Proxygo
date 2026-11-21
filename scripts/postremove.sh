#!/usr/bin/env bash
set -Eeuo pipefail

if [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null; then
  systemctl daemon-reload || true
  systemctl reset-failed proxygo-proxy.service proxygo-engine.service 2>/dev/null || true
fi

rm -f /run/proxygo/engine.sock 2>/dev/null || true
