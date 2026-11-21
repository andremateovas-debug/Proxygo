#!/usr/bin/env bash
set -Eeuo pipefail

if [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null; then
  systemctl stop proxygo-proxy.service proxygo-engine.service || true
  systemctl disable proxygo-proxy.service proxygo-engine.service || true
fi
