#!/usr/bin/env bash
set -Eeuo pipefail

[[ "$(id -u)" -eq 0 ]] || {
  echo 'postinstall debe ejecutarse como root' >&2
  exit 1
}

if ! getent group proxygo >/dev/null; then
  groupadd --system proxygo
fi

if ! getent passwd proxygo >/dev/null; then
  useradd --system \
    --gid proxygo \
    --home-dir /nonexistent \
    --no-create-home \
    --shell /usr/sbin/nologin \
    proxygo
else
  proxy_shell="$(getent passwd proxygo | cut -d: -f7)"
  case "$proxy_shell" in
    /usr/sbin/nologin|/sbin/nologin) ;;
    *)
      echo "la cuenta proxygo existente tiene shell interactiva: $proxy_shell" >&2
      exit 1
      ;;
  esac
fi

if [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null; then
  systemctl daemon-reload
  systemctl enable proxygo-engine.service proxygo-proxy.service
fi