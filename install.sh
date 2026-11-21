#!/usr/bin/env bash
set -euo pipefail

REPO="andremateovas-debug/Proxygo"
TMP_DEB="/tmp/proxygo_latest.deb"

echo "Buscando última versión de ProxyGo..."
DEB_URL=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep -Eo 'https://[^"]+\.deb' | head -n 1)

if [[ -z "${DEB_URL}" ]]; then
  echo "Error: No se encontró un paquete .deb en los releases de ${REPO}."
  exit 1
fi

echo "Descargando ${DEB_URL}..."
curl -fsSL "${DEB_URL}" -o "${TMP_DEB}"

echo "Instalando paquete con apt..."
sudo apt-get update -qq
sudo apt-get install -y "${TMP_DEB}"
rm -f "${TMP_DEB}"

echo "Instalación completada. Verifica el estado con: sudo proxygo-cli status"
