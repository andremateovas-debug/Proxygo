#!/usr/bin/env bash
set -Eeuo pipefail

PROXY_URL="${PROXYGO_TEST_PROXY_URL:-http://127.0.0.1:8080}"
CONTROL_URL="${PROXYGO_TEST_CONTROL_URL:-http://127.0.0.1:8081}"
TARGET_URL="${PROXYGO_TEST_TARGET_URL:-http://httpbin.org/post}"
RESTORE_MODE="${PROXYGO_RESTORE_MODE:-}"
TIMEOUT="${PROXYGO_TEST_TIMEOUT:-10}"
ENGINE_SERVICE="proxygo-engine.service"
engine_was_active=0

fail() {
	printf 'FAIL: %s\n' "$1" >&2
	exit 1
}

set_mode() {
	curl --fail --silent --show-error --max-time 3 \
		-H 'Content-Type: application/json' \
		-d "{\"mode\":\"$1\"}" \
		"$CONTROL_URL/api/mode" >/dev/null
}

request_status() {
	local body="$1"
	curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
		--max-time "$TIMEOUT" --proxy "$PROXY_URL" --noproxy '' \
		--request POST "$TARGET_URL" \
		-H 'Content-Type: application/json' \
		--data-binary "$body"
}

restore_services() {
	set +e
	set_mode "$RESTORE_MODE"
	if (( engine_was_active )); then
		systemctl start "$ENGINE_SERVICE"
	fi
}

[[ "$(id -u)" -eq 0 ]] || fail 'ejecuta este test como root para detener y restaurar el engine'
command -v curl >/dev/null || fail 'curl no está instalado'
command -v systemctl >/dev/null || fail 'systemctl no está disponible'
systemctl is-active --quiet "$ENGINE_SERVICE" || fail "$ENGINE_SERVICE debe estar activo al iniciar"
engine_was_active=1
if [[ -z "$RESTORE_MODE" ]]; then
	mode_response="$(curl --fail --silent --show-error --max-time 3 "$CONTROL_URL/api/mode")" || fail 'no se pudo leer el modo original'
	mode_pattern='"mode"[[:space:]]*:[[:space:]]*"(MONITOR|SANITIZE|BLOCK)"'
	if [[ "$mode_response" =~ $mode_pattern ]]; then
		RESTORE_MODE="${BASH_REMATCH[1]}"
	else
		fail 'la API devolvió un modo original desconocido'
	fi
fi
trap restore_services EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

set_mode BLOCK || fail 'no se pudo activar el modo BLOCK mediante /api/mode'
printf '1/4 Tráfico normal... '
status="$(request_status '{"message":"normal traffic"}')" || fail 'falló la conexión del escenario normal'
[[ "$status" =~ ^2[0-9][0-9]$ ]] || fail "tráfico normal devolvió HTTP $status (revisa PROXYGO_TEST_TARGET_URL)"
printf 'HTTP %s\n' "$status"

printf '2/4 API key de Anthropic... '
status="$(request_status '{"api_key":"sk-ant-api03-abcdefghijklmnopQRSTUVWX"}')" || fail 'falló la conexión del escenario Anthropic'
[[ "$status" == 403 ]] || fail "API key debería bloquearse con HTTP 403, devolvió $status"
printf 'HTTP %s (bloqueada)\n' "$status"

printf '3/4 String de alta entropía... '
status="$(request_status '{"opaque":"aB3dE5fG7hJ9kL2mN4pQ6rT8"}')" || fail 'falló la conexión del escenario de entropía'
[[ "$status" == 403 ]] || fail "secreto de alta entropía debería bloquearse con HTTP 403, devolvió $status"
printf 'HTTP %s (bloqueado)\n' "$status"

printf '4/4 Engine Rust fuera de servicio... '
systemctl stop "$ENGINE_SERVICE"
status="$(request_status '{"message":"engine outage test"}')" || fail 'falló la conexión del escenario de caída del engine'
[[ "$status" == 503 ]] || fail "engine fuera de servicio debería producir HTTP 503 con FAIL_CLOSED, devolvió $status"
printf 'HTTP %s (FAIL_CLOSED)\n' "$status"

printf 'Todos los escenarios pasaron.\n'
