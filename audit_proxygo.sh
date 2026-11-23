#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
SKIP_COUNT=0
PIDS=()
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/proxygo-audit.XXXXXX")"
SOCK_PATH="$TMP_ROOT/engine.sock"
ADMIN_TOKEN=""
ADMIN_CURL_CONFIG="$TMP_ROOT/admin-curl.conf"
RUST_PID=""
GO_PID=""
MOCK_PID=""

pass_test() {
    PASS_COUNT=$((PASS_COUNT + 1))
    printf "${GREEN}[PASS] %s${NC}\n" "$1"
}

fail_test() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    printf "${RED}[FAIL] %s${NC}\n" "$1" >&2
}

warn_test() {
    WARN_COUNT=$((WARN_COUNT + 1))
    printf "${YELLOW}[WARN] %s${NC}\n" "$1"
}

skip_test() {
    SKIP_COUNT=$((SKIP_COUNT + 1))
    printf "${YELLOW}[SKIP] %s${NC}\n" "$1"
}

cleanup_pid() {
    local pid="$1"
    local attempt
    if kill -0 "$pid" 2>/dev/null; then
        kill -TERM "$pid" 2>/dev/null
        for ((attempt = 0; attempt < 20; attempt++)); do
            if ! kill -0 "$pid" 2>/dev/null; then
                break
            fi
            sleep 0.1
        done
        if kill -0 "$pid" 2>/dev/null; then
            kill -KILL "$pid" 2>/dev/null
        fi
    fi
    wait "$pid" 2>/dev/null
    return 0
}

finish() {
    local exit_status=$?
    local pid
    trap - EXIT INT TERM HUP
    set +e
    for pid in "${PIDS[@]}"; do
        cleanup_pid "$pid"
    done
    rm -rf "$TMP_ROOT"

    if ((FAIL_COUNT == 0)); then
        if ((exit_status != 0)); then
            FAIL_COUNT=$((FAIL_COUNT + 1))
            printf "${RED}[FAIL] La ejecución terminó inesperadamente (código %d).${NC}\n" "$exit_status" >&2
        fi
    fi
    printf "\n${CYAN}Resumen: aprobadas=%d fallidas=%d advertencias=%d omitidas=%d${NC}\n" \
        "$PASS_COUNT" "$FAIL_COUNT" "$WARN_COUNT" "$SKIP_COUNT"
    if ((FAIL_COUNT == 0 && exit_status == 0)); then
        printf "${GREEN}AUDITORÍA FINALIZADA CON ÉXITO${NC}\n"
        exit 0
    fi
    printf "${RED}AUDITORÍA FALLIDA O INTERRUMPIDA${NC}\n" >&2
    exit 1
}

trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

require_command() {
    local name="$1"
    shift
    if "$@"; then
        pass_test "$name"
    else
        fail_test "$name"
        exit 1
    fi
}

wait_for_http() {
    local name="$1"
    local url="$2"
    local pid="$3"
    local attempt
    local curl_options=()
    if [[ "$url" == https://* ]]; then
        curl_options=(-k)
    fi
    for ((attempt = 0; attempt < 60; attempt++)); do
        if ! kill -0 "$pid" 2>/dev/null; then
            fail_test "$name terminó antes de estar disponible"
            exit 1
        fi
        if curl "${curl_options[@]}" --noproxy "" --connect-timeout 1 --max-time 2 -fsS "$url" -o /dev/null 2>/dev/null; then
            pass_test "$name disponible en loopback"
            return 0
        fi
        sleep 0.1
    done
    fail_test "$name no estuvo disponible dentro del tiempo límite"
    exit 1
}

test_case() {
    case "$1" in
        pass)
            pass_test "prueba simulada"
            exit 0
            ;;
        fail)
            fail_test "fallo simulado"
            exit 1
            ;;
        interrupt)
            sleep 60 &
            MOCK_PID=$!
            PIDS+=("$MOCK_PID")
            printf '%s\n' "$MOCK_PID" > "$2"
            kill -TERM "$$"
            ;;
        *)
            fail_test "caso de autocomprobación desconocido"
            exit 2
            ;;
    esac
}

self_test() {
    local output
    local pid
    local interrupt_file="$TMP_ROOT/interrupt.pid"

    if output="$(bash "$ROOT_DIR/audit_proxygo.sh" --test-case pass 2>&1)" && \
        [[ "$output" == *"[PASS]"* && "$output" == *"AUDITORÍA FINALIZADA CON ÉXITO"* && "$output" != *"[FAIL]"* ]]; then
        pass_test "autoprueba: caso aprobado sin falsos errores"
    else
        fail_test "autoprueba: el caso aprobado produjo un error o no terminó correctamente"
    fi

    if output="$(bash "$ROOT_DIR/audit_proxygo.sh" --test-case fail 2>&1)"; then
        fail_test "autoprueba: un caso fallido devolvió código cero"
    elif [[ "$output" == *"[FAIL]"* && "$output" != *"AUDITORÍA FINALIZADA CON ÉXITO"* ]]; then
        pass_test "autoprueba: un fallo devuelve error y suprime el éxito"
    else
        fail_test "autoprueba: reporte incorrecto para un caso fallido"
    fi

    if output="$(bash "$ROOT_DIR/audit_proxygo.sh" --test-case interrupt "$interrupt_file" 2>&1)"; then
        fail_test "autoprueba: una interrupción devolvió código cero"
    elif [[ -s "$interrupt_file" ]]; then
        pid="$(<"$interrupt_file")"
        if kill -0 "$pid" 2>/dev/null; then
            fail_test "autoprueba: quedó vivo un proceso tras la interrupción"
        else
            pass_test "autoprueba: trap eliminó el proceso temporal tras SIGTERM"
        fi
    else
        fail_test "autoprueba: no se registró el proceso temporal"
    fi

    if ((FAIL_COUNT > 0)); then
        exit 1
    fi
}

if [[ "${1:-}" == "--test-case" ]]; then
    test_case "${2:-}" "${3:-}"
elif [[ "${1:-}" == "--self-test" ]]; then
    self_test
    exit 0
elif (($# > 0)); then
    fail_test "opción desconocida: $1"
    exit 2
fi

printf "${CYAN}=====================================================\n"
printf "       AUDITORÍA TÉCNICA INTEGRAL - PROXYGO\n"
printf "=====================================================${NC}\n"

for dependency in cargo go curl python3 openssl grep; do
    if ! command -v "$dependency" >/dev/null 2>&1; then
        fail_test "dependencia obligatoria no encontrada: $dependency"
        exit 1
    fi
done
pass_test "dependencias requeridas disponibles"

if bash -n "$ROOT_DIR/audit_proxygo.sh"; then
    pass_test "sintaxis Bash válida"
else
    fail_test "sintaxis Bash inválida"
    exit 1
fi

if grep -rnE '\.unwrap\(\)|unsafe\s*\{' engine-rust/src/; then
    warn_test "se encontraron .unwrap() o bloques unsafe en engine-rust/src; revisar rutas de red"
else
    pass_test "sin .unwrap() ni bloques unsafe detectados en engine-rust/src"
fi

require_command "Cargo Clippy sin warnings" cargo clippy --manifest-path engine-rust/Cargo.toml -- -D warnings
require_command "tests unitarios Rust" cargo test --manifest-path engine-rust/Cargo.toml --quiet
require_command "build de release Rust" cargo build --manifest-path engine-rust/Cargo.toml --release --quiet
require_command "Go Vet" go vet ./cmd/...
require_command "tests Go con detector de carreras" go test -race ./cmd/...
require_command "build Go con detector de carreras" go build -race -o "$TMP_ROOT/proxygo-bin" ./cmd/proxygo

read -r MOCK_PORT PROXY_PORT DASH_PORT < <(python3 -c '
import socket
sockets = []
try:
    for _ in range(3):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sockets.append(sock)
    print(*(sock.getsockname()[1] for sock in sockets))
finally:
    for sock in sockets:
        sock.close()
')
if [[ -z "$MOCK_PORT" || -z "$PROXY_PORT" || -z "$DASH_PORT" ]]; then
    fail_test "no se pudieron asignar puertos efímeros para las pruebas"
    exit 1
fi
pass_test "puertos de prueba efímeros disponibles"

ADMIN_TOKEN="$(openssl rand -hex 32)"
printf 'header = "Origin: http://127.0.0.1:%s"\nheader = "Authorization: Bearer %s"\n' \
    "$DASH_PORT" "$ADMIN_TOKEN" > "$ADMIN_CURL_CONFIG"
chmod 600 "$ADMIN_CURL_CONFIG"
export NO_PROXY= no_proxy=

python3 - "$MOCK_PORT" <<'PY' &
import http.server
import sys

http_port = int(sys.argv[1])
secret = b"sk-ant-api03-99887766554433221100aabbccddeeff"

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass

http.server.ThreadingHTTPServer(("127.0.0.1", http_port), Handler).serve_forever()
PY
MOCK_PID=$!
PIDS+=("$MOCK_PID")
wait_for_http "servidor mock HTTP" "http://127.0.0.1:$MOCK_PORT/health" "$MOCK_PID"

PROXYGO_SOCK_PATH="$SOCK_PATH" ./engine-rust/target/release/proxygo-engine >"$TMP_ROOT/rust.log" 2>&1 &
RUST_PID=$!
PIDS+=("$RUST_PID")
for ((attempt = 0; attempt < 60; attempt++)); do
    if ! kill -0 "$RUST_PID" 2>/dev/null; then
        fail_test "motor Rust terminó durante el arranque"
        exit 1
    fi
    if [[ -S "$SOCK_PATH" ]]; then
        break
    fi
    sleep 0.1
done
if [[ ! -S "$SOCK_PATH" ]]; then
    fail_test "el motor Rust no creó su socket UDS"
    exit 1
fi
pass_test "motor Rust disponible mediante UDS"
SOCK_PERMS="$(python3 -c 'import os,sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o777)[2:])' "$SOCK_PATH")"
if [[ "$SOCK_PERMS" == "660" || "$SOCK_PERMS" == "600" ]]; then
    pass_test "permisos seguros del socket Unix ($SOCK_PERMS)"
else
    fail_test "permisos inseguros del socket Unix ($SOCK_PERMS; se requiere 660 o 600)"
fi

PROXYGO_SOCK_PATH="$SOCK_PATH" \
PROXYGO_PROXY_ADDR="127.0.0.1:$PROXY_PORT" \
PROXYGO_DASH_ADDR="127.0.0.1:$DASH_PORT" \
PROXYGO_ADMIN_TOKEN="$ADMIN_TOKEN" \
PROXYGO_MAX_BODY_BYTES=256 \
PROXYGO_FAILURE_POLICY=FAIL_OPEN \
    "$TMP_ROOT/proxygo-bin" >"$TMP_ROOT/proxygo.log" 2>&1 &
GO_PID=$!
PIDS+=("$GO_PID")
wait_for_http "dashboard" "http://127.0.0.1:$DASH_PORT/api/state" "$GO_PID"
if python3 - "$PROXY_PORT" <<'PY'
import socket
import sys

with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=2):
    pass
PY
then
    pass_test "proxy HTTP escuchando solo en loopback"
else
    fail_test "proxy HTTP no abrió su puerto de loopback"
    exit 1
fi

if curl --noproxy "" --connect-timeout 2 --max-time 5 -fsS \
    --config "$ADMIN_CURL_CONFIG" -X POST "http://127.0.0.1:$DASH_PORT/api/mode" \
    -H 'Content-Type: application/json' -d '{"mode":"SANITIZE"}' \
    -o "$TMP_ROOT/mode-response" && grep -q 'SANITIZE' "$TMP_ROOT/mode-response"; then
    pass_test "configuración del modo SANITIZE mediante API"
else
    fail_test "no se pudo configurar el modo SANITIZE"
    exit 1
fi

if RESPONSE="$(curl --noproxy "" --connect-timeout 2 --max-time 10 -fsS \
    --proxy "http://127.0.0.1:$PROXY_PORT" -X POST \
    "http://127.0.0.1:$MOCK_PORT/v1/messages" -H 'Content-Type: application/json' \
    -d '{"prompt":"Mi llave es sk-ant-api03-99887766554433221100aabbccddeeff"}')" && \
    [[ "$RESPONSE" == *"REDACTED"* ]]; then
    pass_test "sanitización de llave Anthropic"
else
    fail_test "la llave Anthropic no fue sanitizada o el proxy no respondió"
fi

if RESPONSE_NESTED="$(curl --noproxy "" --connect-timeout 2 --max-time 10 -fsS \
    --proxy "http://127.0.0.1:$PROXY_PORT" -X POST \
    "http://127.0.0.1:$MOCK_PORT/v1/chat" -H 'Content-Type: application/json' \
    -d '{"data":{"nested":["texto normal","Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"]}}')" && \
    [[ "$RESPONSE_NESTED" == *"REDACTED"* ]]; then
    pass_test "detección de JWT anidado"
else
    fail_test "el JWT anidado no fue detectado o el proxy no respondió"
fi

python3 - "$TMP_ROOT/large-body" <<'PY'
import sys

with open(sys.argv[1], "wb") as body:
    body.write(b"x" * 1024)
PY
if HTTP_CODE="$(curl --noproxy "" --connect-timeout 2 --max-time 10 -sS -o "$TMP_ROOT/large-response" \
    -w '%{http_code}' --proxy "http://127.0.0.1:$PROXY_PORT" -X POST \
    "http://127.0.0.1:$MOCK_PORT/large" --data-binary "@$TMP_ROOT/large-body" 2>/dev/null)" && \
    [[ "$HTTP_CODE" == "413" ]]; then
    pass_test "bloqueo de cuerpos HTTP que exceden el límite"
else
    fail_test "un cuerpo HTTP demasiado grande devolvió HTTP $HTTP_CODE en vez de 413"
fi

if HTTP_CODE="$(curl --noproxy "" --connect-timeout 2 --max-time 10 -sS -o "$TMP_ROOT/unauthorized-response" \
    -w '%{http_code}' -X POST "http://127.0.0.1:$DASH_PORT/api/mode" \
    -H "Origin: http://127.0.0.1:$DASH_PORT" \
    -H 'Content-Type: application/json' -d '{"mode":"MONITOR"}')" && [[ "$HTTP_CODE" == "401" ]]; then
    pass_test "API administrativa rechaza solicitudes sin autorización"
else
    fail_test "API administrativa devolvió HTTP ${HTTP_CODE:-sin respuesta} sin autorización (esperado 401)"
fi

require_command "sanitización de respuestas gzip/deflate" go test -race ./cmd/proxygo -run '^TestInspectResponseCompressedSanitizationAndFraming$' -count=1
require_command "inspección HTTPS end-to-end mediante CONNECT" go test -race ./cmd/proxygo -run '^TestMITMTunnelEndToEnd$' -count=1

if python3 - "$MOCK_PORT" "$PROXY_PORT" <<'PY'
import concurrent.futures
import json
import sys
import urllib.request

mock_port, proxy_port = map(int, sys.argv[1:])

def send_req(index):
    payload = json.dumps({"id": index, "secret": "AKIAIOSFODNN7EXAMPLE"}).encode()
    request = urllib.request.Request(
        f"http://127.0.0.1:{mock_port}/concurrent",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{proxy_port}"})
    )
    with opener.open(request, timeout=10) as response:
        return response.status, response.read().decode()

with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
    results = list(executor.map(send_req, range(100)))
passed = sum(status == 200 and "REDACTED" in body for status, body in results)
print(f"Completadas: {passed}/100")
if passed != 100:
    raise SystemExit("Algunas peticiones concurrentes fallaron o no fueron sanitizadas")
PY
then
    pass_test "100 peticiones concurrentes sin corrupción de datos"
else
    fail_test "falló la prueba de 100 peticiones concurrentes"
fi

kill -KILL "$RUST_PID"
if wait "$RUST_PID" 2>/dev/null; then
    fail_test "el motor Rust no terminó tras SIGKILL"
else
    pass_test "el motor Rust terminó tras SIGKILL para la prueba de resiliencia"
fi
HTTP_CODE="$(curl --noproxy "" --connect-timeout 2 --max-time 5 -sS -o "$TMP_ROOT/engine-down-response" \
    -w '%{http_code}' --proxy "http://127.0.0.1:$PROXY_PORT" -X POST \
    "http://127.0.0.1:$MOCK_PORT/health" -H 'Content-Type: application/json' \
    -d '{"ping":"pong"}' 2>/dev/null)"
if [[ "$HTTP_CODE" == "200" || "$HTTP_CODE" == "503" ]]; then
    pass_test "el proxy Go sobrevivió a la caída del motor Rust (HTTP $HTTP_CODE)"
else
    fail_test "el proxy Go no sobrevivió a la caída de Rust (HTTP $HTTP_CODE)"
fi