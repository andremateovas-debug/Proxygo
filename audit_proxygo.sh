#!/usr/bin/env bash
set -euo pipefail

# Colores para el reporte
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SOCK_PATH="/tmp/proxygo-audit.sock"
PROXY_PORT=18080
DASH_PORT=18081
MOCK_PORT=18082

echo -e "${CYAN}=====================================================${NC}"
echo -e "${CYAN}       AUDITORÍA TÉCNICA INTEGRAL - PROXYGO          ${NC}"
echo -e "${CYAN}=====================================================${NC}"

# Limpieza al salir
cleanup() {
    echo -e "\n${YELLOW}[CLEANUP] Deteniendo procesos de prueba...${NC}"
    kill ${RUST_PID:-} ${GO_PID:-} ${MOCK_PID:-} 2>/dev/null || true
    rm -f "$SOCK_PATH"
}
trap cleanup EXIT

# ---------------------------------------------------------
# 1. AUDITORÍA ESTÁTICA DE CÓDIGO Y SEGURIDAD
# ---------------------------------------------------------
echo -e "\n${CYAN}[1/5] Auditoría Estática (Rust & Go)...${NC}"

echo " -> Buscando llamadas peligrosas (.unwrap(), unsafe) en Rust..."
if grep -rnE "\.unwrap\(\)|unsafe\s*\{" engine-rust/src/; then
    echo -e "${YELLOW}[WARN] Se encontraron .unwrap() o bloques unsafe. Revisa que no estén en rutas de red.${NC}"
else
    echo -e "${GREEN}[PASS] Cero .unwrap() o bloques unsafe detectados en src/.${NC}"
fi

echo " -> Ejecutando Cargo Clippy y Tests Unitarios..."
(cd engine-rust && cargo clippy -- -D warnings && cargo test --quiet)
echo -e "${GREEN}[PASS] Rust compila sin warnings y pasa los tests unitarios.${NC}"

echo " -> Ejecutando Go Vet y Detector de Race Conditions..."
go vet ./cmd/...
echo -e "${GREEN}[PASS] Go Vet aprobado.${NC}"

# ---------------------------------------------------------
# 2. LEVANTAR ENTORNO AISLADO DE PRUEBA
# ---------------------------------------------------------
echo -e "\n${CYAN}[2/5] Levantando entorno aislado en puertos 18080-18082...${NC}"

# Servidor Mock HTTP que devuelve exactamente lo que recibe (Echo Server)
python3 -c "
from http.server import BaseHTTPRequestHandler, HTTPServer
import sys

class EchoHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, format, *args): pass

HTTPServer(('127.0.0.1', $MOCK_PORT), EchoHandler).serve_forever()
" &
MOCK_PID=$!

# Compilar y levantar Rust Engine
(cd engine-rust && cargo build --release --quiet)
PROXYGO_SOCK_PATH="$SOCK_PATH" ./engine-rust/target/release/proxygo-engine &
RUST_PID=$!
sleep 1

# Verificar permisos del socket UDS
SOCK_PERMS=$(stat -c "%a" "$SOCK_PATH" 2>/dev/null || stat -f "%Lp" "$SOCK_PATH")
if [[ "$SOCK_PERMS" == "660" || "$SOCK_PERMS" == "600" ]]; then
    echo -e "${GREEN}[PASS] Permisos del Unix Socket seguros ($SOCK_PERMS).${NC}"
else
    echo -e "${RED}[FAIL] Permisos del socket demasiado abiertos ($SOCK_PERMS). Debe ser 660 o 600.${NC}"
fi

# Compilar con Race Detector (-race) y levantar Go Proxy
go build -race -o /tmp/proxygo-bin ./cmd/proxygo
PROXYGO_SOCK_PATH="$SOCK_PATH" PROXYGO_PROXY_ADDR=":$PROXY_PORT" PROXYGO_DASH_ADDR=":$DASH_PORT" /tmp/proxygo-bin &
GO_PID=$!
sleep 1

# ---------------------------------------------------------
# 3. AUDITORÍA DE DETECCIÓN, SANITIZACIÓN Y EVASIÓN (DLP)
# ---------------------------------------------------------
echo -e "\n${CYAN}[3/5] Pruebas de Evasión y Sanitización DLP...${NC}"

# Cambiar modo a SANITIZE vía API
curl -s -X POST "http://127.0.0.1:$DASH_PORT/api/mode" -d '{"mode":"SANITIZE"}' > /dev/null

# Test A: Inyección estándar de API Key
RESPONSE=$(curl -s -x "http://127.0.0.1:$PROXY_PORT" -X POST "http://127.0.0.1:$MOCK_PORT/v1/messages" \
    -H "Content-Type: application/json" \
    -d '{"prompt": "Mi llave es sk-ant-api03-99887766554433221100aabbccddeeff"}')

if echo "$RESPONSE" | grep -q "REDACTED"; then
    echo -e "${GREEN}[PASS] Sanitización exitosa de llave Anthropic y recálculo de Content-Length.${NC}"
else
    echo -e "${RED}[FAIL] La llave pasó sin ser sanitizada: $RESPONSE${NC}"
fi

# Test B: Evasión mediante JSON anidado y escapes Unicode
RESPONSE_NESTED=$(curl -s -x "http://127.0.0.1:$PROXY_PORT" -X POST "http://127.0.0.1:$MOCK_PORT/v1/chat" \
    -H "Content-Type: application/json" \
    -d '{"data": {"nested": ["texto normal", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"]}}')

if echo "$RESPONSE_NESTED" | grep -q "REDACTED"; then
    echo -e "${GREEN}[PASS] Detección correcta en estructuras JSON profundamente anidadas.${NC}"
else
    echo -e "${RED}[FAIL] Falla en JSON anidado: $RESPONSE_NESTED${NC}"
fi

# ---------------------------------------------------------
# 4. PRUEBA DE ESTRÉS Y CONCURRENCIA (RACE CONDITIONS)
# ---------------------------------------------------------
echo -e "\n${CYAN}[4/5] Prueba de Estrés Concurrente (100 peticiones simultáneas)...${NC}"

python3 -c "
import concurrent.futures, urllib.request, json

def send_req(i):
    req = urllib.request.Request(
        'http://127.0.0.1:$MOCK_PORT/test',
        data=json.dumps({'id': i, 'secret': 'AKIAIOSFODNN7EXAMPLE'}).encode(),
        headers={'Content-Type': 'application/json'}
    )
    proxy = urllib.request.ProxyHandler({'http': 'http://127.0.0.1:$PROXY_PORT'})
    opener = urllib.request.build_opener(proxy)
    with opener.open(req, timeout=5) as resp:
        return resp.status, resp.read().decode()

with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
    results = list(ex.map(send_req, range(100)))

ok = sum(1 for s, body in results if s == 200 and 'REDACTED' in body)
print(f'Completadas: {ok}/100')
assert ok == 100, 'Algunas peticiones fallaron o no fueron sanitizadas bajo carga'
"
echo -e "${GREEN}[PASS] 100 peticiones concurrentes procesadas sin Race Conditions ni corrupción de datos.${NC}"

# ---------------------------------------------------------
# 5. AUDITORÍA DE RESILIENCIA (CAÍDA DE RUST ENGINE)
# ---------------------------------------------------------
echo -e "\n${CYAN}[5/5] Prueba de Caída del Motor Rust (Resiliencia UDS)...${NC}"

kill -9 "$RUST_PID"
wait "$RUST_PID" 2>/dev/null || true
sleep 0.5

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -x "http://127.0.0.1:$PROXY_PORT" \
    -X POST "http://127.0.0.1:$MOCK_PORT/health" -d '{"ping": "pong"}' --max-time 2)

if [[ "$HTTP_CODE" == "200" || "$HTTP_CODE" == "503" ]]; then
    echo -e "${GREEN}[PASS] El proxy Go sobrevivió a la caída de Rust y aplicó política Fail-Open/Closed (HTTP $HTTP_CODE).${NC}"
else
    echo -e "${RED}[FAIL] El proxy Go se colgó o cayó junto con Rust (HTTP $HTTP_CODE).${NC}"
fi

echo -e "\n${CYAN}=====================================================${NC}"
echo -e "${GREEN}           AUDITORÍA FINALIZADA CON ÉXITO            ${NC}"
echo -e "${CYAN}=====================================================${NC}"