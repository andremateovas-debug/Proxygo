# Pruebas rápidas en vivo para ver el dashboard reaccionar

Abre el dashboard en **`http://127.0.0.1:8081`** (o mediante túnel SSH si estás en un VPS: `ssh -L 8081:127.0.0.1:8081 usuario@ip-vps`) y alterna el selector superior entre **`MONITOR`**, **`SANITIZE`** y **`BLOCK`** mientras lanzas las peticiones.

> **Nota de puerto:** Estos ejemplos usan el puerto por defecto `127.0.0.1:8080`. Si reasignaste el proxy a otro puerto mediante `override.conf` (por ejemplo `8088`), ajusta `PROXY_ADDR` antes de copiar los comandos:
> ```bash
> export PROXY_ADDR="http://127.0.0.1:8080"
> ```

---

### Test 1: Solicitud simple y segura (Prompt)

```bash
curl -i -x "${PROXY_ADDR:-http://127.0.0.1:8080}" -X POST http://httpbin.org/post \
  -H "Content-Type: application/json" \
  -d '{"model":"claude-3-7-sonnet","prompt":"Explica que es un Unix Domain Socket"}'
```

### Test 2: Fuga de API Key (Anthropic)

```bash
curl -i -x "${PROXY_ADDR:-http://127.0.0.1:8080}" -X POST http://httpbin.org/post \
  -H "Content-Type: application/json" \
  -d '{"model":"claude-3-7-sonnet","prompt":"Mi llave es sk-ant-api03-99887766554433221100aabbccddeeff"}'
```

### Test 3: Token JWT / Bearer en JSON anidado

```bash
curl -i -x "${PROXY_ADDR:-http://127.0.0.1:8080}" -X POST http://httpbin.org/post \
  -H "Content-Type: application/json" \
  -d '{"data":{"auth":"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}}'
```

### Test 4: Llave AWS + cadena de alta entropía

```bash
curl -i -x "${PROXY_ADDR:-http://127.0.0.1:8080}" -X POST http://httpbin.org/post \
  -H "Content-Type: application/json" \
  -d '{"aws_key":"AKIAIOSFODNN7EXAMPLE","secret_token":"8f9d8a7s6d5f4g3h2j1k0l9z8x7c6v5b"}'
```

### Test 5: Inspección HTTPS MITM (requiere `PROXYGO_MITM_ENABLED=true`)

Exporta temporalmente el certificado público de la CA de ProxyGo y prueba una petición cifrada:

```bash
sudo proxygo-cli ca-export /tmp/ca.crt

# Prueba en SANITIZE o BLOCK cambiando el modo desde la API (o desde el dashboard)
curl -s -X POST http://127.0.0.1:8081/api/mode -d '{"mode":"SANITIZE"}'

curl -i --proxy "${PROXY_ADDR:-http://127.0.0.1:8080}" --cacert /tmp/ca.crt \
  -X POST https://httpbin.org/post \
  -H "Content-Type: application/json" \
  -d '{"prompt":"llave de prueba sk-ant-api03-99887766554433221100aabbccddeeff"}'
```

Al terminar, restaura el modo `MONITOR` y limpia el certificado temporal:

```bash
curl -s -X POST http://127.0.0.1:8081/api/mode -d '{"mode":"MONITOR"}'
sudo rm -f /tmp/ca.crt
```

---

### Alternativa offline para HTTP plano (si `httpbin.org` está lento)

Para los Tests 1–4 por HTTP plano puedes levantar un servidor echo local temporal en el puerto `18082` y sustituir `http://httpbin.org/post` por `http://127.0.0.1:18082/post` *(no aplica al Test 5 HTTPS si `PROXYGO_BLOCK_PRIVATE_NETWORKS` está activo)*:

```bash
python3 -c "from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
 def do_POST(s):
  b=s.rfile.read(int(s.headers.get('Content-Length',0)))
  s.send_response(200); s.send_header('Content-Type','application/json'); s.end_headers(); s.wfile.write(b)
HTTPServer(('127.0.0.1',18082),H).serve_forever()" &
```

Para detenerlo al finalizar:

```bash
pkill -f "18082"
```