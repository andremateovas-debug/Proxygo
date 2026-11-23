# Pruebas rápidas en vivo para ver el dashboard reaccionar

Abre el dashboard en la dirección configurada (por defecto **`http://127.0.0.1:8081`**) o mediante túnel SSH si estás en un VPS. Alterna el selector superior entre **`MONITOR`**, **`SANITIZE`** y **`BLOCK`** mientras lanzas las peticiones.

> **Puertos:** El bloque siguiente toma primero `PROXYGO_PROXY_ADDR` y `PROXYGO_DASH_ADDR`, luego los alias `PROXY_ADDR` y `DASH_ADDR`, y finalmente los puertos predeterminados. Admite direcciones con o sin `http://`:
> ```bash
> PROXY_ADDR="${PROXYGO_PROXY_ADDR:-${PROXY_ADDR:-127.0.0.1:8080}}"
> DASH_ADDR="${PROXYGO_DASH_ADDR:-${DASH_ADDR:-127.0.0.1:8081}}"
> case "$PROXY_ADDR" in http://*|https://*) ;; *) PROXY_ADDR="http://$PROXY_ADDR" ;; esac
> case "$DASH_ADDR" in http://*|https://*) ;; *) DASH_ADDR="http://$DASH_ADDR" ;; esac
> export PROXY_ADDR DASH_ADDR
> ```

---

### Test 1: Solicitud simple y segura (Prompt)

```bash
curl -i -x "$PROXY_ADDR" -X POST http://httpbin.org/post \
  -H "Content-Type: application/json" \
  -d '{"model":"claude-3-7-sonnet","prompt":"Explica que es un Unix Domain Socket"}'
```

### Test 2: Fuga de API Key (Anthropic)

```bash
curl -i -x "$PROXY_ADDR" -X POST http://httpbin.org/post \
  -H "Content-Type: application/json" \
  -d '{"model":"claude-3-7-sonnet","prompt":"Mi llave es sk-ant-api03-99887766554433221100aabbccddeeff"}'
```

### Test 3: Token JWT / Bearer en JSON anidado

```bash
curl -i -x "$PROXY_ADDR" -X POST http://httpbin.org/post \
  -H "Content-Type: application/json" \
  -d '{"data":{"auth":"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}}'
```

### Test 4: Llave AWS + cadena de alta entropía

```bash
curl -i -x "$PROXY_ADDR" -X POST http://httpbin.org/post \
  -H "Content-Type: application/json" \
  -d '{"aws_key":"AKIAIOSFODNN7EXAMPLE","secret_token":"8f9d8a7s6d5f4g3h2j1k0l9z8x7c6v5b"}'
```

### Test 5: Inspección HTTPS MITM (requiere `PROXYGO_MITM_ENABLED=true`)

Exporta temporalmente el certificado público de la CA de ProxyGo y prueba una petición cifrada:

```bash
sudo proxygo-cli ca-export /tmp/ca.crt

# Prueba en SANITIZE o BLOCK cambiando el modo desde la API (o desde el dashboard)
curl -s -X POST "$DASH_ADDR/api/mode" -d '{"mode":"SANITIZE"}'

curl -i --proxy "$PROXY_ADDR" --cacert /tmp/ca.crt \
  -X POST https://httpbin.org/post \
  -H "Content-Type: application/json" \
  -d '{"prompt":"llave de prueba sk-ant-api03-99887766554433221100aabbccddeeff"}'
```

Al terminar, restaura el modo `MONITOR` y limpia el certificado temporal:

```bash
curl -s -X POST "$DASH_ADDR/api/mode" -d '{"mode":"MONITOR"}'
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