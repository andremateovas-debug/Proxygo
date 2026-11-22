# Pruebas rápidas en vivo para ver el dashboard reaccionar


### Test 1: Solicitud simple y segura (Prompt)

```bash
    curl -i -x http://127.0.0.1:8088 -X POST http://httpbin.org/post \
  -H "Content-Type: application/json" \
  -d '{"model":"claude-3-7-sonnet","prompt":"Explica que es un Unix Domain Socket"}'
```

### Test 2: Fuga de API Key (Anthropic):

```bash
    curl -i -x http://127.0.0.1:8088 -X POST http://httpbin.org/post \
  -H "Content-Type: application/json" \
  -d '{"model":"claude-3-7-sonnet","prompt":"Mi llave es sk-ant-api03-99887766554433221100aabbccddeeff"}'
```

### Test 3: Token JWT / Bearer en JSON anidado:

```bash
    curl -i -x http://127.0.0.1:8088 -X POST http://httpbin.org/post \
    -H "Content-Type: application/json" \
    -d '{"data":{"auth":"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}}'
```

### Test 4: Llave AWS + cadena de alta entropía:

```bash
    curl -i -x http://127.0.0.1:8088 -X POST http://httpbin.org/post \
  -H "Content-Type: application/json" \
  -d '{"aws_key":"AKIAIOSFODNN7EXAMPLE","secret_token":"8f9d8a7s6d5f4g3h2j1k0l9z8x7c6v5b"}'
```