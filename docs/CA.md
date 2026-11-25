# CA de ProxyGo para HTTPS MITM

ProxyGo puede inspeccionar tráfico HTTPS solo si el cliente confía en una Autoridad Certificadora (CA) propia. La CA se genera una sola vez y se reutiliza en disco; cada dominio interceptado recibe un certificado dinámico firmado en memoria por esa misma CA, nunca certificados autofirmados distintos por conexión.

---

## Configuración

Variables de entorno del servicio `proxygo-proxy` para la CA y túneles `CONNECT`:

| Variable | Por defecto | Uso |
|---|---|---|
| `PROXYGO_MITM_ENABLED` | `false` | Activa `CONNECT` con inspección TLS MITM desde el arranque. |
| `PROXYGO_CA_DIR` | `/var/lib/proxygo/ca` | Carpeta de la CA. Debe ser propia y privada de cada instalación. |
| `PROXYGO_CA_ORG` | `ProxyGo` | Organización del certificado raíz (`O=`). Solo se aplica al crear la CA por primera vez. |
| `PROXYGO_CONNECT_PORTS` | `443` | Puertos permitidos para `CONNECT`, separados por coma. |
| `PROXYGO_CONNECT_ALLOWED_HOSTS` | vacío | Hosts permitidos para `CONNECT`, separados por coma. Admite comodines (`*.example.com`) y `*`. **Obligatorio** para habilitar MITM. |
| `PROXYGO_CONNECT_MAX` | `128` | Número máximo de túneles `CONNECT` concurrentes. |

### Variables avanzadas de inspección y seguridad

| Variable | Valores admitidos | Uso |
|---|---|---|
| `PROXYGO_SECURITY_POLICY` | `ALLOW_UNINSPECTED`, `MONITOR_UNINSPECTED`, `BLOCK_UNINSPECTED` | Define cómo actuar ante tráfico no inspeccionable (*certificate pinning*, mTLS, HTTP/2, HTTP/3/QUIC, WebSockets, SSE o certificados inválidos) y ante fallos/timeouts del motor en HTTPS. |
| `PROXYGO_FAILURE_POLICY` | `FAIL_OPEN`, `FAIL_CLOSED` | Política cuando el motor Rust no responde o supera el timeout de 15 ms (en el servicio `systemd` viene fijada en `FAIL_CLOSED`). |
| `PROXYGO_INSPECT_REQUESTS` | `true` / `false` | Activa o desactiva la inspección DLP en el cuerpo de las peticiones salientes. |
| `PROXYGO_INSPECT_RESPONSES` | `true` / `false` | Activa o desactiva la inspección DLP en el cuerpo de las respuestas entrantes. |
| `PROXYGO_INSPECT_HEADERS` | `true` / `false` | Activa o desactiva la inspección y sanitización de cabeceras HTTP (por ejemplo, `Authorization`, `Cookie` o `X-API-Key`). |
| `PROXYGO_BLOCK_INVALID_CERTS` | `true` / `false` | Bloquea servidores destino con certificados TLS inválidos o expirados. |
| `PROXYGO_BLOCK_PRIVATE_NETWORKS` | `true` / `false` | Por defecto (`true`) bloquea destinos privados, loopback y link-local en `CONNECT` para prevenir SSRF. Usar `false` solo en redes de confianza. |
| `PROXYGO_MAX_BODY_BYTES` | entero (bytes) | Límite máximo solicitado para inspeccionar cada cuerpo. El motor NDJSON admite hasta 1 MiB por cuerpo; el límite efectivo es el menor entre ambos. |

Los cuerpos que superan el límite se detectan sin cargar todo el payload en memoria y nunca se envían truncados al motor como si estuvieran completos: en modo `MONITOR` pasan intactos marcados como `body_too_large` (`inspected=false`), y en modos `BLOCK` y `SANITIZE` se bloquean al no poder garantizar que estén libres de secretos.

### Ejemplo persistente con `systemd`

```bash
sudo systemctl edit proxygo-proxy.service
```

```ini
[Service]
Environment="PROXYGO_MITM_ENABLED=true"
Environment="PROXYGO_CA_ORG=Mi Organizacion"
Environment="PROXYGO_CONNECT_ALLOWED_HOSTS=api.example.com,*.trusted.example"
```

```bash
sudo systemctl daemon-reload
sudo systemctl restart proxygo-proxy.service
```

> En un despliegue centralizado, cada organización o entorno debe usar su propio `PROXYGO_CA_DIR` y `PROXYGO_CA_ORG`. Nunca compartas `ca.key` entre organizaciones ni repositorios.

---

## Archivos y permisos

- `ca.key`: clave privada ECDSA P-256 de la CA. Permisos `0600`. Nunca se copia, distribuye ni expone.
- `ca.crt`: certificado público de la CA raíz. Permisos `0644`.
- Directorio de la CA (`/var/lib/proxygo/ca`): permisos `0700` pertenecientes al usuario `proxygo`. Si el directorio tiene permisos abiertos para grupo u otros, ProxyGo rechazará arrancar o activar MITM.

ProxyGo no expone la clave privada por API, dashboard, TUI ni logs. Si `ca.key` se compromete, detén el servicio, elimina la carpeta de la CA, retira el certificado de los dispositivos cliente y genera una nueva CA.

---

## Estado y control en caliente (TUI, Dashboard y API)

El dashboard web (`http://127.0.0.1:8081`) y la TUI (`sudo proxygo-cli tui`) muestran en tiempo real si MITM está activo (`CA: ON/OFF`), la organización, la ruta de `ca.crt` y su fecha de vencimiento. El endpoint `GET /api/state` expone `ca_enabled`, `ca_org`, `ca_cert_path`, `ca_not_before` y `ca_not_after` (únicamente metadatos públicos, nunca `ca.key`).

### Activar o desactivar desde la TUI
1. Asegúrate de que el servicio tenga definido `PROXYGO_CONNECT_ALLOWED_HOSTS` en `systemd` (de lo contrario devolverá error al intentar encenderla).
2. Ejecuta la TUI con acceso al directorio de la CA y al token administrativo:
   ```bash
   sudo env PROXYGO_PROXY_ADDR="127.0.0.1:8080" PROXY_ADDR="127.0.0.1:8080" \
     PROXYGO_DASH_ADDR="127.0.0.1:8081" PROXYGO_CA_DIR="/var/lib/proxygo/ca" proxygo-cli tui
   ```
   *(Ajusta `127.0.0.1:8080` si reasignaste el puerto del proxy.)*
3. Pulsa **`Tab`** para abrir el menú operativo, selecciona **`CA / MITM`** y presiona **`Enter`**.

### Activar o desactivar vía API administrativa
Las mutaciones en `POST /api/ca` requieren el token administrativo (`/var/lib/proxygo/admin.token`) y un encabezado `Origin` del mismo origen:

```bash
ADMIN_TOKEN=$(sudo cat /var/lib/proxygo/admin.token)

# Activar MITM en caliente
curl -sS -X POST http://127.0.0.1:8081/api/ca \
  -H "Origin: http://127.0.0.1:8081" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"enabled":true}'

# Desactivar MITM en caliente
curl -sS -X POST http://127.0.0.1:8081/api/ca \
  -H "Origin: http://127.0.0.1:8081" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"enabled":false}'
```

Al activar MITM en caliente, ProxyGo valida los permisos de la carpeta, genera o carga `ca.crt`/`ca.key` y verifica que `PROXYGO_CONNECT_ALLOWED_HOSTS` no esté vacío. Al desactivarlo, rechaza nuevas peticiones `CONNECT` con HTTP `501` y cierra túneles interceptados sin borrar la CA del disco. Este cambio en caliente vive en memoria; al reiniciar `proxygo-proxy.service`, el servicio vuelve al estado definido en `systemd`.

---

## Exportar el certificado público

```bash
sudo proxygo-cli ca-export /tmp/proxygo-ca.crt
```

Si personalizaste `PROXYGO_CA_DIR`, pásalo al CLI:

```bash
sudo env PROXYGO_CA_DIR="/ruta/personalizada/ca" proxygo-cli ca-export /tmp/proxygo-ca.crt
```

---

## Instalación y confianza en clientes

### Ubuntu / Debian (almacén del sistema)
```bash
sudo proxygo-cli ca-export /usr/local/share/ca-certificates/proxygo-ca.crt
sudo update-ca-certificates
```

Para retirarla:
```bash
sudo rm -f /usr/local/share/ca-certificates/proxygo-ca.crt
sudo update-ca-certificates --fresh
```

Esto cubre `curl`, `wget` y herramientas que consultan `/etc/ssl/certs/ca-certificates.crt`. Firefox utiliza su propio almacén: **Configuración → Privacidad y seguridad → Certificados → Ver certificados → Autoridades → Importar**.

### Node.js y CLIs modernas (Claude Code, npm, undici, Python)
Runtimes como Node.js incorporan su propio almacén de certificados raíz y no leen `/etc/ssl/certs` a menos que se indique `NODE_EXTRA_CA_CERTS`. Para usar herramientas basadas en Node.js (como Claude Code) a través de ProxyGo MITM sin errores `SSL certificate verification failed`, exporta las variables en la misma sesión de terminal:

```bash
export HTTP_PROXY="http://127.0.0.1:8080"
export HTTPS_PROXY="http://127.0.0.1:8080"
export http_proxy="http://127.0.0.1:8080"
export https_proxy="http://127.0.0.1:8080"
export NODE_EXTRA_CA_CERTS="/usr/local/share/ca-certificates/proxygo-ca.crt"
export SSL_CERT_FILE="/etc/ssl/certs/ca-certificates.crt"
export REQUESTS_CA_BUNDLE="/etc/ssl/certs/ca-certificates.crt"
```

*(Sustituye `8080` por `8088` si reasignaste el puerto del proxy en tu servidor.)*

### Windows
En una terminal como Administrador:
```cmd
certutil -addstore -f "ROOT" proxygo-ca.crt
```

Para retirarla:
```cmd
certutil -delstore "ROOT" "ProxyGo Root CA"
```
*(Sustituye `"ProxyGo Root CA"` por el nombre configurado en `PROXYGO_CA_ORG` si lo cambiaste, o elimínala desde `certmgr.msc` → Entidades de certificación raíz de confianza.)*

### macOS
En el llavero del sistema:
```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain /tmp/proxygo-ca.crt
```

Para retirarla:
```bash
sudo security delete-certificate -c "ProxyGo Root CA" \
  /Library/Keychains/System.keychain
```

---

## Retirar completamente la CA de ProxyGo

1. Detén los servicios:
   ```bash
   sudo proxygo-cli stop
   ```
2. Elimina la carpeta privada de la CA en el servidor:
   ```bash
   sudo rm -rf /var/lib/proxygo/ca
   ```
3. Retira `proxygo-ca.crt` del almacén de confianza de los equipos cliente.

Al volver a iniciar ProxyGo con MITM activado se generará una CA completamente nueva.

---

## Límites conocidos

- ProxyGo negocia **HTTP/1.1** sobre TLS tanto con el cliente como con el servidor de origen. Clientes que exijan exclusivamente HTTP/2 o HTTP/3/QUIC no se descifran como HTTP/1.1 y se gestionan según `PROXYGO_SECURITY_POLICY`.
- Las aplicaciones con *certificate pinning* o mTLS (certificado de cliente) rechazarán la interceptación MITM.
- Solo se inspecciona tráfico HTTP sobre TLS; otros protocolos arbitrarios sobre `CONNECT` no son soportados.
- Los destinos privados, loopback y link-local están bloqueados por defecto (`PROXYGO_BLOCK_PRIVATE_NETWORKS=true`) para mitigar SSRF.
- Nunca expongas el puerto del proxy ni el puerto del panel web directamente a redes públicas sin túnel cifrado (como SSH o Tailscale) y firewall.