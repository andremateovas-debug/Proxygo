# CA de ProxyGo para HTTPS MITM

ProxyGo puede inspeccionar HTTPS solo si el cliente confía en una CA propia.
La CA se genera una vez y se reutiliza; las conexiones nunca usan certificados
autofirmados distintos.

## Configuración

Variables de entorno del servicio `proxygo-proxy` para la CA y túneles `CONNECT`:

| Variable | Por defecto | Uso |
|---|---|---|
| `PROXYGO_MITM_ENABLED` | `false` | Activa `CONNECT` con inspección TLS. |
| `PROXYGO_CA_DIR` | `/var/lib/proxygo/ca` | Carpeta de la CA. Debe ser propia de cada instalación. |
| `PROXYGO_CA_ORG` | `ProxyGo` | Organización del certificado raíz. Solo se usa al crear la CA. |
| `PROXYGO_CONNECT_PORTS` | `443` | Puertos permitidos para `CONNECT`, separados por coma. |
| `PROXYGO_CONNECT_ALLOWED_HOSTS` | vacío | Hosts permitidos, separados por coma. Admite `*.example.com` y `*`. Sin lista, el arranque falla. |
| `PROXYGO_CONNECT_MAX` | `128` | Túneles concurrentes máximos. |

### Variables avanzadas de inspección y seguridad

| Variable | Valores admitidos | Uso |
|---|---|---|
| `PROXYGO_SECURITY_POLICY` | `ALLOW_UNINSPECTED`, `MONITOR_UNINSPECTED`, `BLOCK_UNINSPECTED` | Define cómo actuar ante tráfico no inspeccionable (certificate pinning, mTLS, HTTP/2, HTTP/3/QUIC, WebSockets, SSE, contenido comprimido o certificados inválidos) y ante fallos/timeouts del motor en HTTPS. |
| `PROXYGO_FAILURE_POLICY` | `FAIL_OPEN`, `FAIL_CLOSED` | Política cuando el motor Rust no responde o supera el timeout (en el servicio `systemd` viene fijada en `FAIL_CLOSED`). |
| `PROXYGO_INSPECT_REQUESTS` | `true` / `false` | Activa o desactiva la inspección DLP en el cuerpo de las peticiones salientes. |
| `PROXYGO_INSPECT_RESPONSES` | `true` / `false` | Activa o desactiva la inspección DLP en el cuerpo de las respuestas entrantes. |
| `PROXYGO_INSPECT_HEADERS` | `true` / `false` | Activa o desactiva la inspección y sanitización de cabeceras HTTP (por ejemplo, fuga de tokens `Authorization`). |
| `PROXYGO_BLOCK_INVALID_CERTS` | `true` / `false` | Controla el bloqueo de servidores destino con certificados TLS inválidos o expirados. |
| `PROXYGO_BLOCK_PRIVATE_NETWORKS` | `true` / `false` | Bloquea destinos en redes privadas, loopback, link-local, multicast y rangos reservados (protección SSRF). |
| `PROXYGO_MAX_BODY_BYTES` | entero (bytes) | Límite máximo solicitado para inspeccionar cada cuerpo. El motor NDJSON admite hasta 1 MiB por cuerpo; el límite efectivo es el menor entre ambos. |

Los cuerpos que superan el límite se detectan leyendo como máximo un byte
adicional y no se envían al motor como si estuvieran completos. En modo
`MONITOR` se retransmiten intactos y el evento queda marcado como
`body_too_large` con `inspected=false`. En modos `BLOCK` y `SANITIZE` se
bloquean, ya que el proxy no puede confirmar que el cuerpo completo esté libre
de secretos ni afirmar que lo saneó. Los errores de lectura también quedan
registrados como cuerpos no inspeccionados. El resto del cuerpo se mantiene en
streaming y no se carga completo en memoria.

Ejemplo con systemd:

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
sudo systemctl restart proxygo-proxy.service
```

En un despliegue centralizado, cada organización debe usar su propio
`PROXYGO_CA_DIR` y `PROXYGO_CA_ORG`. No comparta `ca.key` entre organizaciones.

## Archivos y permisos

- `ca.key`: clave privada de la CA. Permisos `0600`. No se copia ni se publica.
- `ca.crt`: certificado público de la CA. Permisos `0644`.
- La carpeta de la CA debe ser privada (`0700`); si no existe, se crea con esos
  permisos. Si existe con permisos para grupo u otros, ProxyGo se niega a
  arrancar.

ProxyGo no expone la clave privada por API, dashboard ni logs. Si `ca.key` se
filtra, cualquier equipo que confíe en esa CA queda expuesto: retire la CA,
genere una nueva y vuelva a distribuir el certificado público.

## Estado y control en caliente

El dashboard web y la TUI (`sudo proxygo-cli tui`) muestran el estado de MITM,
la organización, la ruta de `ca.crt` y su vencimiento. `GET /api/state` incluye
`ca_enabled`, `ca_org`, `ca_cert_path`, `ca_not_before` y `ca_not_after`; sólo
se consulta el certificado público, nunca `ca.key`.

La CA/MITM se puede alternar desde el dashboard o con:

```bash
curl -sS -X POST http://127.0.0.1:8081/api/ca \
  -H 'Content-Type: application/json' -d '{"enabled":true}'
curl -sS -X POST http://127.0.0.1:8081/api/ca \
  -H 'Content-Type: application/json' -d '{"enabled":false}'
```

Activar MITM vuelve a validar la carpeta y los permisos de la CA, carga o crea
el par de archivos si hace falta y exige `PROXYGO_CONNECT_ALLOWED_HOSTS` no
vacío. Desactivarlo rechaza nuevos `CONNECT` y cierra túneles interceptados,
pero conserva `ca.crt` y `ca.key`. Los cambios se notifican por SSE y aparecen
en el siguiente snapshot de estado. Proteja el acceso al panel como cualquier
interfaz de control del proxy.

## Exportar el certificado público

Con el paquete instalado:

```bash
sudo proxygo-cli ca-export /tmp/proxygo-ca.crt
```

También puede copiarse el archivo público:

```bash
sudo cp /var/lib/proxygo/ca/ca.crt /tmp/proxygo-ca.crt
```

Si cambió `PROXYGO_CA_DIR`, expórtelo también al usar el CLI o copie el archivo
desde esa ruta.

## Instalar en Ubuntu / Debian

```bash
sudo cp /tmp/proxygo-ca.crt /usr/local/share/ca-certificates/proxygo-ca.crt
sudo update-ca-certificates
```

Para retirarla:

```bash
sudo rm /usr/local/share/ca-certificates/proxygo-ca.crt
sudo update-ca-certificates --fresh
```

Esto cubre curl, wget y programas que usan el almacén del sistema. Firefox usa
su propio almacén: Configuración → Privacidad y seguridad → Certificados →
Ver certificados → Autoridades → Importar.

## Instalar en Windows

Como administrador:

```cmd
certutil -addstore -f "ROOT" proxygo-ca.crt
```

También se puede usar `certmgr.msc` → Entidades de certificación raíz de
confianza → Importar.

Para retirarla:

```cmd
certutil -delstore "ROOT" "ProxyGo Root CA"
```

Sustituya `ProxyGo Root CA` por el nombre real si cambió `PROXYGO_CA_ORG`.
También puede eliminarse desde `certmgr.msc`.

## Instalar en macOS

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

También puede hacerse desde Acceso a Llaveros → Sistema → Certificados. Si el
navegador usa Firefox, impórtela en su almacén propio.

## Retirar la CA de ProxyGo

1. Detenga el servicio:
   ```bash
   sudo proxygo-cli stop
   ```
2. Retire la carpeta de la CA:
   ```bash
   sudo rm -rf /var/lib/proxygo/ca
   ```
3. Retire también el certificado de confianza de los dispositivos.

Al arrancar de nuevo con MITM activo se generará una CA distinta. Los clientes
deben retirar la anterior y confiar en la nueva.

## Límites conocidos

- Se anuncia solo HTTP/1.1 sobre TLS, tanto hacia el cliente como hacia el
  servidor. Los clientes que exigen HTTP/2 pueden fallar; la mayoría negocia
  HTTP/1.1.
- Las aplicaciones con certificate pinning rechazarán la intercepción.
- Solo se intercepta HTTP sobre TLS. Otros protocolos que usan `CONNECT` no
  funcionan.
- Los destinos privados, loopback, link-local, multicast y rangos reservados
  están bloqueados por defecto (`PROXYGO_BLOCK_PRIVATE_NETWORKS`). El proxy no
  es un túnel abierto.
- El comportamiento ante conexiones que no pueden inspeccionarse (pinning, mTLS,
  WebSockets, SSE o fallos del motor) depende de `PROXYGO_SECURITY_POLICY`.
- No exponga el puerto del proxy a Internet sin autenticación y firewall.