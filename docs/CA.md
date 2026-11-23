# CA de ProxyGo para HTTPS MITM

ProxyGo puede inspeccionar HTTPS solo si el cliente confía en una CA propia.
La CA se genera una vez y se reutiliza; las conexiones nunca usan certificados
autofirmados distintos.

## Configuración

Variables de entorno del servicio `proxygo-proxy`:

| Variable | Por defecto | Uso |
|---|---|---|
| `PROXYGO_MITM_ENABLED` | `false` | Activa `CONNECT` con inspección TLS. |
| `PROXYGO_CA_DIR` | `/var/lib/proxygo/ca` | Carpeta de la CA. Debe ser propia de cada instalación. |
| `PROXYGO_CA_ORG` | `ProxyGo` | Organización del certificado raíz. Solo se usa al crear la CA. |
| `PROXYGO_CONNECT_PORTS` | `443` | Puertos permitidos para `CONNECT`, separados por coma. |
| `PROXYGO_CONNECT_ALLOWED_HOSTS` | vacío | Hosts permitidos, separados por coma. Admite `*.example.com` y `*`. Sin lista, el arranque falla. |
| `PROXYGO_CONNECT_MAX` | `128` | Túneles concurrentes máximos. |

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
  están bloqueados. El proxy no es un túnel abierto.
- No exponga el puerto del proxy a Internet sin autenticación y firewall.
