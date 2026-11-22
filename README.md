# ProxyGo

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![Rust Version](https://img.shields.io/badge/Rust-1.78+-000000?logo=rust&logoColor=white)](https://www.rust-lang.org/)

**Inspector y Firewall de Tráfico HTTP/JSON (DLP - Data Loss Prevention) con observabilidad en tiempo real.**

ProxyGo actúa como un intermediario local o en VPS que intercepta peticiones salientes hacia APIs externas (como Anthropic, OpenAI, Stripe o webhooks internos), clasifica el tráfico y evita la fuga accidental de credenciales, tokens o datos sensibles mediante expresiones regulares y cálculo de entropía de Shannon, ofreciendo un panel web ligero en tiempo real.

---

## Arquitectura del Sistema

ProxyGo separa el plano de red y control del motor de inspección profunda para garantizar baja latencia y tolerancia a fallos:

```text
[App / Script / CLI]
        │  HTTP/JSON (127.0.0.1:8080)
        ▼
┌───────────────────────────────┐      SSE (:8081)      ┌─────────────────────────┐
│     Plano de Red (Go)         │ ────────────────────▶ │  Dashboard Web          │
│  ReverseProxy + Políticas     │                       │  HTML / CSS / Chart.js  │
└───────────────┬───────────────┘                       └─────────────────────────┘
                │ Unix Domain Socket (/run/proxygo/engine.sock)
                ▼
┌───────────────────────────────┐
│   Motor de Inspección (Rust)  │
│  Regex + Entropía + Sanitizar │
└───────────────────────────────┘
```

* **Plano de Red y Control (Go):** Gestiona el proxy HTTP, aplica políticas de resiliencia (*Fail-Open* / *Fail-Closed*), recalcula cabeceras dinámicamente tras la sanitización y transmite eventos en vivo mediante *Server-Sent Events* (SSE) sirviendo el frontend embebido (`go:embed`). Por seguridad, ambos servidores escuchan estrictamente en `127.0.0.1`.
* **Motor de Inspección DLP (Rust):** Corre como un proceso independiente comunicado por **Unix Domain Sockets (UDS)** con protocolo NDJSON. Analiza cargas útiles en microsegundos sin pausas de recolección de basura, detectando secretos conocidos y cadenas de alta entropía.
* **Aislamiento de Fallos:** Si el motor de Rust sufre una interrupción o excede el timeout configurado (15 ms), `systemd` lo reinicia automáticamente mientras el proxy en Go mantiene el control del tráfico sin colgar las conexiones.

---

## Características Principales

* **Detección Híbrida (Regex + Entropía de Shannon):** Identifica llaves de API (`sk-ant-...`, `sk-proj-...`, `AKIA...`), tokens Bearer/JWT, cadenas de conexión a bases de datos y secretos aleatorios sin prefijo conocido.
* **Tres Modos de Operación en Caliente:**
  * `MONITOR`: Audita, clasifica y registra el tráfico sin alterar las peticiones.
  * `SANITIZE`: Reemplaza credenciales detectadas por etiquetas seguras (`[REDACTED_...]`) antes de que salgan a internet.
  * `BLOCK`: Detiene la petición inmediatamente con estado `HTTP 403 Forbidden` y emite una alerta crítica.
* **Dashboard Ligero sin Frameworks Pesados:** Interfaz web construida con HTML, CSS puro y Chart.js embebida directamente en el binario de Go.
* **Administración Integrada:** CLI (`proxygo-cli`) y unidades `systemd` endurecidas para operar ambos servicios de forma unificada.

---

## Instalación

### Opción 1: Instalación rápida en Debian / Ubuntu
Descarga e instala el paquete `.deb` oficial desde GitHub Releases:

```bash
curl -fsSL [https://raw.githubusercontent.com/andremateovas-debug/Proxygo/main/install.sh](https://raw.githubusercontent.com/andremateovas-debug/Proxygo/main/install.sh) | bash
```

### Opción 2: Compilación desde el código fuente

**Requisitos:** Go 1.22+, Rust / Cargo 1.78+ y Linux (o WSL2) para soporte nativo de Unix Domain Sockets.

```bash
git clone [https://github.com/andremateovas-debug/Proxygo.git](https://github.com/andremateovas-debug/Proxygo.git)
cd Proxygo

make build
```

Los binarios generados quedarán en `build/proxygo-proxy`, `build/proxygo-cli` y `engine-rust/target/release/proxygo-engine`.

---

## Uso y Comandos

### Gestión de Servicios
```bash
sudo proxygo-cli start            # Inicia el motor Rust y el proxy Go
sudo proxygo-cli stop             # Detiene ambos servicios
sudo proxygo-cli restart engine   # Reinicia solo el motor Rust sin cortar conexiones activas
sudo proxygo-cli status           # Muestra estado de los procesos y del socket UDS
```

### Enrutar tráfico a través de ProxyGo
Configura la variable de entorno `HTTP_PROXY` en tu terminal, script o aplicación:

```bash
export HTTP_PROXY="[http://127.0.0.1:8080](http://127.0.0.1:8080)"

# Ejemplo de petición auditada
curl -x [http://127.0.0.1:8080](http://127.0.0.1:8080) -X POST [http://httpbin.org/post](http://httpbin.org/post) \
  -H "Content-Type: application/json" \
  -d '{"model": "claude-3-7-sonnet", "prompt": "Hola mundo"}'
```

Accede al panel de monitoreo en tiempo real desde tu navegador en: **`http://127.0.0.1:8081`**

---

## Solución de Problemas y Despliegue en VPS

### 1. Los servicios aparecen como `inactive` tras instalar el `.deb`
El paquete habilita las unidades en `systemd` para arrancar con el sistema, pero si tras la instalación `sudo proxygo-cli status` muestra `inactive` y `engine.sock missing`, inícialos manualmente:

```bash
sudo proxygo-cli start
sudo proxygo-cli status
```

### 2. Conflicto de puertos (`:8080` o `:8081` ocupado por Docker, Adminer, etc.)
ProxyGo **no cambia de puerto automáticamente**. Si en tu servidor o VPS ya tienes un contenedor Docker (como Adminer) u otro servicio escuchando en el puerto `8080`, `proxygo-proxy.service` fallará al arrancar con `bind: address already in use`.

1. Verifica si los puertos están ocupados:
   ```bash
   sudo ss -tulnp | grep -E ':(8080|8081)\b'
   ```
2. Si `:8080` está en uso y no quieres mover tu contenedor, reasigna el puerto de ProxyGo mediante un *override* de `systemd` usando las variables `PROXYGO_PROXY_ADDR` y `PROXYGO_DASH_ADDR`:
   ```bash
   sudo mkdir -p /etc/systemd/system/proxygo-proxy.service.d
   cat << 'EOF' | sudo tee /etc/systemd/system/proxygo-proxy.service.d/override.conf
   [Service]
   Environment="PROXYGO_PROXY_ADDR=127.0.0.1:8088"
   # Opcional si el 8081 también estuviera ocupado:
   # Environment="PROXYGO_DASH_ADDR=127.0.0.1:8089"
   EOF

   sudo systemctl daemon-reload
   sudo systemctl restart proxygo-proxy.service
   sudo proxygo-cli status
   ```
   En este caso, enruta tu tráfico apuntando al nuevo puerto (`http://127.0.0.1:8088`).

### 3. Ver el Dashboard desde un VPS remoto
Por seguridad, tanto el proxy como el panel web escuchan únicamente en `127.0.0.1` para evitar que terceros en internet intercepten el tráfico SSE o cambien el modo de operación en `/api/mode`. Para abrir el panel desde tu computadora local hacia un VPS remoto, crea un túnel SSH:

```bash
ssh -L 8081:127.0.0.1:8081 usuario@ip-de-tu-vps
```

Luego abre `http://127.0.0.1:8081` en tu navegador local.

---

## Auditoría y Pruebas

El repositorio incluye una suite automatizada para verificar la detección de fugas, sanitización de JSON anidado, concurrencia y tolerancia a fallos ante caídas del motor Rust:

```bash
chmod +x audit_proxygo.sh
./audit_proxygo.sh
```

Si instalaste el paquete `.deb`, también puedes lanzar pruebas rápidas contra el proxy en ejecución con:

```bash
/usr/share/proxygo/test-anomalies.sh
```

---

## Dashboard y ejemplos en vivo

![Dashboard de ProxyGo](readme-imgs/dashboard.png)

*Panel de monitoreo con métricas, tráfico por minuto y eventos recientes.*

### Ejemplos de detección

<table>
  <tr>
    <td align="center">
      <img src="readme-imgs/ejemplo2.png" alt="Detección y sanitización de una API key de Anthropic" width="100%"><br>
      <strong>Sanitización de una clave de Anthropic</strong>
    </td>
    <td align="center">
      <img src="readme-imgs/ejemplo3.png" alt="Detección y sanitización de una clave AWS" width="100%"><br>
      <strong>Sanitización de una clave AWS</strong>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="readme-imgs/ejemploseguro.png" alt="Solicitud segura sin secretos detectados" width="100%"><br>
      <strong>Solicitud segura</strong>
    </td>
    <td align="center">
      <img src="readme-imgs/enviobloqueado.png" alt="Evento bloqueado en el dashboard" width="100%"><br>
      <strong>Evento bloqueado</strong>
    </td>
  </tr>
</table>

Si quieres probar el dashboard con peticiones rápidas y ver cómo reaccionan las alertas, sigue las instrucciones de [Pruebas rápidas en vivo](test_de_reaccion.md).

---

## Licencia y Atribución

Este proyecto está licenciado bajo la **Licencia Apache, Versión 2.0**. Consulta los archivos [LICENSE](LICENSE) y [NOTICE](NOTICE) para más detalles.

Desarrollado por **Andre Mateo Vasquez Mosqueda / AM Devs**.