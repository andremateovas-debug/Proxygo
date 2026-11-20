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
        │  HTTP/JSON (:8080)
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

* **Plano de Red y Control (Go):** Gestiona el proxy HTTP/HTTPS, aplica políticas de resiliencia (*Fail-Open* / *Fail-Closed*), recalcula cabeceras dinámicamente tras la sanitización y transmite eventos en vivo mediante *Server-Sent Events* (SSE) sirviendo el frontend embebido (`go:embed`).
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

### Opción 1: Instalación rápida vía APT (Debian / Ubuntu)
```bash
curl -fsSL https://andremateovas-debug.github.io/proxygo/gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/proxygo.gpg
echo "deb [signed-by=/usr/share/keyrings/proxygo.gpg] https://andremateovas-debug.github.io/proxygo stable main" | sudo tee /etc/apt/sources.list.d/proxygo.list
sudo apt update && sudo apt install proxygo
```

### Opción 2: Compilación desde el código fuente

**Requisitos:** Go 1.22+, Rust / Cargo 1.78+ y Linux (o WSL2) para soporte nativo de Unix Domain Sockets.

```bash
git clone https://github.com/andremateovas-debug/proxygo.git
cd proxygo

# 1. Compilar el motor de inspección en Rust
cd engine-rust && cargo build --release && cd ..

# 2. Compilar el proxy y la herramienta CLI en Go
go build -o bin/proxygo ./cmd/proxygo
go build -o bin/proxygo-cli ./cmd/proxygo-cli
```

---

## Uso y Comandos

### Gestión de Servicios
```bash
sudo proxygo-cli start            # Inicia el motor Rust y el proxy Go
sudo proxygo-cli stop             # Detiene ambos servicios
sudo proxygo-cli restart engine   # Reinicia solo el motor Rust sin cortar conexiones activas
proxygo-cli status                # Muestra estado de los procesos y del socket UDS
```

### Enrutar tráfico a través de ProxyGo
Configura la variable de entorno `HTTP_PROXY` en tu terminal, script o aplicación:
```bash
export HTTP_PROXY="http://127.0.0.1:8080"

# Ejemplo de petición auditada
curl -x http://127.0.0.1:8080 -X POST https://api.anthropic.com/v1/messages \
  -H "Content-Type: application/json" \
  -d '{"model": "claude-3-7-sonnet", "prompt": "Hola mundo"}'
```

Accede al panel de monitoreo en tiempo real desde tu navegador en: **`http://127.0.0.1:8081`**

---

## Auditoría y Pruebas

El repositorio incluye una suite automatizada para verificar la detección de fugas, sanitización de JSON anidado, concurrencia y tolerancia a fallos ante caídas del motor Rust:

```bash
chmod +x audit_proxygo.sh
./audit_proxygo.sh
```

---

## Licencia y Atribución

Este proyecto está licenciado bajo la **Licencia Apache, Versión 2.0**. Consulta los archivos [LICENSE](LICENSE) y [NOTICE](NOTICE) para más detalles.

Desarrollado por **Andre Mateo Vasquez Mosqueda / AM Devs**.