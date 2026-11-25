# ENrutar datos de "claude" a proxygo

```bash
export HTTP_PROXY="http://127.0.0.1:8088"
export HTTPS_PROXY="http://127.0.0.1:8088"
export http_proxy="http://127.0.0.1:8088"
export https_proxy="http://127.0.0.1:8088"
export NODE_EXTRA_CA_CERTS="/var/lib/proxygo/ca/ca.crt"
export SSL_CERT_FILE="/etc/ssl/certs/ca-certificates.crt"
/usr/bin/claude
```
