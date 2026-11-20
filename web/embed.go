package web

import "embed"

// Assets contiene los archivos estáticos de la interfaz del daemon.
//go:embed index.html app.js styles.css
var Assets embed.FS