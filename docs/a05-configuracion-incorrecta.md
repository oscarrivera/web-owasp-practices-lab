# Configuración de seguridad incorrecta (A05)

El fallo: una API JSON sin cabeceras de marco, sniffing ni CSP se deja
incrustar o cachear. Express, además, anuncia `X-Powered-By` si no se
desactiva.

El control: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`,
`Content-Security-Policy` y `Cache-Control: no-store` en las respuestas.
`x-powered-by` está apagado.

Ruta: `GET /labs/a05`.
