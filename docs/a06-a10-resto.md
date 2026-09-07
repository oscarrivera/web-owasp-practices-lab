# A06, A08, A09 y A10

## A06 — Componentes vulnerables y desactualizados

No filtrar versión de runtime, pid ni plataforma. `/labs/a06` responde
`{ status, mode }`. El inventario de dependencias vive en el proceso de
build y en el SCA, no en un endpoint público.

## A08 — Fallos de integridad

Un webhook sin HMAC acepta cualquier cuerpo. `/labs/a08` exige cabecera
`x-signature` (HMAC-SHA256 del `payload`) comparada en tiempo constante.
Secreto mínimo: 32 caracteres.

## A09 — Registro y monitorización

El log de autenticación guarda usuario, resultado y motivo. Nunca la
contraseña. `redactSecrets` sustituye claves que coinciden con
password/secret/token. `/labs/a09` demuestra la redacción.

## A10 — SSRF

No hay fetch abierto. `/labs/a10/preview` parsea la URL, exige `https`,
rechaza userinfo y solo admite `example.com` y `www.example.com`. El
laboratorio no origina peticiones: valida y niega por defecto.
