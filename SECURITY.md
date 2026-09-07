# Seguridad

Este repositorio es un laboratorio **local**. No hay instancia pública, no hay
datos reales y no hay promesa de que el código inseguro (detrás de
`ENABLE_VULN_LABS`) sea exhaustivo ni representativo.

## Uso

- Bind por defecto: `127.0.0.1`.
- `ENABLE_VULN_LABS` distinto de `true` → solo handlers corregidos.
- Con el flag activo, `HOST` debe ser `127.0.0.1` o `localhost`. Si no, el
  proceso no arranca.
- Secretos de demostración (`JWT_SECRET`, `SESSION_SECRET`, `WEBHOOK_SECRET`)
  son para la máquina del desarrollador. Rotarlos si se copian a otro entorno,
  que no debería existir.

## Qué no enviar

No abras issues con procedimientos ofensivos, payloads o PoC contra terceros.
Si encuentras un defecto en el **modo fijo** (el que corre por defecto),
describe el impacto y el control que falta. Contacto: el propietario del
repositorio vía issues de GitHub, sin datos personales de usuarios.

## Alcance

SQLite en memoria, sesiones HMAC, JWT de laboratorio. No es un framework de
producción. Antes de reutilizar un control, revisa secretos, TLS, almacenamiento
y el modelo de autorización del producto real.
