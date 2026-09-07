# Fallos criptográficos (A02)

El fallo: un secreto corto, un algoritmo negociable o verificar un JWT sin
fijar `algorithms` deja la integridad del token en manos del cliente.

El control: el secreto tiene al menos 32 caracteres. La firma y la
verificación usan solo HS256. No se decodifica un token como si eso
demostrara autenticidad.

Ruta: `POST /labs/a02` con `{ "action": "sign"|"verify", ... }`.
