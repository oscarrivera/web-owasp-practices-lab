# Identificación y autenticación (A07)

El fallo: devolver el token de sesión en el JSON y guardarlo en
`localStorage` lo expone a cualquier script de la página. Una cookie sin
`httpOnly` / `sameSite` tiene el mismo problema por otra vía.

El control: login escribe una cookie `sid` con `httpOnly`, `sameSite=strict`
y `secure` en producción. El cuerpo de `/login` no lleva token. `/labs/a07/session`
devuelve identidad, no el secreto de sesión.

La página estática de `localStorage` no se sirve salvo `ENABLE_VULN_LABS=true`.
