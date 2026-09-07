# Diseño inseguro (A04)

El fallo: tratar el cuerpo HTTP como un parche genérico (mass assignment)
permite subir `role` u otros campos de negocio que el cliente no debería
escribir.

El control: lista blanca. El perfil público solo acepta `displayName` con
longitud acotada. El rol no entra por el mismo endpoint.

Ruta: `PATCH /labs/a04/profile`. Requiere sesión.
