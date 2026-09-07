# Inyección (A03)

El fallo: interpolar la entrada del usuario en el texto SQL convierte datos
en instrucciones. Las comillas en un nombre dejan de ser literales.

El control: consultas parametrizadas con `better-sqlite3` (`WHERE username = ?`).
El valor viaja separado del SQL. Un apellido con apóstrofe es un apellido,
no un cambio de consulta.

Ruta: `GET /labs/a03/users?q=`. Requiere sesión.
La concatenación queda detrás de `ENABLE_VULN_LABS=true` y no forma parte de
la batería de tests.
