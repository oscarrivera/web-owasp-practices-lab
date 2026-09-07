# Control de acceso roto (A01)

El fallo: un identificador en la URL no es autorización. Si el servidor
devuelve un recurso con solo comprobar que el id existe, cualquier sesión
válida (o ninguna) lee datos de otro titular.

El control: la nota se entrega solo cuando `ownerId` coincide con el usuario
de la sesión. Sin cookie de sesión, 401. Con sesión de otro titular, 403. El
cuerpo no incluye campos internos del titular.

Ruta: `GET /labs/a01/notes/:id` (también `GET /api/notes/:id`).
Modo por defecto: `fixedHandler`. El handler sin comprobación de titular no
se monta salvo `ENABLE_VULN_LABS=true`.
