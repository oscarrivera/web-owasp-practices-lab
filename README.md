# web-owasp-practices-lab

Laboratorio local de **controles** del OWASP Top 10 (2021). Node 20, TypeScript, Express, SQLite en memoria.

## Aviso

**No se despliega.** El proceso escucha en `127.0.0.1` por defecto. No es un escáner, no es un CTF y no es un paquete de pruebas ofensivas.

Los modos inseguros están **apagados**. Solo se montan si `ENABLE_VULN_LABS=true` **y** el host es `127.0.0.1` o `localhost`. En cualquier otro bind, el proceso aborta.

La batería de tests cubre únicamente los handlers corregidos: denegación por defecto, SQL parametrizado, cabeceras, cookie de sesión. No hay aserciones de que un fallo sea explotable.

## Cómo ejecutarlo

```bash
cp .env.example .env   # opcional; los valores por defecto ya son locales
npm install
npm test
npm start
```

Credenciales de demostración (solo localhost):

| usuario | contraseña  |
|---------|-------------|
| alice   | alice-demo  |
| bob     | bob-demo    |
| o'hara  | ohara-demo  |

`POST /login` con JSON `{ "username", "password" }` deja la cookie `sid` (`httpOnly`, `sameSite=strict`).

## Mapa de laboratorios

| Id  | Ruta | Control por defecto |
|-----|------|---------------------|
| A01 | `GET /labs/a01/notes/:id` | titular de la nota = usuario de sesión |
| A02 | `POST /labs/a02` | secreto ≥ 32, HS256 fijado, sin `alg=none` |
| A03 | `GET /labs/a03/users?q=` | `WHERE username = ?` |
| A04 | `PATCH /labs/a04/profile` | solo `displayName` |
| A05 | `GET /labs/a05` | cabeceras de marco, sniffing, CSP, `no-store` |
| A06 | `GET /labs/a06` | sin inventario de runtime |
| A07 | `GET /labs/a07/session` | identidad sin token en el cuerpo |
| A08 | `POST /labs/a08` | HMAC de `payload` en `x-signature` |
| A09 | `POST /labs/a09` | logs sin secretos |
| A10 | `GET /labs/a10/preview?url=` | allowlist HTTPS (`example.com`) |

Documentación: `docs/`. Cada ficha describe el defecto y el control, no un procedimiento de ataque.

Alias de A01: `GET /api/notes/:id`.

## Pedagogía

1. El código que importa es el `fixedHandler`. Es el contrato que hay que copiar a un servicio real.
2. El `vulnerableHandler` existe para contrastar en local. No se registra sin el flag. Los tests no lo invocan.
3. SQLite en memoria con tres usuarios y dos notas. Suficiente para titularidad, búsqueda parametrizada y mass assignment. No hay persistencia.
4. Un laboratorio no sustituye modelado de amenazas ni revisión de dependencias. A06 aquí solo enseña a no filtrar versiones; el SCA va en CI.

## Scripts

- `npm test` — vitest, solo controles
- `npm start` — `tsx src/index.ts`
- `npm run lint` — eslint

Licencia MIT. Ver `SECURITY.md` para el canal de avisos.
