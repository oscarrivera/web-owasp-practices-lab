import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import Database from 'better-sqlite3';

export type UserRow = {
  id: number;
  username: string;
  password_hash: string;
  display_name: string;
  role: string;
};

export type NoteRow = {
  id: number;
  owner_id: number;
  title: string;
  body: string;
};

export type PublicUser = {
  id: number;
  username: string;
  displayName: string;
  role: string;
};

export type PublicNote = {
  id: number;
  ownerId: number;
  title: string;
  body: string;
};

const db = new Database(':memory:');

function hashPassword(password: string): string {
  const salt = randomBytes(16).toString('hex');
  const hash = scryptSync(password, salt, 32).toString('hex');
  return `${salt}:${hash}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const [salt, hash] = stored.split(':');
  if (!salt || !hash) {
    return false;
  }
  const actual = scryptSync(password, salt, 32);
  const expected = Buffer.from(hash, 'hex');
  if (actual.length !== expected.length) {
    return false;
  }
  return timingSafeEqual(actual, expected);
}

function seed(): void {
  db.exec(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      display_name TEXT NOT NULL,
      role TEXT NOT NULL
    );
    CREATE TABLE notes (
      id INTEGER PRIMARY KEY,
      owner_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      FOREIGN KEY (owner_id) REFERENCES users(id)
    );
  `);

  const insertUser = db.prepare(
    'INSERT INTO users (username, password_hash, display_name, role) VALUES (?, ?, ?, ?)',
  );
  insertUser.run('alice', hashPassword('alice-demo'), 'Alice', 'user');
  insertUser.run('bob', hashPassword('bob-demo'), 'Bob', 'user');
  insertUser.run("o'hara", hashPassword('ohara-demo'), "O'Hara", 'user');

  const insertNote = db.prepare(
    'INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)',
  );
  insertNote.run(1, 'Nota de Alice', 'Solo Alice debe leer esto.');
  insertNote.run(2, 'Nota de Bob', 'Solo Bob debe leer esto.');
}

seed();

export function findUserByUsername(username: string): UserRow | undefined {
  return db.prepare('SELECT * FROM users WHERE username = ?').get(username) as
    | UserRow
    | undefined;
}

export function findUserById(id: number): UserRow | undefined {
  return db.prepare('SELECT * FROM users WHERE id = ?').get(id) as UserRow | undefined;
}

export function toPublicUser(row: UserRow): PublicUser {
  return {
    id: row.id,
    username: row.username,
    displayName: row.display_name,
    role: row.role,
  };
}

export function getNoteById(id: number): PublicNote | undefined {
  const row = db.prepare('SELECT * FROM notes WHERE id = ?').get(id) as NoteRow | undefined;
  if (!row) {
    return undefined;
  }
  return {
    id: row.id,
    ownerId: row.owner_id,
    title: row.title,
    body: row.body,
  };
}

export function searchUsersByUsername(query: string): PublicUser[] {
  const rows = db
    .prepare('SELECT * FROM users WHERE username = ?')
    .all(query) as UserRow[];
  return rows.map(toPublicUser);
}

/** Unsafe concatenation. Used only by the opt-in lab handler. */
export function searchUsersByUsernameUnsafe(query: string): PublicUser[] {
  const sql = `SELECT * FROM users WHERE username = '${query}'`;
  const rows = db.prepare(sql).all() as UserRow[];
  return rows.map(toPublicUser);
}

export function updateUserProfile(
  id: number,
  patch: { displayName?: string; role?: string },
): PublicUser | undefined {
  const current = findUserById(id);
  if (!current) {
    return undefined;
  }
  const displayName = patch.displayName ?? current.display_name;
  const role = patch.role ?? current.role;
  db.prepare('UPDATE users SET display_name = ?, role = ? WHERE id = ?').run(
    displayName,
    role,
    id,
  );
  return toPublicUser(findUserById(id)!);
}

export function updateDisplayName(id: number, displayName: string): PublicUser | undefined {
  db.prepare('UPDATE users SET display_name = ? WHERE id = ?').run(displayName, id);
  const row = findUserById(id);
  return row ? toPublicUser(row) : undefined;
}

export function userCount(): number {
  const row = db.prepare('SELECT COUNT(*) AS n FROM users').get() as { n: number };
  return row.n;
}
