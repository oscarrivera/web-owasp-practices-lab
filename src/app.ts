import cookieParser from 'cookie-parser';
import express, { type Express, type Request, type Response } from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { labMode, setSessionCookie, clearSessionCookie, getSessionUser } from './auth.js';
import { findUserByUsername, toPublicUser, verifyPassword } from './db.js';
import { recordAuthEvent } from './labs/a09-logging.js';
import { applySecurityHeaders } from './labs/a05-config.js';
import { pickHandler } from './labs/pick.js';
import { vulnLabsEnabled } from './config.js';
import * as a01 from './labs/a01-access.js';
import * as a02 from './labs/a02-crypto.js';
import * as a03 from './labs/a03-injection.js';
import * as a04 from './labs/a04-design.js';
import * as a05 from './labs/a05-config.js';
import * as a06 from './labs/a06-components.js';
import * as a07 from './labs/a07-auth.js';
import * as a08 from './labs/a08-integrity.js';
import * as a09 from './labs/a09-logging.js';
import * as a10 from './labs/a10-ssrf.js';

const here = path.dirname(fileURLToPath(import.meta.url));

const LABS = [
  { id: 'a01', title: 'Broken Access Control', path: '/labs/a01' },
  { id: 'a02', title: 'Cryptographic Failures', path: '/labs/a02' },
  { id: 'a03', title: 'Injection', path: '/labs/a03' },
  { id: 'a04', title: 'Insecure Design', path: '/labs/a04' },
  { id: 'a05', title: 'Security Misconfiguration', path: '/labs/a05' },
  { id: 'a06', title: 'Vulnerable and Outdated Components', path: '/labs/a06' },
  { id: 'a07', title: 'Identification and Authentication Failures', path: '/labs/a07' },
  { id: 'a08', title: 'Software and Data Integrity Failures', path: '/labs/a08' },
  { id: 'a09', title: 'Security Logging and Monitoring Failures', path: '/labs/a09' },
  { id: 'a10', title: 'Server-Side Request Forgery', path: '/labs/a10' },
];

function labIndex(_req: Request, res: Response, id: string): void {
  const meta = LABS.find((lab) => lab.id === id);
  res.json({
    lab: id,
    title: meta?.title,
    mode: labMode(),
    vulnLabs: vulnLabsEnabled(),
  });
}

export function createApp(): Express {
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '32kb' }));
  app.use(cookieParser());
  app.use((req, res, next) => {
    if (vulnLabsEnabled() && req.path === '/labs/a05') {
      next();
      return;
    }
    applySecurityHeaders(res);
    next();
  });

  app.get('/', (_req, res) => {
    res.json({
      name: 'web-owasp-practices-lab',
      warning: 'localhost only. do not deploy.',
      mode: labMode(),
      labs: LABS,
    });
  });

  app.post('/login', (req, res) => {
    const username = typeof req.body?.username === 'string' ? req.body.username : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    const row = findUserByUsername(username);
    if (!row || !verifyPassword(password, row.password_hash)) {
      recordAuthEvent({
        event: 'auth_failure',
        username,
        reason: 'invalid_credentials',
        ts: Date.now(),
      });
      res.status(401).json({ error: 'invalid credentials' });
      return;
    }
    recordAuthEvent({
      event: 'auth_success',
      username,
      ts: Date.now(),
    });
    if (vulnLabsEnabled()) {
      res.json({ ok: true, token: 'insecure-demo-token', user: toPublicUser(row) });
      return;
    }
    setSessionCookie(res, row.id);
    res.json({ ok: true });
  });

  app.post('/logout', (_req, res) => {
    clearSessionCookie(res);
    res.json({ ok: true });
  });

  app.get('/api/notes/:id', pickHandler(a01.fixedHandler, a01.vulnerableHandler));

  app.get('/labs/a01', (req, res) => labIndex(req, res, 'a01'));
  app.get('/labs/a01/notes/:id', pickHandler(a01.fixedHandler, a01.vulnerableHandler));

  app.get('/labs/a02', (req, res) => labIndex(req, res, 'a02'));
  app.post('/labs/a02', pickHandler(a02.fixedHandler, a02.vulnerableHandler));

  app.get('/labs/a03', (req, res) => labIndex(req, res, 'a03'));
  app.get('/labs/a03/users', pickHandler(a03.fixedHandler, a03.vulnerableHandler));

  app.get('/labs/a04', (req, res) => labIndex(req, res, 'a04'));
  app.patch('/labs/a04/profile', pickHandler(a04.fixedHandler, a04.vulnerableHandler));

  app.get('/labs/a05', pickHandler(a05.fixedHandler, a05.vulnerableHandler));

  app.get('/labs/a06', pickHandler(a06.fixedHandler, a06.vulnerableHandler));

  app.get('/labs/a07', (req, res) => labIndex(req, res, 'a07'));
  app.get('/labs/a07/session', pickHandler(a07.fixedHandler, a07.vulnerableHandler));
  app.get('/labs/a07/me', (req, res) => {
    const user = getSessionUser(req);
    if (!user) {
      res.status(401).json({ error: 'unauthenticated' });
      return;
    }
    res.json({ user: { id: user.id, username: user.username } });
  });

  if (vulnLabsEnabled()) {
    app.get('/labs/a07/insecure-client.html', (_req, res) => {
      res.sendFile(path.join(here, 'public', 'insecure-client.html'));
    });
  }

  app.get('/labs/a08', (req, res) => labIndex(req, res, 'a08'));
  app.post('/labs/a08', pickHandler(a08.fixedHandler, a08.vulnerableHandler));

  app.get('/labs/a09', (req, res) => labIndex(req, res, 'a09'));
  app.post('/labs/a09', pickHandler(a09.fixedHandler, a09.vulnerableHandler));

  app.get('/labs/a10', (req, res) => labIndex(req, res, 'a10'));
  app.get('/labs/a10/preview', pickHandler(a10.fixedHandler, a10.vulnerableHandler));

  app.use((_req, res) => {
    res.status(404).json({ error: 'not found' });
  });

  return app;
}
