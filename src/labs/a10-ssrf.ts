import type { Request, Response } from 'express';

const ALLOWED_HOSTS = new Set(['example.com', 'www.example.com']);

export function previewUrl(raw: string): { ok: true; host: string } | { ok: false; status: number; error: string } {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return { ok: false, status: 400, error: 'invalid url' };
  }
  if (parsed.protocol !== 'https:') {
    return { ok: false, status: 400, error: 'https required' };
  }
  if (parsed.username || parsed.password) {
    return { ok: false, status: 400, error: 'userinfo not allowed' };
  }
  if (!ALLOWED_HOSTS.has(parsed.hostname)) {
    return { ok: false, status: 403, error: 'host not allowed' };
  }
  return { ok: true, host: parsed.hostname };
}

export function fixedHandler(req: Request, res: Response): void {
  const raw = typeof req.query.url === 'string' ? req.query.url : '';
  if (!raw) {
    res.status(400).json({ error: 'url required' });
    return;
  }
  const result = previewUrl(raw);
  if (!result.ok) {
    res.status(result.status).json({ error: result.error });
    return;
  }
  res.json({ host: result.host });
}

export function vulnerableHandler(req: Request, res: Response): void {
  const raw = typeof req.query.url === 'string' ? req.query.url : '';
  res.json({ url: raw });
}
