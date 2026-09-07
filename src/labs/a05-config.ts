import type { Request, Response } from 'express';

export const SECURITY_HEADERS: Record<string, string> = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
  'Cache-Control': 'no-store',
};

export function applySecurityHeaders(res: Response): void {
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    res.setHeader(name, value);
  }
}

export function fixedHandler(_req: Request, res: Response): void {
  applySecurityHeaders(res);
  res.json({ ok: true, headers: Object.keys(SECURITY_HEADERS) });
}

export function vulnerableHandler(_req: Request, res: Response): void {
  res.json({ ok: true });
}
