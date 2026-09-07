import { createHmac, timingSafeEqual } from 'node:crypto';
import type { Request, Response } from 'express';
import { MIN_SECRET_LENGTH, webhookSecret } from '../config.js';

export function signWebhookPayload(payload: string, secret: string): string {
  if (secret.length < MIN_SECRET_LENGTH) {
    throw new Error('webhook secret must be at least 32 characters');
  }
  return createHmac('sha256', secret).update(payload).digest('hex');
}

function signaturesMatch(provided: string, expected: string): boolean {
  const a = Buffer.from(provided, 'hex');
  const b = Buffer.from(expected, 'hex');
  if (a.length === 0 || a.length !== b.length) {
    return false;
  }
  return timingSafeEqual(a, b);
}

export function fixedHandler(req: Request, res: Response): void {
  const payload = typeof req.body?.payload === 'string' ? req.body.payload : '';
  if (!payload || payload.length > 2048) {
    res.status(400).json({ error: 'payload required' });
    return;
  }
  const provided = req.get('x-signature') ?? '';
  const expected = signWebhookPayload(payload, webhookSecret());
  if (!signaturesMatch(provided, expected)) {
    res.status(401).json({ error: 'invalid signature' });
    return;
  }
  res.json({ ok: true });
}

export function vulnerableHandler(req: Request, res: Response): void {
  const payload = typeof req.body?.payload === 'string' ? req.body.payload : '';
  res.json({ ok: true, payload });
}
