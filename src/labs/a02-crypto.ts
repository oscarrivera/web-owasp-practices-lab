import type { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { jwtSecret, MIN_SECRET_LENGTH } from '../config.js';

function assertStrongSecret(secret: string): void {
  if (secret.length < MIN_SECRET_LENGTH) {
    throw new Error('JWT secret must be at least 32 characters');
  }
}

export function signAccessToken(subject: string, secret: string): string {
  assertStrongSecret(secret);
  return jwt.sign({ sub: subject }, secret, {
    algorithm: 'HS256',
    expiresIn: '15m',
  });
}

export function verifyAccessToken(token: string, secret: string): jwt.JwtPayload {
  assertStrongSecret(secret);
  const payload = jwt.verify(token, secret, { algorithms: ['HS256'] });
  if (typeof payload === 'string') {
    throw new Error('unexpected token payload');
  }
  return payload;
}

export function fixedHandler(req: Request, res: Response): void {
  const action = typeof req.body?.action === 'string' ? req.body.action : '';
  const secret = jwtSecret();
  try {
    if (action === 'sign') {
      const subject = typeof req.body?.sub === 'string' ? req.body.sub : '';
      if (!subject || subject.length > 64) {
        res.status(400).json({ error: 'invalid sub' });
        return;
      }
      const token = signAccessToken(subject, secret);
      res.json({ token, alg: 'HS256' });
      return;
    }
    if (action === 'verify') {
      const token = typeof req.body?.token === 'string' ? req.body.token : '';
      if (!token) {
        res.status(400).json({ error: 'token required' });
        return;
      }
      const payload = verifyAccessToken(token, secret);
      res.json({ sub: payload.sub, alg: 'HS256' });
      return;
    }
    res.status(400).json({ error: 'action must be sign or verify' });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'crypto error';
    res.status(400).json({ error: message });
  }
}

export function vulnerableHandler(req: Request, res: Response): void {
  const action = typeof req.body?.action === 'string' ? req.body.action : '';
  const weak = 'secret';
  if (action === 'sign') {
    const subject = typeof req.body?.sub === 'string' ? req.body.sub : 'anon';
    const token = jwt.sign({ sub: subject }, weak);
    res.json({ token });
    return;
  }
  if (action === 'verify') {
    const token = typeof req.body?.token === 'string' ? req.body.token : '';
    const payload = jwt.decode(token);
    res.json({ payload });
    return;
  }
  res.status(400).json({ error: 'action must be sign or verify' });
}
