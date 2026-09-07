import { createHmac, timingSafeEqual } from 'node:crypto';
import type { CookieOptions, Request, Response } from 'express';
import { SESSION_COOKIE, sessionSecret, vulnLabsEnabled } from './config.js';
import { findUserById, type PublicUser, toPublicUser } from './db.js';

export type SessionUser = PublicUser;

type SessionPayload = {
  sub: number;
  exp: number;
};

function encodeSession(userId: number): string {
  const payload: SessionPayload = {
    sub: userId,
    exp: Date.now() + 60 * 60 * 1000,
  };
  const body = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const sig = createHmac('sha256', sessionSecret()).update(body).digest('base64url');
  return `${body}.${sig}`;
}

function decodeSession(token: string): number | undefined {
  const [body, sig] = token.split('.');
  if (!body || !sig) {
    return undefined;
  }
  const expected = createHmac('sha256', sessionSecret()).update(body).digest('base64url');
  const sigBuf = Buffer.from(sig);
  const expectedBuf = Buffer.from(expected);
  if (sigBuf.length !== expectedBuf.length || !timingSafeEqual(sigBuf, expectedBuf)) {
    return undefined;
  }
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as SessionPayload;
    if (typeof payload.sub !== 'number' || payload.exp < Date.now()) {
      return undefined;
    }
    return payload.sub;
  } catch {
    return undefined;
  }
}

export function sessionCookieOptions(): CookieOptions {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
    maxAge: 60 * 60 * 1000,
  };
}

export function setSessionCookie(res: Response, userId: number): void {
  res.cookie(SESSION_COOKIE, encodeSession(userId), sessionCookieOptions());
}

export function clearSessionCookie(res: Response): void {
  res.clearCookie(SESSION_COOKIE, { path: '/' });
}

export function getSessionUser(req: Request): SessionUser | undefined {
  const raw = req.cookies?.[SESSION_COOKIE];
  if (typeof raw !== 'string' || raw.length === 0) {
    return undefined;
  }
  const userId = decodeSession(raw);
  if (userId === undefined) {
    return undefined;
  }
  const row = findUserById(userId);
  return row ? toPublicUser(row) : undefined;
}

export function issueOpaqueToken(userId: number): string {
  return encodeSession(userId);
}

export function labMode(): 'fixed' | 'vulnerable' {
  return vulnLabsEnabled() ? 'vulnerable' : 'fixed';
}
