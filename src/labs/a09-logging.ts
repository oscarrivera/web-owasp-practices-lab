import type { Request, Response } from 'express';

export type AuthLogEvent = {
  event: 'auth_failure' | 'auth_success';
  username: string;
  reason?: string;
  ts: number;
};

const MAX_LOGS = 50;
const logs: AuthLogEvent[] = [];

export function redactSecrets(input: unknown): unknown {
  if (input === null || typeof input !== 'object') {
    return input;
  }
  if (Array.isArray(input)) {
    return input.map(redactSecrets);
  }
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input)) {
    if (/password|secret|token|authorization/i.test(key)) {
      out[key] = '[redacted]';
    } else {
      out[key] = redactSecrets(value);
    }
  }
  return out;
}

export function recordAuthEvent(event: AuthLogEvent): AuthLogEvent {
  const safe: AuthLogEvent = {
    event: event.event,
    username: event.username,
    ts: event.ts,
  };
  if (event.reason) {
    safe.reason = event.reason;
  }
  logs.push(safe);
  if (logs.length > MAX_LOGS) {
    logs.shift();
  }
  return safe;
}

export function recentAuthLogs(): AuthLogEvent[] {
  return [...logs];
}

export function resetAuthLogs(): void {
  logs.length = 0;
}

export function fixedHandler(req: Request, res: Response): void {
  const username = typeof req.body?.username === 'string' ? req.body.username : '';
  const body = redactSecrets(req.body);
  if (!username) {
    res.status(400).json({ error: 'username required' });
    return;
  }
  const entry = recordAuthEvent({
    event: 'auth_failure',
    username,
    reason: 'invalid_credentials',
    ts: Date.now(),
  });
  res.json({ logged: entry, acceptedBody: body });
}

export function vulnerableHandler(req: Request, res: Response): void {
  logs.push({
    event: 'auth_failure',
    username: String(req.body?.username ?? ''),
    reason: JSON.stringify(req.body),
    ts: Date.now(),
  });
  res.json({ logged: logs.at(-1) });
}
