export const SESSION_COOKIE = 'sid';
export const MIN_SECRET_LENGTH = 32;

export function vulnLabsEnabled(): boolean {
  return process.env.ENABLE_VULN_LABS === 'true';
}

export function listenHost(): string {
  return process.env.HOST ?? '127.0.0.1';
}

export function listenPort(): number {
  const raw = process.env.PORT ?? '3000';
  const port = Number(raw);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('PORT must be an integer between 1 and 65535');
  }
  return port;
}

export function jwtSecret(): string {
  const secret = process.env.JWT_SECRET ?? 'dev-only-jwt-secret-do-not-deploy!!';
  return secret;
}

export function webhookSecret(): string {
  return process.env.WEBHOOK_SECRET ?? 'dev-only-webhook-secret-do-not-use!!';
}

export function sessionSecret(): string {
  return process.env.SESSION_SECRET ?? 'dev-only-session-secret-do-not-use!';
}

export function assertLocalVulnMode(host: string): void {
  if (!vulnLabsEnabled()) {
    return;
  }
  if (host !== '127.0.0.1' && host !== 'localhost') {
    throw new Error('ENABLE_VULN_LABS=true only allowed when HOST is 127.0.0.1 or localhost');
  }
}
