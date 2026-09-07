import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { createApp } from '../src/app.js';
import { resetAuthLogs } from '../src/labs/a09-logging.js';
import { MIN_SECRET_LENGTH } from '../src/config.js';
import { signAccessToken, verifyAccessToken } from '../src/labs/a02-crypto.js';
import { signWebhookPayload } from '../src/labs/a08-integrity.js';
import { previewUrl } from '../src/labs/a10-ssrf.js';
import { redactSecrets } from '../src/labs/a09-logging.js';
import { userCount } from '../src/db.js';
import { SESSION_COOKIE } from '../src/config.js';

function app() {
  return createApp();
}

async function login(agent: request.SuperTest<request.Test>, username = 'alice', password = 'alice-demo') {
  const res = await agent.post('/login').send({ username, password });
  expect(res.status).toBe(200);
  expect(res.body.token).toBeUndefined();
  return res;
}

describe('deny by default', () => {
  it('does not enable vulnerable labs unless ENABLE_VULN_LABS=true', async () => {
    expect(process.env.ENABLE_VULN_LABS).not.toBe('true');
    const res = await request(app()).get('/');
    expect(res.status).toBe(200);
    expect(res.body.mode).toBe('fixed');
    expect(res.body.warning).toMatch(/do not deploy/i);
  });

  it('does not serve the insecure client page', async () => {
    const res = await request(app()).get('/labs/a07/insecure-client.html');
    expect(res.status).toBe(404);
  });
});

describe('A01 access control', () => {
  it('rejects missing session', async () => {
    const res = await request(app()).get('/labs/a01/notes/1');
    expect(res.status).toBe(401);
  });

  it('returns the owner note and denies another owner', async () => {
    const agent = request.agent(app());
    await login(agent);
    const own = await agent.get('/labs/a01/notes/1');
    expect(own.status).toBe(200);
    expect(own.body.title).toBe('Nota de Alice');
    expect(own.body.ownerId).toBeUndefined();

    const other = await agent.get('/labs/a01/notes/2');
    expect(other.status).toBe(403);

    const api = await agent.get('/api/notes/2');
    expect(api.status).toBe(403);
  });
});

describe('A02 JWT controls', () => {
  const strong = 'abcdefghijklmnopqrstuvwxyz012345';

  it('rejects secrets shorter than 32 characters', () => {
    expect(strong.length).toBeGreaterThanOrEqual(MIN_SECRET_LENGTH);
    expect(() => signAccessToken('alice', 'short-secret')).toThrow(/32/);
    expect(() => verifyAccessToken('x.y.z', 'short-secret')).toThrow(/32/);
  });

  it('signs and verifies with HS256 only', () => {
    const token = signAccessToken('alice', strong);
    const payload = verifyAccessToken(token, strong);
    expect(payload.sub).toBe('alice');
  });

  it('rejects unsigned tokens (alg none is not accepted)', () => {
    const unsigned = [
      Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url'),
      Buffer.from(JSON.stringify({ sub: 'alice' })).toString('base64url'),
      '',
    ].join('.');
    expect(() => verifyAccessToken(unsigned, strong)).toThrow();
  });
});

describe('A03 parameterized queries', () => {
  it('matches a username that contains an apostrophe as a literal', async () => {
    const agent = request.agent(app());
    await login(agent);
    const found = await agent.get('/labs/a03/users').query({ q: "o'hara" });
    expect(found.status).toBe(200);
    expect(found.body.users).toEqual([
      expect.objectContaining({ username: "o'hara" }),
    ]);
    expect(userCount()).toBe(3);

    const miss = await agent.get('/labs/a03/users').query({ q: "o'hara extra" });
    expect(miss.status).toBe(200);
    expect(miss.body.users).toEqual([]);
    expect(userCount()).toBe(3);
  });

  it('requires a session', async () => {
    const res = await request(app()).get('/labs/a03/users').query({ q: 'alice' });
    expect(res.status).toBe(401);
  });
});

describe('A04 allowlisted profile', () => {
  it('updates displayName and ignores role in the public contract', async () => {
    const agent = request.agent(app());
    await login(agent);
    const res = await agent.patch('/labs/a04/profile').send({
      displayName: 'Alicia',
      role: 'admin',
    });
    expect(res.status).toBe(200);
    expect(res.body.user.displayName).toBe('Alicia');
    expect(res.body.user.role).toBe('user');
  });
});

describe('A05 security headers', () => {
  it('sets defensive headers on the lab response', async () => {
    const res = await request(app()).get('/labs/a05');
    expect(res.status).toBe(200);
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-frame-options']).toBe('DENY');
    expect(res.headers['referrer-policy']).toBe('no-referrer');
    expect(res.headers['content-security-policy']).toMatch(/default-src 'none'/);
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.headers['x-powered-by']).toBeUndefined();
  });
});

describe('A06 component disclosure', () => {
  it('does not leak runtime inventory', async () => {
    const res = await request(app()).get('/labs/a06');
    expect(res.status).toBe(200);
    expect(res.body.node).toBeUndefined();
    expect(res.body.pid).toBeUndefined();
    expect(res.body.platform).toBeUndefined();
    expect(res.body.status).toBe('ok');
  });
});

describe('A07 session cookie', () => {
  it('sets httpOnly sameSite cookie and keeps the token out of the JSON body', async () => {
    const res = await request(app()).post('/login').send({
      username: 'alice',
      password: 'alice-demo',
    });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true });
    const cookie = res.headers['set-cookie']?.[0] ?? '';
    expect(cookie).toMatch(new RegExp(`${SESSION_COOKIE}=`));
    expect(cookie.toLowerCase()).toContain('httponly');
    expect(cookie.toLowerCase()).toContain('samesite=strict');
  });

  it('returns identity without a token field', async () => {
    const agent = request.agent(app());
    await login(agent);
    const res = await agent.get('/labs/a07/session');
    expect(res.status).toBe(200);
    expect(res.body.token).toBeUndefined();
    expect(res.body.user.username).toBe('alice');
  });
});

describe('A08 webhook integrity', () => {
  it('rejects a missing signature and accepts a valid HMAC', async () => {
    const payload = 'note-created';
    const denied = await request(app()).post('/labs/a08').send({ payload });
    expect(denied.status).toBe(401);

    const secret = process.env.WEBHOOK_SECRET ?? 'dev-only-webhook-secret-do-not-use!!';
    const sig = signWebhookPayload(payload, secret);
    const ok = await request(app())
      .post('/labs/a08')
      .set('x-signature', sig)
      .send({ payload });
    expect(ok.status).toBe(200);
    expect(ok.body.ok).toBe(true);
  });
});

describe('A09 logging redaction', () => {
  beforeEach(() => {
    resetAuthLogs();
  });

  afterEach(() => {
    resetAuthLogs();
  });

  it('does not echo passwords in the accepted body', async () => {
    const res = await request(app()).post('/labs/a09').send({
      username: 'alice',
      password: 'should-not-appear',
    });
    expect(res.status).toBe(200);
    expect(JSON.stringify(res.body)).not.toContain('should-not-appear');
    expect(res.body.acceptedBody.password).toBe('[redacted]');
    expect(redactSecrets({ token: 'abc', nested: { secret: 'x' } })).toEqual({
      token: '[redacted]',
      nested: { secret: '[redacted]' },
    });
  });
});

describe('A10 URL allowlist', () => {
  it('denies hosts outside the allowlist and accepts example.com over https', () => {
    expect(previewUrl('https://example.com/x')).toEqual({ ok: true, host: 'example.com' });
    expect(previewUrl('http://example.com/x').ok).toBe(false);
    expect(previewUrl('https://not-allowed.example/x')).toEqual({
      ok: false,
      status: 403,
      error: 'host not allowed',
    });
  });

  it('rejects loopback and missing urls on the HTTP surface', async () => {
    const missing = await request(app()).get('/labs/a10/preview');
    expect(missing.status).toBe(400);
    const loopback = await request(app()).get('/labs/a10/preview').query({
      url: 'http://127.0.0.1/',
    });
    expect(loopback.status).toBe(400);
  });
});
