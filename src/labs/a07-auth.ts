import type { Request, Response } from 'express';
import { getSessionUser, issueOpaqueToken } from '../auth.js';

export function fixedHandler(req: Request, res: Response): void {
  const user = getSessionUser(req);
  if (!user) {
    res.status(401).json({ error: 'unauthenticated' });
    return;
  }
  res.json({
    user: { id: user.id, username: user.username },
  });
}

export function vulnerableHandler(req: Request, res: Response): void {
  const user = getSessionUser(req);
  if (!user) {
    res.status(401).json({ error: 'unauthenticated' });
    return;
  }
  res.json({
    user,
    token: issueOpaqueToken(user.id),
  });
}
