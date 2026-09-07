import type { Request, Response } from 'express';
import { getSessionUser } from '../auth.js';
import { searchUsersByUsername, searchUsersByUsernameUnsafe } from '../db.js';

export function fixedHandler(req: Request, res: Response): void {
  const user = getSessionUser(req);
  if (!user) {
    res.status(401).json({ error: 'unauthenticated' });
    return;
  }
  const q = typeof req.query.q === 'string' ? req.query.q : '';
  if (q.length === 0 || q.length > 64) {
    res.status(400).json({ error: 'q required' });
    return;
  }
  const users = searchUsersByUsername(q);
  res.json({ users });
}

export function vulnerableHandler(req: Request, res: Response): void {
  const q = typeof req.query.q === 'string' ? req.query.q : '';
  const users = searchUsersByUsernameUnsafe(q);
  res.json({ users });
}
