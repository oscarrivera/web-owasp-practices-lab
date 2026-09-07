import type { Request, Response } from 'express';
import { getSessionUser } from '../auth.js';
import { updateDisplayName, updateUserProfile } from '../db.js';

export function fixedHandler(req: Request, res: Response): void {
  const user = getSessionUser(req);
  if (!user) {
    res.status(401).json({ error: 'unauthenticated' });
    return;
  }
  const displayName = req.body?.displayName;
  if (typeof displayName !== 'string' || displayName.trim().length < 1 || displayName.length > 80) {
    res.status(400).json({ error: 'invalid displayName' });
    return;
  }
  const updated = updateDisplayName(user.id, displayName.trim());
  res.json({ user: updated });
}

export function vulnerableHandler(req: Request, res: Response): void {
  const user = getSessionUser(req);
  if (!user) {
    res.status(401).json({ error: 'unauthenticated' });
    return;
  }
  const patch = {
    displayName: typeof req.body?.displayName === 'string' ? req.body.displayName : undefined,
    role: typeof req.body?.role === 'string' ? req.body.role : undefined,
  };
  const updated = updateUserProfile(user.id, patch);
  res.json({ user: updated });
}
