import type { Request, Response } from 'express';
import { getSessionUser } from '../auth.js';
import { getNoteById } from '../db.js';

export function fixedHandler(req: Request, res: Response): void {
  const user = getSessionUser(req);
  if (!user) {
    res.status(401).json({ error: 'unauthenticated' });
    return;
  }
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1) {
    res.status(400).json({ error: 'invalid id' });
    return;
  }
  const note = getNoteById(id);
  if (!note) {
    res.status(404).json({ error: 'not found' });
    return;
  }
  if (note.ownerId !== user.id) {
    res.status(403).json({ error: 'forbidden' });
    return;
  }
  res.json({
    id: note.id,
    title: note.title,
    body: note.body,
  });
}

export function vulnerableHandler(req: Request, res: Response): void {
  const id = Number(req.params.id);
  const note = getNoteById(id);
  if (!note) {
    res.status(404).json({ error: 'not found' });
    return;
  }
  res.json(note);
}
