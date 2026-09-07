import type { Request, Response } from 'express';
import { labMode } from '../auth.js';

export function fixedHandler(_req: Request, res: Response): void {
  res.json({ status: 'ok', mode: labMode() });
}

export function vulnerableHandler(_req: Request, res: Response): void {
  res.json({
    status: 'ok',
    node: process.version,
    pid: process.pid,
    platform: process.platform,
  });
}
