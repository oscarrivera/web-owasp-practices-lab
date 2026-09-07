import type { RequestHandler } from 'express';
import { vulnLabsEnabled } from '../config.js';

export function pickHandler(
  fixed: RequestHandler,
  vulnerable: RequestHandler,
): RequestHandler {
  return vulnLabsEnabled() ? vulnerable : fixed;
}
