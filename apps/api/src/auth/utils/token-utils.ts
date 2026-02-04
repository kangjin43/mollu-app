import { createHash } from 'crypto';

export function hashToken(token: string) {
  return createHash('sha256').update(token).digest('hex');
}

export function durationToMs(duration: string, fallbackMs: number) {
  if (!duration) {
    return fallbackMs;
  }
  const match = duration.trim().match(/^(\d+)(ms|s|m|h|d)$/);
  if (!match) {
    return fallbackMs;
  }
  const value = Number.parseInt(match[1], 10);
  const unit = match[2];
  switch (unit) {
    case 'ms':
      return value;
    case 's':
      return value * 1000;
    case 'm':
      return value * 60 * 1000;
    case 'h':
      return value * 60 * 60 * 1000;
    case 'd':
      return value * 24 * 60 * 60 * 1000;
    default:
      return fallbackMs;
  }
}
