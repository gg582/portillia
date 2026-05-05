const RECENT_ACTIVITY_WINDOW_MS = 90 * 1000;

function parseTimestamp(value: string | undefined): number | null {
  if (!value) {
    return null;
  }
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

export function isLeaseOnline(
  ready: number | undefined,
  lastSeenAt: string | undefined
): boolean {
  if ((ready || 0) > 0) {
    return true;
  }

  const lastSeenMs = parseTimestamp(lastSeenAt);
  if (lastSeenMs === null) {
    return false;
  }

  return Date.now() - lastSeenMs <= RECENT_ACTIVITY_WINDOW_MS;
}
