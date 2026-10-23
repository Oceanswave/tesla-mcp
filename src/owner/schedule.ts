// Wall-clock scheduling in an IANA time zone, correct across DST changes.
// Uses only Intl.DateTimeFormat (no time zone database bundled).

const DAY_MS = 86_400_000;
const formatters = new Map<string, Intl.DateTimeFormat>();

function formatter(timeZone: string): Intl.DateTimeFormat {
  let cached = formatters.get(timeZone);
  if (!cached) {
    cached = new Intl.DateTimeFormat("en-US", {
      timeZone,
      hourCycle: "h23",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
    formatters.set(timeZone, cached);
  }
  return cached;
}

export type LocalParts = {
  year: number;
  month: number;
  day: number;
  hour: number;
  minute: number;
  second: number;
};

export function localParts(instant: number, timeZone: string): LocalParts {
  const parts: Record<string, number> = {};
  for (const part of formatter(timeZone).formatToParts(new Date(instant))) {
    if (part.type !== "literal") parts[part.type] = Number(part.value);
  }
  return {
    year: parts.year as number,
    month: parts.month as number,
    day: parts.day as number,
    hour: parts.hour as number,
    minute: parts.minute as number,
    second: parts.second as number,
  };
}

/** The local wall-clock time at `instant`, expressed as if it were UTC. */
function wallClockAsUtc(instant: number, timeZone: string): number {
  const p = localParts(instant, timeZone);
  return Date.UTC(p.year, p.month - 1, p.day, p.hour, p.minute, p.second);
}

function offsetAt(instant: number, timeZone: string): number {
  return wallClockAsUtc(instant, timeZone) - Math.floor(instant / 1000) * 1000;
}

/** Convert a local wall-clock time to an instant.
 * - Ambiguous (fall-back repeated hour): the first occurrence.
 * - Nonexistent (spring-forward gap): shifted forward by the gap length, e.g.
 *   02:30 on a spring-forward night becomes 03:30 daylight time. */
export function localToInstant(
  year: number,
  month: number,
  day: number,
  hour: number,
  minute: number,
  timeZone: string,
): number {
  const target = Date.UTC(year, month - 1, day, hour, minute);
  const before = offsetAt(target - DAY_MS, timeZone);
  const after = offsetAt(target + DAY_MS, timeZone);
  const candidates = [...new Set([before, after])]
    .map((offset) => target - offset)
    .filter((instant) => wallClockAsUtc(instant, timeZone) === target)
    .sort((a, b) => a - b);
  return candidates[0] ?? target - before;
}

export function localDateString(instant: number, timeZone: string): string {
  const p = localParts(instant, timeZone);
  return `${p.year}-${String(p.month).padStart(2, "0")}-${String(p.day).padStart(2, "0")}`;
}

export function parseLocalTime(value: string): { hour: number; minute: number } | null {
  const match = /^([01]\d|2[0-3]):([0-5]\d)$/.exec(value);
  if (!match) return null;
  return { hour: Number(match[1]), minute: Number(match[2]) };
}

export function validTimeZone(value: string): boolean {
  if (!value || value.length > 64) return false;
  try {
    formatter(value);
    return true;
  } catch {
    return false;
  }
}

/** The next instant strictly after `now` whose local time in `timeZone` is
 * `hhmm` ("HH:MM", 24-hour). Throws on invalid input. */
export function computeNextRun(now: Date, hhmm: string, timeZone: string): Date {
  const time = parseLocalTime(hhmm);
  if (!time) throw new RangeError("invalid local time");
  if (!validTimeZone(timeZone)) throw new RangeError("invalid time zone");
  const nowMs = now.getTime();
  const today = localParts(nowMs, timeZone);
  for (let offset = 0; offset <= 2; offset++) {
    // Date.UTC normalizes day overflow across month and year boundaries.
    const date = new Date(Date.UTC(today.year, today.month - 1, today.day + offset));
    const candidate = localToInstant(
      date.getUTCFullYear(),
      date.getUTCMonth() + 1,
      date.getUTCDate(),
      time.hour,
      time.minute,
      timeZone,
    );
    if (candidate > nowMs) return new Date(candidate);
  }
  throw new Error("no next run found");
}
