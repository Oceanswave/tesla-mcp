import { describe, expect, it } from "vitest";
import { computeNextRun, localDateString, localToInstant } from "../src/owner/schedule";

const NY = "America/New_York";
const next = (now: string, time = "22:00", zone = NY) => computeNextRun(new Date(now), time, zone).toISOString();

describe("computeNextRun", () => {
  it("runs later today, or tomorrow once the time has passed", () => {
    expect(next("2026-10-23T15:00:00Z")).toBe("2026-10-24T02:00:00.000Z"); // 22:00 EDT
    expect(next("2026-10-24T02:00:00Z")).toBe("2026-10-25T02:00:00.000Z"); // exactly at: strictly after
    expect(next("2026-10-24T02:00:01Z")).toBe("2026-10-25T02:00:00.000Z");
  });

  it("handles the 2026-11-01 fall-back", () => {
    // Oct 31 22:00 is still EDT (UTC-4).
    expect(next("2026-10-31T12:00:00Z")).toBe("2026-11-01T02:00:00.000Z");
    // Nov 1 22:00 is EST (UTC-5), 25 hours later.
    expect(next("2026-11-01T02:00:00Z")).toBe("2026-11-02T03:00:00.000Z");
    // The repeated 01:30 resolves to its first occurrence (EDT).
    expect(next("2026-11-01T04:00:00Z", "01:30")).toBe("2026-11-01T05:30:00.000Z");
    // Between the two 01:30s, the next is tomorrow's, not the second repeat.
    expect(next("2026-11-01T05:45:00Z", "01:30")).toBe("2026-11-02T06:30:00.000Z");
  });

  it("handles the 2027-03-14 spring-forward", () => {
    // Mar 13 22:00 is EST (UTC-5); Mar 14 22:00 is EDT (UTC-4), 23 hours later.
    expect(next("2027-03-13T12:00:00Z")).toBe("2027-03-14T03:00:00.000Z");
    expect(next("2027-03-14T03:00:00Z")).toBe("2027-03-15T02:00:00.000Z");
    // 02:30 does not exist that night; it runs at 03:30 EDT instead of being skipped.
    expect(next("2027-03-14T05:00:00Z", "02:30")).toBe("2027-03-14T07:30:00.000Z");
  });

  it("crosses month and year boundaries and supports other zones", () => {
    expect(next("2026-12-31T23:30:00Z", "00:15", "Europe/London")).toBe("2027-01-01T00:15:00.000Z");
    expect(next("2026-06-30T12:00:00Z", "09:00", "Asia/Kolkata")).toBe("2026-07-01T03:30:00.000Z");
  });

  it("rejects invalid input", () => {
    expect(() => next("2026-10-23T15:00:00Z", "24:00")).toThrow(RangeError);
    expect(() => next("2026-10-23T15:00:00Z", "9:00")).toThrow(RangeError);
    expect(() => next("2026-10-23T15:00:00Z", "22:00", "Mars/Olympus")).toThrow(RangeError);
  });

  it("reports local dates in the zone", () => {
    expect(localDateString(Date.parse("2026-11-01T03:59:00Z"), NY)).toBe("2026-10-31");
    expect(localToInstant(2026, 11, 1, 22, 0, NY)).toBe(Date.parse("2026-11-02T03:00:00Z"));
  });
});
