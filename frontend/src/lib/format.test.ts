import { describe, expect, it } from "vitest"
import { colonHex, fromNow, keyLabel, lifetime, plural, shortDuration } from "./format"

const NOW = Date.parse("2026-10-29T12:00:00Z")
const at = (hours: number) => new Date(NOW + hours * 3_600_000).toISOString()

describe("fromNow", () => {
  it("uses the unit that suits the distance", () => {
    expect(fromNow(at(0.25), NOW)).toBe("in 15 minutes")
    expect(fromNow(at(23), NOW)).toBe("in 23 hours")
    expect(fromNow(at(-30), NOW)).toBe("30 hours ago")
    expect(fromNow(at(24 * 12), NOW)).toBe("in 12 days")
    expect(fromNow(at(-24 * 400), NOW)).toBe("400 days ago")
    expect(fromNow(at(-49), NOW)).toBe("2 days ago")
  })

  it("never says zero minutes", () => {
    expect(fromNow(at(0), NOW)).toBe("in 1 minute")
  })

  it("writes serials with colons", () => {
    expect(colonHex("4f2a910c")).toBe("4f:2a:91:0c")
    expect(colonHex("abc")).toBe("0a:bc")
  })

  it("shows a dash for no date", () => {
    expect(fromNow(null, NOW)).toBe("—")
  })
})

describe("lifetime", () => {
  it("is the elapsed part of the validity, between 0 and 1", () => {
    expect(lifetime(at(-6), at(18), NOW)?.elapsed).toBe(0.25)
    expect(lifetime(at(1), at(25), NOW)?.elapsed).toBe(0)
    expect(lifetime(at(-48), at(-24), NOW)?.elapsed).toBe(1)
    expect(lifetime(at(-24 * 45), at(24 * 45), NOW)?.days).toBe(90)
  })

  it("is null without both dates", () => {
    expect(lifetime(null, at(1), NOW)).toBeNull()
  })
})

it("pluralises", () => {
  expect(plural(1, "certificate")).toBe("1 certificate")
  expect(plural(1200, "certificate")).toMatch(/^1.200 certificates$/)
})

describe("shortDuration", () => {
  it("drops zero units and counts whole days", () => {
    expect(shortDuration("24h0m0s")).toBe("24h")
    expect(shortDuration("48h0m0s")).toBe("2d")
    expect(shortDuration("2160h0m0s")).toBe("90d")
    expect(shortDuration("1h30m0s")).toBe("1h30m")
    expect(shortDuration("5m0s")).toBe("5m")
    expect(shortDuration("90s")).toBe("1m30s")
    expect(shortDuration(null)).toBeNull()
    expect(shortDuration("2160h0m0s", { days: false })).toBe("2160h")
  })
})

describe("keyLabel", () => {
  it("names curves as NIST does and leaves the rest", () => {
    expect(keyLabel("secp256r1")).toBe("P-256")
    expect(keyLabel("secp384r1")).toBe("P-384")
    expect(keyLabel("RSA 2048")).toBe("RSA 2048")
    expect(keyLabel("Ed25519")).toBe("Ed25519")
    expect(keyLabel(null)).toBe("—")
  })
})
