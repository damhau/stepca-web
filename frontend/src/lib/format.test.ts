import { describe, expect, it } from "vitest"
import { fromNow, lifetime, plural } from "./format"

const NOW = Date.parse("2026-10-29T12:00:00Z")
const at = (hours: number) => new Date(NOW + hours * 3_600_000).toISOString()

describe("fromNow", () => {
  it("uses the unit that suits the distance", () => {
    expect(fromNow(at(0.25), NOW)).toBe("in 15 minutes")
    expect(fromNow(at(23), NOW)).toBe("in 23 hours")
    expect(fromNow(at(-30), NOW)).toBe("30 hours ago")
    expect(fromNow(at(24 * 12), NOW)).toBe("in 12 days")
    expect(fromNow(at(-24 * 400), NOW)).toBe("400 days ago")
  })

  it("never says zero minutes", () => {
    expect(fromNow(at(0), NOW)).toBe("in 1 minute")
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
