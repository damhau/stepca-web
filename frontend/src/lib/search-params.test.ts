import { expect, it } from "vitest"
import { int, listSearch, oneOf, text } from "./search-params"

it("keeps only valid values from the URL", () => {
  expect(listSearch({ page: "3", per_page: "100", q: "web" })).toEqual({ page: 3, per_page: 100, q: "web" })
  expect(listSearch({ page: "0", per_page: "9000", q: "  " })).toEqual({
    page: undefined,
    per_page: undefined,
    q: undefined,
  })
  expect(int("2.5")).toBeUndefined()
  expect(oneOf("revoked", ["valid", "revoked"] as const)).toBe("revoked")
  expect(oneOf("<script>", ["valid", "revoked"] as const)).toBeUndefined()
  expect(text("x".repeat(500))).toHaveLength(200)
})
