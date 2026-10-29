import { expect, it } from "vitest"
import { errorMessage } from "./client"

it("says what went wrong in words", () => {
  expect(errorMessage({ error: "Certificate 42 not found." })).toBe("Certificate 42 not found.")
  expect(
    errorMessage([
      {
        loc: ["valid_for"],
        msg: "Value error, 'two days' is not a duration such as 24h, 90m or 1h30m",
        type: "value_error",
      },
      { loc: ["password"], msg: "Field required", type: "missing" },
    ]),
  ).toBe("valid_for: 'two days' is not a duration such as 24h, 90m or 1h30m; password: Field required")
  expect(errorMessage(new TypeError("Failed to fetch"))).toBe("The server could not be reached.")
  expect(errorMessage(undefined)).toBe("Something went wrong.")
})
