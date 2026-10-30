import { describe, expect, it } from "vitest"
import { certificateState } from "./kit"

describe("certificateState", () => {
  it("names each status, and tells expiring certificates from active ones", () => {
    expect(certificateState("valid", false)).toEqual({ tone: "success", label: "Active" })
    expect(certificateState("valid", true)).toEqual({ tone: "warning", label: "Expiring" })
    expect(certificateState("revoked", false)).toEqual({ tone: "danger", label: "Revoked" })
    expect(certificateState("expired", false)).toEqual({ tone: "neutral", label: "Expired" })
    expect(certificateState("not_yet_valid", false)).toEqual({ tone: "brand", label: "Not yet valid" })
  })
})
