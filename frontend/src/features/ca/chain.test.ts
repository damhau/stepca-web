import { describe, expect, it } from "vitest"
import type { CaCertificate } from "@/api/types"
import { chainOf, commonName } from "./chain"

function cert(subject: string, issuer: string, fingerprint: string): CaCertificate {
  return {
    subject,
    issuer,
    fingerprint,
    not_before: "2026-01-01T00:00:00Z",
    not_after: "2036-01-01T00:00:00Z",
    serial: "1",
    key: "secp256r1",
    days_left: 3600,
    pinned: false,
  }
}

const rootA = cert("CN=Root A", "CN=Root A", "ra")
const rootB = cert("CN=Root B", "CN=Root B", "rb")

describe("chainOf", () => {
  it("puts each intermediate under the root that issued it, and step-ca's first as the signing one", () => {
    const signing = cert("CN=Issuing CA", "CN=Root B", "i1")
    const older = cert("CN=Old issuing CA", "CN=Root A", "i2")
    const chain = chainOf([rootA, rootB], [signing, older])
    expect(chain.map((link) => [link.cert.fingerprint, link.role, link.signing, link.linked])).toEqual([
      ["ra", "root", false, false],
      ["i2", "intermediate", false, true],
      ["rb", "root", false, false],
      ["i1", "intermediate", true, true],
    ])
  })

  it("still shows an intermediate whose root the CA doesn't list, unlinked", () => {
    const orphan = cert("CN=Issuing CA", "CN=Elsewhere", "i1")
    expect(chainOf([rootA], [orphan]).map((link) => [link.cert.fingerprint, link.linked])).toEqual([
      ["ra", false],
      ["i1", false],
    ])
  })
})

describe("commonName", () => {
  it("takes the CN out of the subject, or the whole subject without one", () => {
    expect(commonName("CN=E2E CA Intermediate CA,O=E2E CA")).toBe("E2E CA Intermediate CA")
    expect(commonName("O=Corp,CN=Corp Root")).toBe("Corp Root")
    expect(commonName("O=Corp")).toBe("O=Corp")
  })
})
