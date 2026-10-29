import { render, screen } from "@testing-library/react"
import { expect, it } from "vitest"
import { CertificateStatusPill } from "./status"
import { ValidityBar } from "./validity-bar"

const hours = (n: number) => new Date(Date.now() + n * 3_600_000).toISOString()

it("names each status, not only by colour", () => {
  const { rerender } = render(<CertificateStatusPill status="valid" expiring={false} />)
  expect(screen.getByText("Valid")).toBeInTheDocument()
  rerender(<CertificateStatusPill status="valid" expiring />)
  expect(screen.getByText("Expiring")).toBeInTheDocument()
  rerender(<CertificateStatusPill status="revoked" expiring={false} />)
  expect(screen.getByText("Revoked")).toBeInTheDocument()
  rerender(<CertificateStatusPill status="not_yet_valid" expiring={false} />)
  expect(screen.getByText("Not yet valid")).toBeInTheDocument()
})

it("draws the elapsed lifetime and says what is left", () => {
  render(<ValidityBar notBefore={hours(-6)} notAfter={hours(18)} status="valid" expiring={false} />)
  expect(screen.getByRole("meter", { name: "Lifetime elapsed" })).toHaveAttribute("aria-valuenow", "25")
  expect(screen.getByText("ends in 18 hours")).toBeInTheDocument()
})

it("says when a certificate was revoked rather than when it ends", () => {
  render(
    <ValidityBar notBefore={hours(-6)} notAfter={hours(18)} status="revoked" expiring={false} revokedAt={hours(-2)} />,
  )
  expect(screen.getByText("revoked 2 hours ago")).toBeInTheDocument()
})
