import type { CaCertificate } from "@/api/types"

export type ChainLink = { cert: CaCertificate; role: "root" | "intermediate"; signing: boolean; linked: boolean }

/** Each root, then the intermediates it issued. step-ca signs with the first intermediate it lists (its crt). */
export function chainOf(roots: CaCertificate[], intermediates: CaCertificate[]): ChainLink[] {
  const signing = intermediates[0]?.fingerprint
  const placed = new Set<string>()
  const chain: ChainLink[] = []
  for (const root of roots) {
    chain.push({ cert: root, role: "root", signing: false, linked: false })
    for (const intermediate of intermediates) {
      if (intermediate.issuer !== root.subject || placed.has(intermediate.fingerprint)) continue
      placed.add(intermediate.fingerprint)
      chain.push({
        cert: intermediate,
        role: "intermediate",
        signing: intermediate.fingerprint === signing,
        linked: true,
      })
    }
  }
  // Issued by a root the CA doesn't list
  for (const intermediate of intermediates) {
    if (!placed.has(intermediate.fingerprint))
      chain.push({
        cert: intermediate,
        role: "intermediate",
        signing: intermediate.fingerprint === signing,
        linked: false,
      })
  }
  return chain
}

export function commonName(subject: string) {
  return /(?:^|,)CN=([^,]+)/.exec(subject)?.[1] ?? subject
}
