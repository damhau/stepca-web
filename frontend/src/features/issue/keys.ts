import "reflect-metadata"
import * as x509 from "@peculiar/x509"

// Key pairs and CSRs made in the browser with WebCrypto: the private key never leaves it

export type KeyType = "P-256" | "P-384" | "Ed25519" | "RSA-2048"

export const KEY_TYPES: { value: KeyType; label: string; cli: string; name: string }[] = [
  { value: "P-256", label: "ECDSA P-256 (recommended)", cli: "--kty EC --curve P-256", name: "ECDSA P-256" },
  { value: "P-384", label: "ECDSA P-384", cli: "--kty EC --curve P-384", name: "ECDSA P-384" },
  { value: "Ed25519", label: "Ed25519", cli: "--kty OKP --curve Ed25519", name: "Ed25519" },
  { value: "RSA-2048", label: "RSA 2048", cli: "--kty RSA --size 2048", name: "RSA 2048" },
]

const ALGORITHMS: Record<KeyType, RsaHashedKeyGenParams | EcKeyGenParams | Algorithm> = {
  "P-256": { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" } as EcKeyGenParams,
  "P-384": { name: "ECDSA", namedCurve: "P-384", hash: "SHA-384" } as EcKeyGenParams,
  Ed25519: { name: "Ed25519" },
  "RSA-2048": {
    name: "RSASSA-PKCS1-v1_5",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-256",
  },
}

const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/
const IPV6 = /^[0-9a-f:]+$/i

/** How a subject alternative name is encoded: an IP address, an e-mail address, a URI or a DNS name. */
export function sanType(value: string): "ip" | "email" | "url" | "dns" {
  if (IPV4.test(value) || (value.includes(":") && IPV6.test(value))) return "ip"
  if (value.includes("://")) return "url"
  if (value.includes("@")) return "email"
  return "dns"
}

export function validSan(value: string) {
  const type = sanType(value)
  if (type === "ip") return IPV4.test(value) ? value.split(".").every((part) => Number(part) <= 255) : true
  if (type === "email") return /^[^@\s]+@[^@\s]+$/.test(value)
  if (type === "url") return /^[a-z][a-z0-9+.-]*:\/\/\S+$/i.test(value)
  return /^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i.test(value)
}

function pem(label: string, der: ArrayBuffer) {
  const text = btoa(String.fromCharCode(...new Uint8Array(der)))
  return `-----BEGIN ${label}-----\n${text.match(/.{1,64}/g)?.join("\n")}\n-----END ${label}-----\n`
}

/** A new key pair, and a CSR for this common name and these names. */
export async function makeCsr(keyType: KeyType, commonName: string, sans: string[]) {
  x509.cryptoProvider.set(crypto)
  const algorithm = ALGORITHMS[keyType]
  let keys: CryptoKeyPair
  try {
    keys = (await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"])) as CryptoKeyPair
  } catch {
    throw new Error(
      `This browser can't generate ${KEY_TYPES.find((type) => type.value === keyType)?.name} keys: choose another key type.`,
    )
  }
  const csr = await x509.Pkcs10CertificateRequestGenerator.create({
    name: [{ CN: [commonName] }],
    keys,
    signingAlgorithm: algorithm,
    extensions: sans.length
      ? [new x509.SubjectAlternativeNameExtension(sans.map((value) => ({ type: sanType(value), value })))]
      : [],
  })
  return { csr: csr.toString("pem"), key: pem("PRIVATE KEY", await crypto.subtle.exportKey("pkcs8", keys.privateKey)) }
}
