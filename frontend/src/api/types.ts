import type { components } from "./schema"

type Schemas = components["schemas"]

export type SessionInfo = Schemas["SessionInfo"]
export type Role = NonNullable<SessionInfo["role"]>
export type CertificateItem = Schemas["CertificateItem"]
export type CertificateStatus = CertificateItem["status"]
export type CertificateDetail = Schemas["CertificateDetail"]
export type Dashboard = Schemas["Dashboard"]
export type AcmeAccountItem = Schemas["AcmeAccountItem"]
export type AcmeOrderItem = Schemas["AcmeOrderItem"]
export type AcmeAuthorizationItem = Schemas["AcmeAuthorizationItem"]
export type AcmeChallengeItem = Schemas["AcmeChallengeItem"]
export type AcmeCertificateItem = Schemas["AcmeCertificateItem"]
export type AcmeIdentifier = Schemas["AcmeIdentifier"]
export type ProvisionerItem = Schemas["ProvisionerItem"]
export type AdminItem = Schemas["AdminItem"]
export type CaCertificate = Schemas["CaCertificate"]
export type AuditItem = Schemas["AuditItem"]
export type CsrDescription = Schemas["CsrDescription"]
