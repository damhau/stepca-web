import { useQueryClient } from "@tanstack/react-query"
import { useNavigate } from "@tanstack/react-router"
import { Check, X } from "lucide-react"
import { useEffect, useState } from "react"
import { $api, errorMessage, fetchClient } from "@/api/client"
import { useSession } from "@/api/session"
import type { CsrDescription, ProvisionerItem } from "@/api/types"
import { toast } from "@/components/toaster"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"
import { base64, saveFile } from "@/lib/download"
import { colonHex } from "@/lib/format"
import { cn } from "@/lib/utils"
import { KEY_TYPES, makeCsr, validSan, type KeyType } from "./keys"

type Method = "gen" | "csr"
type Step = 1 | 2 | 3 | 4

const VALIDITIES = [
  { value: "default", label: "The provisioner's default", hours: null },
  { value: "24", label: "24 hours", hours: 24 },
  { value: "168", label: "7 days", hours: 168 },
  { value: "720", label: "30 days", hours: 720 },
  { value: "2160", label: "90 days", hours: 2160 },
  { value: "8760", label: "1 year", hours: 8760 },
]

// step-ca's default maximum when neither the provisioner nor ca.json sets one
const CA_DEFAULT_MAX_HOURS = 24
const MAX_CSR_BYTES = 64 * 1024
const UNITS: Record<string, number> = { h: 1, m: 1 / 60, s: 1 / 3600, ms: 1 / 3_600_000 }

function hours(duration: string | null | undefined) {
  if (!duration) return null
  let total = 0
  for (const [, number, unit] of duration.matchAll(/(\d+(?:\.\d+)?)(ms|h|m|s)/g))
    total += Number(number) * (UNITS[unit!] ?? 0)
  return total || null
}

function lifetimeLabel(total: number) {
  if (total >= 48 && total % 24 === 0) return `${total / 24} days`
  return `${Math.round(total * 100) / 100} hours`
}

function maxHours(provisioner: ProvisionerItem | undefined) {
  return hours(provisioner?.durations.max) ?? CA_DEFAULT_MAX_HOURS
}

type Issued = { serial: string; pem: string; chain: string; key: string | null; name: string }

/** "New certificate": a key pair made in this browser (only its CSR is sent) or an uploaded CSR, signed by a JWK provisioner. */
export default function IssueDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { authority } = useSession()
  const provisioners = $api.useQuery("get", "/api/v1/provisioners", {}, { enabled: open, staleTime: 60_000 })
  const jwk = (provisioners.data?.provisioners ?? []).filter((provisioner) => provisioner.type === "JWK")

  const [step, setStep] = useState<Step>(1)
  const [method, setMethod] = useState<Method>("gen")
  const [commonName, setCommonName] = useState("")
  const [sans, setSans] = useState<string[]>([])
  const [sanDraft, setSanDraft] = useState("")
  const [sanError, setSanError] = useState<string | null>(null)
  const [csr, setCsr] = useState("")
  const [preview, setPreview] = useState<{ csr: string; result: CsrDescription | null; error?: string } | null>(null)
  const [picked, setProvisionerName] = useState("")
  const [password, setPassword] = useState("")
  const [validity, setValidity] = useState("default")
  const [keyType, setKeyType] = useState<KeyType>("P-256")
  const [busy, setBusy] = useState(false)
  const [failure, setFailure] = useState<string | null>(null)
  const [issued, setIssued] = useState<Issued | null>(null)

  // What an uploaded CSR asks for, shown as soon as it is pasted
  useEffect(() => {
    const text = csr.trim()
    if (method !== "csr" || !text.includes("BEGIN CERTIFICATE REQUEST")) return
    const timer = setTimeout(async () => {
      const { data, error } = await fetchClient.POST("/api/v1/csr/preview", { body: { csr_pem: text } })
      setPreview({ csr: text, result: data ?? null, error: error ? errorMessage(error) : undefined })
    }, 300)
    return () => clearTimeout(timer)
  }, [csr, method])
  const csrPreview = preview && preview.csr === csr.trim() ? preview : null

  // The first JWK provisioner until another is picked
  const provisionerName = picked || jwk[0]?.name || ""
  const provisioner = jwk.find((item) => item.name === provisionerName)
  const chosen = VALIDITIES.find((item) => item.value === validity)!
  const tooLong = chosen.hours !== null && chosen.hours > maxHours(provisioner)
  // The common name is always one of the names: TLS clients ignore a CN that isn't among the SANs
  const commonSan = validSan(commonName.trim()) ? commonName.trim() : null
  const extraSans = sans.filter((san) => san !== commonSan)
  const names = method === "gen" ? [...(commonSan ? [commonSan] : []), ...extraSans] : (csrPreview?.result?.sans ?? [])
  const keyName = KEY_TYPES.find((item) => item.value === keyType)!

  const canContinue =
    step === 1
      ? method === "gen"
        ? commonName.trim().length > 0
        : !!csrPreview?.result?.signature_valid
      : step === 2
        ? !!provisioner && password.length > 0 && !tooLong
        : true

  function reset() {
    setStep(1)
    setCommonName("")
    setSans([])
    setSanDraft("")
    setCsr("")
    setPreview(null)
    setPassword("")
    setValidity("default")
    setFailure(null)
    setIssued(null)
  }

  function close(next: boolean) {
    if (busy) return
    onOpenChange(next)
    // Forget the password and the key with the dialog
    if (!next) setTimeout(reset, 200)
  }

  function addSan() {
    const value = sanDraft.trim()
    if (!value) return
    if (!validSan(value)) {
      setSanError(`"${value}" is not a DNS name, IP address, e-mail address or URI.`)
      return
    }
    setSanError(null)
    if (!sans.includes(value) && value !== commonSan) setSans([...sans, value])
    setSanDraft("")
  }

  async function issue() {
    setBusy(true)
    setFailure(null)
    try {
      const made = method === "gen" ? await makeCsr(keyType, commonName.trim(), names) : { csr: csr.trim(), key: null }
      const { data, error } = await fetchClient.POST("/api/v1/certificates", {
        body: {
          csr_pem: made.csr,
          provisioner: provisionerName,
          password,
          valid_for: chosen.hours ? `${chosen.hours}h` : null,
        },
      })
      if (error) throw new Error(errorMessage(error))
      setIssued({
        serial: data.serial,
        pem: data.pem,
        chain: data.chain_pem,
        key: made.key,
        name: method === "gen" ? commonName.trim() : (csrPreview?.result?.common_name ?? data.serial),
      })
      setPassword("")
      setStep(4)
      queryClient.invalidateQueries()
      toast.success("Certificate issued.")
    } catch (caught) {
      setFailure(errorMessage(caught))
    } finally {
      setBusy(false)
    }
  }

  function next() {
    if (!canContinue || busy) return
    if (step === 4) reset()
    else if (step === 3) issue()
    else setStep((step + 1) as Step)
  }

  const short =
    (issued?.name || commonName || "certificate").split(".")[0]?.replace(/[^A-Za-z0-9_-]/g, "_") || "certificate"
  const notAfter = chosen.hours ? `${chosen.hours}h` : null
  const cli =
    method === "gen"
      ? [
          `step ca certificate ${commonName.trim() || "<common-name>"} ${short}.crt ${short}.key`,
          `--provisioner ${provisionerName}`,
          ...(notAfter ? [`--not-after ${notAfter}`] : []),
          // With any --san, the step CLI leaves the common name out of the SANs: name it too
          ...(extraSans.length ? names.map((san) => `--san ${san}`) : []),
          keyName.cli,
          `--ca-url ${authority.url}`,
        ].join(" \\\n  ")
      : [
          `step ca sign ${short}.csr ${short}.crt`,
          `--provisioner ${provisionerName}`,
          ...(notAfter ? [`--not-after ${notAfter}`] : []),
          `--ca-url ${authority.url}`,
        ].join(" \\\n  ")

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent
        showCloseButton={false}
        className="top-16 max-h-[calc(100svh-6rem)] translate-y-0 gap-0 overflow-hidden p-0 sm:max-w-[720px]"
        onPointerDownOutside={(event) => busy && event.preventDefault()}
      >
        <div className="flex items-center justify-between gap-3 border-b border-border-subtle px-[22px] py-[18px]">
          <DialogTitle className="text-[17px] font-semibold">New certificate</DialogTitle>
          <DialogDescription className="sr-only">
            Issue an X.509 certificate from a JWK provisioner, in three steps
          </DialogDescription>
          <Button variant="ghost" size="icon-sm" onClick={() => close(false)} aria-label="Close">
            <X className="size-4" />
          </Button>
        </div>

        {step < 4 && (
          <ol
            aria-label="Steps"
            className="flex flex-wrap gap-x-6 gap-y-2 border-b border-border-subtle px-[22px] py-3.5"
          >
            {["Subject", "Provisioner & validity", "Review"].map((label, index) => {
              const number = index + 1
              const current = step === number
              const done = step > number
              return (
                <li
                  key={label}
                  aria-current={current ? "step" : undefined}
                  className={cn(
                    "flex items-center gap-2 font-medium",
                    current || done ? "text-foreground" : "text-muted-foreground",
                  )}
                >
                  <span
                    aria-hidden
                    className={cn(
                      "grid size-[22px] place-items-center rounded-full border text-xs",
                      current
                        ? "border-inverse bg-inverse text-inverse-foreground"
                        : done
                          ? "border-green-200 bg-success-bg text-success"
                          : "bg-card text-muted-foreground",
                    )}
                  >
                    {done ? <Check className="size-3" strokeWidth={3} /> : number}
                  </span>
                  {label}
                </li>
              )
            })}
          </ol>
        )}

        <div className="overflow-y-auto p-[22px]">
          {step === 1 && (
            <div className="flex flex-col gap-[18px]">
              <fieldset>
                <legend className="mb-2 text-[13px] font-medium">Key material</legend>
                <div className="grid gap-2.5 sm:grid-cols-2">
                  <ChoiceCard
                    name="method"
                    checked={method === "gen"}
                    onChange={() => setMethod("gen")}
                    title="Generate a key pair"
                    sub="In this browser; only the CSR is sent"
                  />
                  <ChoiceCard
                    name="method"
                    checked={method === "csr"}
                    onChange={() => setMethod("csr")}
                    title="Upload a CSR"
                    sub="Key stays on the target host"
                  />
                </div>
              </fieldset>
              {method === "gen" ? (
                <>
                  <div className="flex flex-col gap-1.5">
                    <label htmlFor="issue-cn" className="text-[13px] font-medium">
                      Common name
                    </label>
                    <Input
                      id="issue-cn"
                      value={commonName}
                      onChange={(event) => setCommonName(event.target.value)}
                      className="h-[38px] font-mono text-[13px]"
                      placeholder="api.example.internal"
                      autoFocus
                    />
                  </div>
                  <div className="flex flex-col gap-1.5">
                    <label htmlFor="issue-san" className="text-[13px] font-medium">
                      Subject alternative names
                    </label>
                    {names.length > 0 && (
                      <div className="flex flex-wrap gap-1.5">
                        {commonSan && (
                          <span className="inline-flex min-h-7 items-center gap-1.5 rounded-md border bg-sidebar px-2 font-mono text-xs">
                            {commonSan}
                            <span className="font-sans text-muted-foreground">common name</span>
                          </span>
                        )}
                        {extraSans.map((san) => (
                          <span
                            key={san}
                            className="inline-flex items-center gap-0.5 rounded-md border bg-sidebar py-0.5 pr-0.5 pl-2 font-mono text-xs"
                          >
                            {san}
                            <button
                              type="button"
                              aria-label={`Remove ${san}`}
                              onClick={() => setSans(sans.filter((item) => item !== san))}
                              className="grid size-6 place-items-center rounded text-muted-foreground hover:text-foreground"
                            >
                              <X className="size-3" />
                            </button>
                          </span>
                        ))}
                      </div>
                    )}
                    <div className="flex gap-2">
                      <Input
                        id="issue-san"
                        value={sanDraft}
                        onChange={(event) => setSanDraft(event.target.value)}
                        onKeyDown={(event) => {
                          if (event.key === "Enter") {
                            event.preventDefault()
                            addSan()
                          }
                        }}
                        placeholder="DNS name, IP address or email"
                        aria-invalid={!!sanError}
                        className="h-[38px] font-mono text-[13px]"
                      />
                      <Button variant="outline" className="h-[38px] text-[13px]" onClick={addSan}>
                        Add
                      </Button>
                    </div>
                    {sanError ? (
                      <p className="text-[13px] text-danger-fg">{sanError}</p>
                    ) : (
                      <p className="text-[13px] text-muted-foreground">
                        The common name is always included. Add the other names clients will use.
                      </p>
                    )}
                  </div>
                </>
              ) : (
                <div className="flex flex-col gap-1.5">
                  <label htmlFor="issue-csr" className="text-[13px] font-medium">
                    Certificate signing request
                  </label>
                  <Textarea
                    id="issue-csr"
                    rows={6}
                    value={csr}
                    onChange={(event) => setCsr(event.target.value)}
                    onDragOver={(event) => event.preventDefault()}
                    onDrop={async (event) => {
                      event.preventDefault()
                      const file = event.dataTransfer.files[0]
                      if (file && file.size <= MAX_CSR_BYTES) setCsr((await file.text()).trim())
                    }}
                    spellCheck={false}
                    placeholder="-----BEGIN CERTIFICATE REQUEST-----"
                    className="font-mono text-xs leading-normal"
                  />
                  <p className="text-[13px] text-muted-foreground">
                    Or drop a .csr file here, or{" "}
                    <label className="cursor-pointer text-brand hover:text-brand-hover">
                      choose one
                      <input
                        type="file"
                        accept=".csr,.pem,.req,.txt"
                        className="sr-only"
                        onChange={async (event) => {
                          const file = event.target.files?.[0]
                          if (file && file.size <= MAX_CSR_BYTES) setCsr((await file.text()).trim())
                        }}
                      />
                    </label>
                    .
                  </p>
                  {csrPreview &&
                    (csrPreview.result ? (
                      <dl
                        aria-live="polite"
                        className="grid grid-cols-[110px_minmax(0,1fr)] gap-x-3 gap-y-1 rounded-lg border bg-sidebar px-3 py-2 text-[13px]"
                      >
                        <dt className="text-muted-foreground">Subject</dt>
                        <dd className="font-mono break-all">{csrPreview.result.subject || "—"}</dd>
                        <dt className="text-muted-foreground">Names</dt>
                        <dd className="font-mono break-all">{csrPreview.result.sans.join(", ") || "—"}</dd>
                        <dt className="text-muted-foreground">Key</dt>
                        <dd>{csrPreview.result.key}</dd>
                        {!csrPreview.result.signature_valid && (
                          <dd className="col-span-2 text-danger-fg">
                            Its signature isn't valid: step-ca will refuse it.
                          </dd>
                        )}
                      </dl>
                    ) : (
                      <p role="alert" className="text-[13px] text-danger-fg">
                        {csrPreview.error}
                      </p>
                    ))}
                </div>
              )}
            </div>
          )}

          {step === 2 && (
            <div className="flex flex-col gap-[18px]">
              <fieldset>
                <legend className="mb-2 text-[13px] font-medium">Provisioner</legend>
                {provisioners.isPending ? (
                  <p className="text-muted-foreground">Loading the provisioners…</p>
                ) : jwk.length === 0 ? (
                  <p className="text-muted-foreground">
                    No JWK provisioner: create one in Provisioners. ACME provisioners can't issue from here.
                  </p>
                ) : (
                  <div className="flex flex-col gap-2">
                    {jwk.map((item) => (
                      <ChoiceCard
                        key={item.name}
                        name="provisioner"
                        checked={provisionerName === item.name}
                        onChange={() => setProvisionerName(item.name)}
                        title={<span className="font-mono text-[13px]">{item.name}</span>}
                        sub={
                          item.is_app_provisioner
                            ? "JWK · this app's own provisioner"
                            : "JWK · signs with the provisioner's password"
                        }
                        aside={`max ${item.durations.max ? lifetimeLabel(maxHours(item)) : "24 hours (CA default)"}`}
                      />
                    ))}
                  </div>
                )}
              </fieldset>
              <div className="flex flex-col gap-1.5">
                <label htmlFor="issue-password" className="text-[13px] font-medium">
                  Provisioner password
                </label>
                <Input
                  id="issue-password"
                  type="password"
                  autoComplete="off"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  className="h-[38px]"
                />
                <p className="text-[13px] text-muted-foreground">
                  It decrypts the provisioner's key on the server, for this request only.
                </p>
              </div>
              <div className="grid gap-3.5 sm:grid-cols-2">
                <div className="flex flex-col gap-1.5">
                  <label htmlFor="issue-validity" className="text-[13px] font-medium">
                    Validity
                  </label>
                  <Select value={validity} onValueChange={setValidity}>
                    <SelectTrigger
                      id="issue-validity"
                      className={cn("h-[38px] w-full", tooLong && "border-danger")}
                      aria-invalid={tooLong}
                    >
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {VALIDITIES.map((item) => (
                        <SelectItem key={item.value} value={item.value}>
                          {item.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                {method === "gen" && (
                  <div className="flex flex-col gap-1.5">
                    <label htmlFor="issue-key" className="text-[13px] font-medium">
                      Key type
                    </label>
                    <Select value={keyType} onValueChange={(value) => setKeyType(value as KeyType)}>
                      <SelectTrigger id="issue-key" className="h-[38px] w-full">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {KEY_TYPES.map((item) => (
                          <SelectItem key={item.value} value={item.value}>
                            {item.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                )}
              </div>
              {tooLong && provisioner && (
                <p role="alert" className="rounded-lg bg-danger-bg px-3 py-2.5 text-[13px] text-danger-fg">
                  {chosen.label} exceeds the {lifetimeLabel(maxHours(provisioner))} maximum for {provisioner.name}.
                </p>
              )}
            </div>
          )}

          {step === 3 && (
            <div className="flex flex-col gap-4">
              <dl className="grid grid-cols-[140px_minmax(0,1fr)] overflow-hidden rounded-xl border">
                {(
                  [
                    [
                      "Subject",
                      method === "gen" ? `CN=${commonName.trim()}` : (csrPreview?.result?.subject ?? "from CSR"),
                      true,
                    ],
                    ["Names", names.join(", ") || "none", true],
                    [
                      "Key",
                      method === "gen"
                        ? `${keyName.name}, generated in browser`
                        : (csrPreview?.result?.key ?? "from CSR"),
                      false,
                    ],
                    ["Provisioner", provisionerName, true],
                    ["Validity", chosen.label, false],
                    ["Issuer", "This authority's intermediate", false],
                  ] as [string, string, boolean][]
                ).map(([label, value, mono], index) => (
                  <div key={label} className="contents">
                    <dt className={cn("px-3.5 py-2.5 text-muted-foreground", index && "border-t border-border-subtle")}>
                      {label}
                    </dt>
                    <dd
                      className={cn(
                        "px-3.5 py-2.5 text-[13px] [overflow-wrap:anywhere]",
                        mono && "font-mono",
                        index && "border-t border-border-subtle",
                      )}
                    >
                      {value}
                    </dd>
                  </div>
                ))}
              </dl>
              <details>
                <summary className="min-h-7 cursor-pointer text-fg-2">Equivalent step CLI command</summary>
                <pre className="mt-2 rounded-lg border border-border-subtle bg-sidebar p-3 font-mono text-xs leading-relaxed [overflow-wrap:anywhere] whitespace-pre-wrap">
                  {cli}
                </pre>
              </details>
              {failure && (
                <p role="alert" className="rounded-lg bg-danger-bg px-3 py-2.5 text-[13px] text-danger-fg">
                  {failure}
                </p>
              )}
            </div>
          )}

          {step === 4 && issued && (
            <div className="flex flex-col items-start gap-[18px]">
              <span aria-hidden className="grid size-10 place-items-center rounded-full bg-success-bg">
                <Check className="size-5 text-success" strokeWidth={2.5} />
              </span>
              <div>
                <p role="status" className="text-[17px] font-semibold">
                  Certificate issued
                </p>
                <p className="mt-1 text-muted-foreground">
                  <span className="font-mono">{issued.name}</span> · serial{" "}
                  <span className="font-mono">{colonHex(BigInt(issued.serial).toString(16)).slice(0, 14)}…</span> ·
                  valid {chosen.hours ? chosen.label : "for the provisioner's default"}
                </p>
              </div>
              <div className="grid w-full gap-2.5 sm:grid-cols-3">
                <DownloadCard
                  title="PEM bundle"
                  sub={issued.key ? "cert + chain + key" : "cert + chain"}
                  onClick={() => saveFile(`${short}.pem`, issued.chain + (issued.key ?? ""))}
                />
                {issued.key ? (
                  <DownloadCard
                    title="Private key"
                    sub={`${short}.key, PKCS#8`}
                    onClick={() => saveFile(`${short}.key`, issued.key!)}
                  />
                ) : (
                  <DownloadCard
                    title="Certificate"
                    sub={`${short}.crt, PEM`}
                    onClick={() => saveFile(`${short}.crt`, issued.pem)}
                  />
                )}
                {issued.key && (
                  <DownloadCard
                    title="Kubernetes Secret"
                    sub="type kubernetes.io/tls"
                    onClick={() =>
                      saveFile(
                        `${short}-tls.yaml`,
                        `apiVersion: v1\nkind: Secret\nmetadata:\n  name: ${short.toLowerCase().replace(/_/g, "-")}-tls\ntype: kubernetes.io/tls\ndata:\n  tls.crt: ${base64(issued.chain)}\n  tls.key: ${base64(issued.key!)}\n`,
                        "application/yaml",
                      )
                    }
                  />
                )}
              </div>
              {issued.key && (
                <p className="rounded-lg bg-warning-bg px-3 py-2.5 text-[13px] text-warning-strong">
                  The private key exists only in this browser. Download it now; it can't be recovered later.
                </p>
              )}
            </div>
          )}
        </div>

        <div className="flex items-center justify-between gap-3 border-t border-border-subtle bg-sidebar px-[22px] py-3.5">
          {step > 1 && step < 4 ? (
            <Button variant="outline" onClick={() => setStep((step - 1) as Step)} disabled={busy}>
              Back
            </Button>
          ) : (
            <button
              type="button"
              className="min-h-9 px-1 font-medium text-fg-2 hover:text-foreground"
              onClick={() => {
                const serial = issued?.serial
                close(false)
                if (serial) navigate({ to: "/certificates", search: { cert: serial } })
              }}
            >
              {step === 4 ? "Back to certificates" : "Cancel"}
            </button>
          )}
          <Button
            onClick={next}
            disabled={!canContinue || busy}
            className="px-4 disabled:bg-neutral-dot disabled:opacity-100"
          >
            {step === 4 ? "Issue another" : step === 3 ? (busy ? "Issuing…" : "Issue certificate") : "Continue"}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}

function ChoiceCard({
  name,
  checked,
  onChange,
  title,
  sub,
  aside,
}: {
  name: string
  checked: boolean
  onChange: () => void
  title: React.ReactNode
  sub: string
  aside?: string
}) {
  return (
    <label
      className={cn(
        "flex cursor-pointer items-start gap-2.5 rounded-xl border px-3.5 py-3 transition-colors",
        checked ? "border-brand bg-brand-soft" : "bg-card hover:border-muted-foreground/40",
      )}
    >
      <input type="radio" name={name} checked={checked} onChange={onChange} className="mt-0.5 size-4 accent-brand" />
      <span className="min-w-0 flex-1">
        <span className="block font-medium">{title}</span>
        <span className="mt-0.5 block text-[13px] text-muted-foreground">{sub}</span>
      </span>
      {aside && <span className="self-center text-xs whitespace-nowrap text-muted-foreground">{aside}</span>}
    </label>
  )
}

function DownloadCard({ title, sub, onClick }: { title: string; sub: string; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="min-h-16 rounded-xl border bg-card px-3.5 py-2.5 text-left hover:border-muted-foreground/40 hover:bg-sidebar"
    >
      <span className="block font-medium">{title}</span>
      <span className="block text-xs text-muted-foreground">{sub}</span>
    </button>
  )
}
