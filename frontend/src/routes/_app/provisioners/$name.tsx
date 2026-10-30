import { useQuery, useQueryClient } from "@tanstack/react-query"
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router"
import { useState } from "react"
import { stringify } from "yaml"
import { $api, errorMessage } from "@/api/client"
import { useCan, useSession } from "@/api/session"
import type { ProvisionerItem } from "@/api/types"
import { columnHelper, DataTable } from "@/components/data-table"
import { CertificateStatus, ErrorState, LineTabs, Loading, Mono, Pill, SettingsSection } from "@/components/kit"
import { toast } from "@/components/toaster"
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { base64 } from "@/lib/download"
import { formatDate, formatDateTime, formatNumber, fromNow, plural, shortDuration } from "@/lib/format"
import { oneOf } from "@/lib/search-params"
import { cn } from "@/lib/utils"
import type { AuditItem, CertificateItem } from "@/api/types"

const TABS = ["general", "usage", "activity"] as const

export const Route = createFileRoute("/_app/provisioners/$name")({
  validateSearch: (search: Record<string, unknown>): { tab?: (typeof TABS)[number] } => ({
    tab: oneOf(search.tab, TABS),
  }),
  component: Provisioner,
})

const CHALLENGES = [
  { value: "HTTP_01", name: "http-01", description: "Serve a token on port 80. Simplest for public-facing servers." },
  { value: "DNS_01", name: "dns-01", description: "Publish a TXT record. Works for wildcards and internal hosts." },
  { value: "TLS_ALPN_01", name: "tls-alpn-01", description: "Answer on port 443 with a special certificate." },
] as const

type Challenge = (typeof CHALLENGES)[number]["value"]

const GO_DURATION = /^(\d+(\.\d+)?(ns|us|µs|ms|s|m|h))+$/

type Draft = {
  min: string
  def: string
  max: string
  challenges: Challenge[]
  forceCn: boolean
  requireEab: boolean
  disableRenewal: boolean
  renewAfterExpiry: boolean
}

function draftOf(item: ProvisionerItem): Draft {
  return {
    // As typed: "24h" rather than step-ca's "24h0m0s"
    min: shortDuration(item.durations.min, { days: false }) ?? "",
    def: shortDuration(item.durations.default, { days: false }) ?? "",
    max: shortDuration(item.durations.max, { days: false }) ?? "",
    challenges: (item.acme?.challenges ?? []) as Challenge[],
    forceCn: !!item.acme?.force_cn,
    requireEab: !!item.acme?.require_eab,
    disableRenewal: item.disable_renewal,
    renewAfterExpiry: item.allow_renewal_after_expiry,
  }
}

function changes(base: Draft, draft: Draft) {
  let count = 0
  for (const key of ["min", "def", "max", "forceCn", "requireEab", "disableRenewal", "renewAfterExpiry"] as const)
    if (base[key] !== draft[key]) count++
  for (const challenge of CHALLENGES)
    if (base.challenges.includes(challenge.value) !== draft.challenges.includes(challenge.value)) count++
  return count
}

function Provisioner() {
  const { name } = Route.useParams()
  const { tab = "general" } = Route.useSearch()
  const navigate = Route.useNavigate()
  const { data, error, refetch } = $api.useQuery("get", "/api/v1/provisioners/{name}", { params: { path: { name } } })
  const [yaml, setYaml] = useState(false)
  return (
    <>
      <p className="-mb-1 text-[13px] text-muted-foreground">
        <Link to="/provisioners" className="text-muted-foreground hover:text-foreground">
          Provisioners
        </Link>{" "}
        / {name}
      </p>
      {error ? (
        <ErrorState error={error} onRetry={() => refetch()} />
      ) : !data ? (
        <Loading lines={6} />
      ) : (
        <>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex min-w-0 items-center gap-3">
              <span
                aria-hidden
                className="grid size-10 shrink-0 place-items-center rounded-xl bg-brand-tile font-mono text-xs font-semibold text-brand"
              >
                {data.type.slice(0, 2).toUpperCase()}
              </span>
              <div className="min-w-0">
                <h1 className="font-mono text-[22px] font-semibold tracking-[-0.02em] break-words">{data.name}</h1>
                <p className="mt-0.5 text-[13px] text-muted-foreground">
                  {data.type}
                  {data.created_at && ` · created ${formatDate(data.created_at)}`} ·{" "}
                  {plural(data.issued_30d, "certificate")} in 30 days
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2.5">
              {data.is_app_provisioner && <Pill tone="brand">This app's provisioner</Pill>}
              <Button variant="outline" onClick={() => setYaml(true)}>
                View as YAML
              </Button>
            </div>
          </div>
          <LineTabs
            label="Provisioner sections"
            className="max-w-[1040px]"
            value={tab}
            onChange={(value) => navigate({ search: { tab: value === "general" ? undefined : value }, replace: true })}
            tabs={[
              { value: "general", label: "General" },
              { value: "usage", label: "Usage" },
              { value: "activity", label: "Activity" },
            ]}
          />
          {tab === "general" ? (
            <General key={JSON.stringify(data)} item={data} />
          ) : tab === "usage" ? (
            <Usage item={data} />
          ) : (
            <Activity name={data.name} />
          )}
          <Dialog open={yaml} onOpenChange={setYaml}>
            <DialogContent className="sm:max-w-2xl">
              <DialogHeader>
                <DialogTitle className="font-mono">{data.name}</DialogTitle>
                <DialogDescription>As step-ca's Admin API returns it.</DialogDescription>
              </DialogHeader>
              <pre className="max-h-[60vh] overflow-auto rounded-lg border border-border-subtle bg-sidebar p-3 font-mono text-xs leading-relaxed">
                {stringify(data.raw)}
              </pre>
            </DialogContent>
          </Dialog>
        </>
      )}
    </>
  )
}

function rootBundle() {
  return fetch("/api/v1/ca/roots.pem", { credentials: "same-origin" }).then((response) => {
    if (!response.ok) throw new Error("The CA's roots could not be read.")
    return response.text()
  })
}

function General({ item }: { item: ProvisionerItem }) {
  const can = useCan()
  const { authority } = useSession()
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const editable = can("admin")
  const [base, setBase] = useState(() => draftOf(item))
  const [draft, setDraft] = useState(base)
  const [saved, setSaved] = useState(false)
  const [copied, setCopied] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const roots = useQuery({
    queryKey: ["roots.pem"],
    queryFn: rootBundle,
    staleTime: Infinity,
    enabled: item.type === "ACME",
  })
  const set = (changes: Partial<Draft>) => {
    setDraft((current) => ({ ...current, ...changes }))
    setSaved(false)
  }
  const count = changes(base, draft)
  const invalid = (["min", "def", "max"] as const).filter((key) => draft[key] && !GO_DURATION.test(draft[key].trim()))
  const save = $api.useMutation("put", "/api/v1/provisioners/{name}", {
    onSuccess: (updated) => {
      const next = draftOf(updated)
      setBase(next)
      setDraft(next)
      setSaved(true)
      queryClient.invalidateQueries({ queryKey: ["get", "/api/v1/provisioners"] })
    },
  })
  const remove = $api.useMutation("delete", "/api/v1/provisioners/{name}", {
    onSuccess: ({ message }) => {
      toast.success(message)
      queryClient.invalidateQueries()
      navigate({ to: "/provisioners" })
    },
  })
  const directory = item.directory_url ?? ""
  const snippet = `apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: step-ca
spec:
  acme:
    server: ${directory}
    caBundle: ${roots.data ? base64(roots.data) : "<base64 of the CA's root certificate>"}
    privateKeySecretRef:
      name: step-ca-account-key${
        draft.requireEab
          ? `
    externalAccountBinding:
      keyID: <EAB key ID>
      keySecretRef: { name: step-eab, key: secret }`
          : ""
      }
    solvers:
      - http01:
          ingress: {}`
  return (
    <div className="flex max-w-[1040px] flex-col">
      {item.type === "ACME" ? (
        <SettingsSection title="Directory" description="Point cert-manager, certbot or any ACME client at this URL.">
          <div className="flex flex-col gap-3 rounded-xl border bg-card p-4">
            <label htmlFor="directory" className="text-[13px] font-medium">
              Directory URL
            </label>
            <div className="flex gap-2">
              <Input id="directory" readOnly value={directory} className="font-mono text-[13px]" />
              <Button
                variant="outline"
                className="text-[13px]"
                onClick={async () => {
                  await navigator.clipboard.writeText(directory)
                  setCopied(true)
                }}
              >
                {copied ? "Copied" : "Copy"}
              </Button>
            </div>
            <details className="text-[13px]">
              <summary className="min-h-7 cursor-pointer text-fg-2">cert-manager ClusterIssuer snippet</summary>
              <pre className="mt-2 overflow-x-auto rounded-lg border border-border-subtle bg-sidebar p-3 font-mono text-xs leading-relaxed [overflow-wrap:anywhere] whitespace-pre-wrap">
                {snippet}
              </pre>
            </details>
          </div>
        </SettingsSection>
      ) : (
        <SettingsSection
          title="Use it"
          description="Anyone with the provisioner's password can get certificates from it, for example with the step CLI."
        >
          <pre className="overflow-x-auto rounded-xl border bg-card p-4 font-mono text-xs leading-relaxed [overflow-wrap:anywhere] whitespace-pre-wrap">
            {`step ca certificate <name> <name>.crt <name>.key \\\n  --provisioner ${item.name} \\\n  --ca-url ${authority.url}`}
          </pre>
        </SettingsSection>
      )}

      {item.type === "ACME" && (
        <SettingsSection
          title="Challenges"
          description="How clients prove they control a name. Turn off the ones your network can't reach. None ticked: step-ca allows all three."
        >
          <div className="grid grid-cols-[repeat(auto-fit,minmax(180px,1fr))] gap-2.5">
            {CHALLENGES.map((challenge) => {
              const on = draft.challenges.includes(challenge.value)
              return (
                <label
                  key={challenge.value}
                  className={cn(
                    "flex items-start gap-2.5 rounded-xl border p-3.5",
                    editable && "cursor-pointer",
                    on ? "border-brand bg-brand-soft" : "bg-card",
                  )}
                >
                  <input
                    type="checkbox"
                    checked={on}
                    disabled={!editable}
                    onChange={() =>
                      set({
                        challenges: on
                          ? draft.challenges.filter((value) => value !== challenge.value)
                          : [...draft.challenges, challenge.value],
                      })
                    }
                    className="mt-0.5 size-4 accent-brand"
                  />
                  <span>
                    <span className="block font-mono text-[13px] font-medium">{challenge.name}</span>
                    <span className="mt-1 block text-[13px] leading-snug text-muted-foreground">
                      {challenge.description}
                    </span>
                  </span>
                </label>
              )
            })}
          </div>
        </SettingsSection>
      )}

      <SettingsSection
        title="Certificate lifetime"
        description="Requests outside this range are rejected. Shorter is safer when renewal is automated."
      >
        <div className="grid grid-cols-[repeat(auto-fit,minmax(130px,1fr))] gap-3 rounded-xl border bg-card p-4">
          {(
            [
              ["min", "Minimum"],
              ["def", "Default"],
              ["max", "Maximum"],
            ] as const
          ).map(([key, label]) => (
            <div key={key} className="flex flex-col gap-1.5">
              <label htmlFor={`lifetime-${key}`} className="text-[13px] font-medium">
                {label}
              </label>
              <Input
                id={`lifetime-${key}`}
                value={draft[key]}
                disabled={!editable}
                onChange={(event) => set({ [key]: event.target.value } as Partial<Draft>)}
                placeholder="CA default"
                aria-describedby="lifetime-help"
                aria-invalid={invalid.includes(key)}
                className="font-mono text-[13px]"
              />
            </div>
          ))}
          <p id="lifetime-help" className="col-span-full text-[13px] text-muted-foreground">
            Go duration format, e.g. <Mono>5m</Mono>, <Mono>24h</Mono>, <Mono>720h</Mono>. Empty: the CA's default.
            {item.is_app_provisioner &&
              " This app signs in with a 24-hour certificate from it: keep the maximum at 24h or more."}
          </p>
          {invalid.length > 0 && (
            <p className="col-span-full text-[13px] text-danger-fg">Use a duration such as 24h, 90m or 1h30m.</p>
          )}
        </div>
      </SettingsSection>

      <SettingsSection
        title="Renewal and contents"
        description="What step-ca allows once a certificate is issued, and what goes in it."
      >
        <div className="divide-y divide-border-subtle rounded-xl border bg-card">
          <SwitchRow
            id="disable-renewal"
            label="Refuse renewals"
            checked={draft.disableRenewal}
            disabled={!editable}
            onChange={(value) => set({ disableRenewal: value })}
          />
          <SwitchRow
            id="renew-after-expiry"
            label="Allow renewing expired certificates"
            checked={draft.renewAfterExpiry}
            disabled={!editable}
            onChange={(value) => set({ renewAfterExpiry: value })}
          />
          {item.type === "ACME" && (
            <SwitchRow
              id="force-cn"
              label="Put a common name in each certificate"
              checked={draft.forceCn}
              disabled={!editable}
              onChange={(value) => set({ forceCn: value })}
            />
          )}
        </div>
      </SettingsSection>

      {item.type === "ACME" && (
        <SettingsSection
          title="External account binding"
          description="Only clients holding an EAB key can create an ACME account."
        >
          <div className="rounded-xl border bg-card">
            <SwitchRow
              id="require-eab"
              label="Require external account binding"
              checked={draft.requireEab}
              disabled={!editable}
              onChange={(value) => set({ requireEab: value })}
            />
            <p className="border-t border-border-subtle px-4 py-3 text-[13px] text-muted-foreground">
              Open-source step-ca can't create EAB keys (only Smallstep's Certificate Manager can): with this on, no
              ACME client can register.
            </p>
          </div>
        </SettingsSection>
      )}

      {editable && (
        <SettingsSection
          title="Danger zone"
          description="These actions affect every client using this provisioner."
          danger
          last
        >
          <div className="rounded-xl border border-danger-border bg-card">
            <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3.5">
              <div>
                <p className="font-medium">Delete provisioner</p>
                <p className="mt-0.5 text-[13px] text-muted-foreground">
                  {item.is_app_provisioner
                    ? "This app signs in to step-ca with it: it can't be deleted from here."
                    : `Existing certificates stay valid; ${item.type === "ACME" ? "renewals through ACME" : "new requests"} will fail.`}
                </p>
              </div>
              <Button variant="danger" size="md" disabled={item.is_app_provisioner} onClick={() => setDeleting(true)}>
                Delete…
              </Button>
            </div>
          </div>
        </SettingsSection>
      )}

      {count > 0 && (
        <div
          role="status"
          className="sticky bottom-4 z-10 mt-2 flex flex-wrap items-center justify-between gap-3 rounded-xl bg-inverse px-4 py-3 text-inverse-foreground shadow-[0_8px_24px_rgba(0,0,0,0.15)]"
        >
          <span>
            {count === 1 ? "1 unsaved change" : `${count} unsaved changes`}
            {save.error && <span className="ml-2 text-red-300">{errorMessage(save.error)}</span>}
          </span>
          <div className="flex gap-2">
            <Button
              variant="ghost"
              size="md"
              className="text-neutral-dot hover:bg-transparent hover:text-inverse-foreground"
              onClick={() => {
                setDraft(base)
                save.reset()
              }}
            >
              Discard
            </Button>
            <Button
              size="md"
              className="bg-card text-foreground hover:bg-card/90"
              disabled={save.isPending || invalid.length > 0}
              onClick={() =>
                save.mutate({
                  params: { path: { name: item.name } },
                  body: {
                    durations: {
                      min: draft.min.trim() || null,
                      default: draft.def.trim() || null,
                      max: draft.max.trim() || null,
                    },
                    disable_renewal: draft.disableRenewal,
                    allow_renewal_after_expiry: draft.renewAfterExpiry,
                    acme:
                      item.type === "ACME"
                        ? { challenges: draft.challenges, force_cn: draft.forceCn, require_eab: draft.requireEab }
                        : null,
                  },
                })
              }
            >
              {save.isPending ? "Saving…" : "Save changes"}
            </Button>
          </div>
        </div>
      )}
      {saved && count === 0 && (
        <p role="status" className="mt-2 text-[13px] text-success">
          Saved. Applied live and recorded in the audit log.
        </p>
      )}

      <AlertDialog open={deleting} onOpenChange={(open) => !open && (setDeleting(false), remove.reset())}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete {item.name}?</AlertDialogTitle>
            <AlertDialogDescription>
              Nobody can get a certificate from it any more. The certificates it issued stay valid until they expire.
            </AlertDialogDescription>
          </AlertDialogHeader>
          {remove.error && (
            <p role="alert" className="text-[13px] text-danger-fg">
              {errorMessage(remove.error)}
            </p>
          )}
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <Button
              variant="danger"
              disabled={remove.isPending}
              onClick={() => remove.mutate({ params: { path: { name: item.name } } })}
            >
              {remove.isPending ? "Deleting…" : "Delete provisioner"}
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

function SwitchRow({
  id,
  label,
  checked,
  disabled,
  onChange,
}: {
  id: string
  label: string
  checked: boolean
  disabled: boolean
  onChange: (value: boolean) => void
}) {
  return (
    <div className="flex items-center justify-between gap-3 px-4 py-3.5">
      <label id={`${id}-label`} htmlFor={id} className="font-medium">
        {label}
      </label>
      <Switch
        id={id}
        checked={checked}
        disabled={disabled}
        onCheckedChange={onChange}
        aria-labelledby={`${id}-label`}
      />
    </div>
  )
}

const certificates = columnHelper<CertificateItem>()

function Usage({ item }: { item: ProvisionerItem }) {
  const list = $api.useQuery("get", "/api/v1/certificates", {
    params: { query: { provisioner: [item.name], per_page: 10, sort: "not_before", order: "desc" } },
  })
  const columns = certificates.columns([
    certificates.accessor("common_name", {
      header: "Name",
      cell: ({ row }) => (
        <Link
          to="/certificates"
          search={{ cert: row.original.serial }}
          className="font-mono text-[13px] font-medium text-foreground"
        >
          {row.original.common_name ?? row.original.subject}
        </Link>
      ),
    }),
    certificates.accessor("status", {
      header: "Status",
      cell: ({ row }) => <CertificateStatus status={row.original.status} expiring={row.original.expiring} />,
    }),
    certificates.accessor("not_before", {
      header: "Issued",
      meta: { className: "text-muted-foreground" },
      cell: ({ getValue }) => fromNow(getValue()),
    }),
  ])
  return (
    <div className="flex max-w-[1040px] flex-col gap-4">
      <p className="text-muted-foreground">
        {formatNumber(item.issued_30d)} certificates in the last 30 days, {formatNumber(list.data?.total ?? 0)} in all.{" "}
        <Link to="/certificates" search={{ provisioner: [item.name] }}>
          See them in Certificates
        </Link>
      </p>
      <DataTable
        label="Latest certificates"
        columns={columns}
        rows={list.data?.items}
        rowId={(row) => row.serial}
        isPending={list.isPending}
        error={list.error}
        onRetry={() => list.refetch()}
        empty="It has issued no certificate yet."
      />
    </div>
  )
}

const audit = columnHelper<AuditItem>()

function Activity({ name }: { name: string }) {
  const can = useCan()
  const list = $api.useQuery(
    "get",
    "/api/v1/audit",
    { params: { query: { q: name, per_page: 25 } } },
    { enabled: can("admin") },
  )
  if (!can("admin")) return <p className="text-muted-foreground">The audit log is for admins.</p>
  const columns = audit.columns([
    audit.accessor("created_at", {
      header: "When",
      meta: { className: "whitespace-nowrap" },
      cell: ({ getValue }) => formatDateTime(getValue()),
    }),
    audit.accessor("user", {
      header: "Who",
      cell: ({ getValue }) => <span className="font-medium">{getValue()}</span>,
    }),
    audit.accessor("action", { header: "Action", cell: ({ getValue }) => getValue().replaceAll("_", " ") }),
    audit.accessor("success", {
      header: "Result",
      cell: ({ getValue }) => (getValue() ? "ok" : <span className="text-danger-fg">failed</span>),
    }),
    audit.accessor("detail", { header: "Detail", meta: { className: "text-[13px] text-muted-foreground" } }),
  ])
  return (
    <DataTable
      className="max-w-[1040px]"
      label="Changes to this provisioner"
      columns={columns}
      rows={list.data?.items}
      rowId={(row) => String(row.id)}
      isPending={list.isPending}
      error={list.error}
      onRetry={() => list.refetch()}
      empty="Nothing recorded for this provisioner."
    />
  )
}
