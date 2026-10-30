import { useQueryClient } from "@tanstack/react-query"
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router"
import { Plus } from "lucide-react"
import { useState } from "react"
import { $api, errorMessage } from "@/api/client"
import { useCan } from "@/api/session"
import type { ProvisionerItem } from "@/api/types"
import { columnHelper, DataTable } from "@/components/data-table"
import { Mono, PageHeader, Pill } from "@/components/kit"
import { toast } from "@/components/toaster"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { formatDate, formatNumber, shortDuration } from "@/lib/format"
import { cn } from "@/lib/utils"

export const Route = createFileRoute("/_app/provisioners/")({ component: Provisioners })

const CHALLENGE_NAMES: Record<string, string> = { HTTP_01: "http-01", DNS_01: "dns-01", TLS_ALPN_01: "tls-alpn-01" }
const GO_DURATION = /^(\d+(\.\d+)?(ns|us|µs|ms|s|m|h))+$/

const helper = columnHelper<ProvisionerItem>()

function lifetime(item: ProvisionerItem) {
  const { default: standard, max } = item.durations
  if (!standard && !max) return <span className="text-muted-foreground">CA defaults</span>
  return (
    <span>
      {standard ? <Mono>{shortDuration(standard)}</Mono> : <span className="text-muted-foreground">CA default</span>}
      <span className="text-muted-foreground"> · max </span>
      {max ? <Mono>{shortDuration(max)}</Mono> : <span className="text-muted-foreground">CA default</span>}
    </span>
  )
}

function Provisioners() {
  const can = useCan()
  const list = $api.useQuery("get", "/api/v1/provisioners")
  const [creating, setCreating] = useState(false)
  const columns = helper.columns([
    helper.accessor("name", {
      header: "Name",
      cell: ({ row }) => (
        <span className="flex items-center gap-2">
          <Link
            to="/provisioners/$name"
            params={{ name: row.original.name }}
            className="font-mono text-[13px] font-medium text-foreground hover:underline"
          >
            {row.original.name}
          </Link>
          {row.original.is_app_provisioner && <Pill tone="brand">this app's</Pill>}
        </span>
      ),
    }),
    helper.accessor("type", { header: "Type", meta: { className: "text-fg-2" } }),
    helper.accessor("durations", {
      header: "Lifetime",
      meta: { className: "whitespace-nowrap" },
      cell: ({ row }) => lifetime(row.original),
    }),
    helper.accessor("acme", {
      header: "Challenges",
      meta: { className: "text-fg-2" },
      cell: ({ getValue }) => {
        const acme = getValue()
        if (!acme) return <span className="text-muted-foreground">—</span>
        return (
          <Mono>
            {acme.challenges?.length
              ? acme.challenges.map((challenge) => CHALLENGE_NAMES[challenge] ?? challenge).join(", ")
              : "all"}
          </Mono>
        )
      },
    }),
    helper.accessor("issued_30d", {
      header: "Issued in 30 days",
      meta: { className: "tabular-nums" },
      cell: ({ getValue }) => formatNumber(getValue()),
    }),
    helper.accessor("created_at", {
      header: "Created",
      meta: { className: "pr-4 text-muted-foreground whitespace-nowrap" },
      cell: ({ getValue }) => formatDate(getValue()),
    }),
  ])
  return (
    <>
      <PageHeader
        title="Provisioners"
        description="How step-ca decides who gets a certificate: a password-protected key (JWK) or an ACME client proving it controls a name."
        actions={
          can("admin") && (
            <Button onClick={() => setCreating(true)}>
              <Plus strokeWidth={2.2} /> Add provisioner
            </Button>
          )
        }
      />
      <DataTable
        label="Provisioners"
        columns={columns}
        rows={list.data?.provisioners}
        rowId={(row) => row.name}
        isPending={list.isPending}
        error={list.error}
        onRetry={() => list.refetch()}
        empty="step-ca has no provisioner."
      />
      <CreateProvisioner open={creating} onClose={() => setCreating(false)} />
    </>
  )
}

function CreateProvisioner({ open, onClose }: { open: boolean; onClose: () => void }) {
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const [type, setType] = useState<"ACME" | "JWK">("ACME")
  const [name, setName] = useState("")
  const [password, setPassword] = useState("")
  const [durations, setDurations] = useState({ default: "", max: "" })
  const [challenges, setChallenges] = useState<("HTTP_01" | "DNS_01" | "TLS_ALPN_01")[]>([])
  const create = $api.useMutation("post", "/api/v1/provisioners", {
    onSuccess: ({ message }) => {
      toast.success(message)
      queryClient.invalidateQueries()
      const created = name.trim()
      close()
      navigate({ to: "/provisioners/$name", params: { name: created } })
    },
  })
  const invalid = Object.values(durations).some((value) => value && !GO_DURATION.test(value.trim()))
  const ready = name.trim() && !invalid && (type === "ACME" || password.length >= 8)
  function close() {
    setName("")
    setPassword("")
    setDurations({ default: "", max: "" })
    setChallenges([])
    create.reset()
    onClose()
  }
  return (
    <Dialog open={open} onOpenChange={(next) => !next && close()}>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>Add provisioner</DialogTitle>
          <DialogDescription>Its name and type can't be changed afterwards.</DialogDescription>
        </DialogHeader>
        <form
          id="create-provisioner"
          className="flex flex-col gap-4"
          onSubmit={(event) => {
            event.preventDefault()
            if (!ready) return
            create.mutate({
              body: {
                name: name.trim(),
                type,
                password: type === "JWK" ? password : null,
                durations: { default: durations.default.trim() || null, min: null, max: durations.max.trim() || null },
                acme: type === "ACME" ? { challenges, require_eab: false, force_cn: false } : null,
              },
            })
          }}
        >
          <fieldset>
            <legend className="mb-2 text-[13px] font-medium">Type</legend>
            <div className="grid gap-2.5 sm:grid-cols-2">
              {(
                [
                  ["ACME", "ACME", "cert-manager, certbot, Caddy… prove they control a name"],
                  ["JWK", "JWK", "Operators sign with the provisioner's password"],
                ] as const
              ).map(([value, title, sub]) => (
                <label
                  key={value}
                  className={cn(
                    "flex cursor-pointer items-start gap-2.5 rounded-xl border px-3.5 py-3",
                    type === value ? "border-brand bg-brand-soft" : "bg-card",
                  )}
                >
                  <input
                    type="radio"
                    name="type"
                    checked={type === value}
                    onChange={() => setType(value)}
                    className="mt-0.5 size-4 accent-brand"
                  />
                  <span>
                    <span className="block font-medium">{title}</span>
                    <span className="mt-0.5 block text-[13px] text-muted-foreground">{sub}</span>
                  </span>
                </label>
              ))}
            </div>
          </fieldset>
          <div className="flex flex-col gap-1.5">
            <label htmlFor="provisioner-name" className="text-[13px] font-medium">
              Name
            </label>
            <Input
              id="provisioner-name"
              value={name}
              onChange={(event) => setName(event.target.value)}
              className="font-mono text-[13px]"
              autoFocus
            />
          </div>
          {type === "JWK" && (
            <div className="flex flex-col gap-1.5">
              <label htmlFor="provisioner-password" className="text-[13px] font-medium">
                Password
              </label>
              <Input
                id="provisioner-password"
                type="password"
                autoComplete="new-password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
              />
              <p className="text-[13px] text-muted-foreground">
                At least 8 characters. It encrypts the provisioner's key: whoever signs with it needs it.
              </p>
            </div>
          )}
          <div className="grid gap-3 sm:grid-cols-2">
            {(
              [
                ["default", "Default lifetime", "24h"],
                ["max", "Maximum lifetime", "720h"],
              ] as const
            ).map(([key, label, example]) => (
              <div key={key} className="flex flex-col gap-1.5">
                <label htmlFor={`new-${key}`} className="text-[13px] font-medium">
                  {label}
                </label>
                <Input
                  id={`new-${key}`}
                  value={durations[key]}
                  onChange={(event) => setDurations({ ...durations, [key]: event.target.value })}
                  placeholder={`CA default (e.g. ${example})`}
                  aria-invalid={!!durations[key] && !GO_DURATION.test(durations[key].trim())}
                  className="font-mono text-[13px]"
                />
              </div>
            ))}
          </div>
          {type === "ACME" && (
            <fieldset>
              <legend className="mb-2 text-[13px] font-medium">Challenges</legend>
              <div className="flex flex-wrap gap-x-5 gap-y-2">
                {(["HTTP_01", "DNS_01", "TLS_ALPN_01"] as const).map((challenge) => (
                  <label key={challenge} className="flex cursor-pointer items-center gap-2 font-mono text-[13px]">
                    <input
                      type="checkbox"
                      checked={challenges.includes(challenge)}
                      onChange={(event) =>
                        setChallenges(
                          event.target.checked
                            ? [...challenges, challenge]
                            : challenges.filter((item) => item !== challenge),
                        )
                      }
                      className="size-4 accent-brand"
                    />
                    {CHALLENGE_NAMES[challenge]}
                  </label>
                ))}
              </div>
              <p className="mt-1.5 text-[13px] text-muted-foreground">None ticked: step-ca allows all three.</p>
            </fieldset>
          )}
          {create.error && (
            <p role="alert" className="rounded-lg bg-danger-bg px-3 py-2.5 text-[13px] text-danger-fg">
              {errorMessage(create.error)}
            </p>
          )}
        </form>
        <DialogFooter>
          <Button variant="outline" onClick={close}>
            Cancel
          </Button>
          <Button type="submit" form="create-provisioner" disabled={!ready || create.isPending}>
            {create.isPending ? "Adding…" : "Add provisioner"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
