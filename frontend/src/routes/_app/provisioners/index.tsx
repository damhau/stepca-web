import { zodResolver } from "@hookform/resolvers/zod"
import { useQueryClient } from "@tanstack/react-query"
import { createFileRoute, Link } from "@tanstack/react-router"
import { Braces, MoreHorizontal, Pencil, Plus, Trash2 } from "lucide-react"
import { useState } from "react"
import { useForm, useWatch } from "react-hook-form"
import { z } from "zod"
import { $api, errorMessage } from "@/api/client"
import { useCan } from "@/api/session"
import type { ProvisionerItem } from "@/api/types"
import { columnHelper, DataTable } from "@/components/data-table"
import { PageHeader } from "@/components/page"
import { Pill } from "@/components/status"
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { AcmeFields, acmeSchema, DurationFields, durationsBody, durationsSchema } from "@/features/provisioner-fields"

export const Route = createFileRoute("/_app/provisioners/")({ component: Provisioners })

const helper = columnHelper<ProvisionerItem>()

const CHALLENGE_LABELS: Record<string, string> = { HTTP_01: "http-01", DNS_01: "dns-01", TLS_ALPN_01: "tls-alpn-01" }

function Provisioners() {
  const can = useCan()
  const list = $api.useQuery("get", "/api/v1/provisioners")
  const [viewing, setViewing] = useState<ProvisionerItem | null>(null)
  const [deleting, setDeleting] = useState<ProvisionerItem | null>(null)
  const [creating, setCreating] = useState(false)

  const columns = helper.columns([
    helper.accessor("name", {
      header: "Name",
      cell: ({ row }) => (
        <span className="flex flex-wrap items-center gap-2 font-medium">
          {row.original.name}
          {row.original.is_app_provisioner && <Pill tone="pending">this app's</Pill>}
        </span>
      ),
    }),
    helper.accessor("type", { header: "Type" }),
    helper.accessor("durations", {
      header: "Durations",
      cell: ({ row }) => {
        const { default: standard, min, max } = row.original.durations
        if (!standard && !min && !max) return <span className="text-muted-foreground">CA defaults</span>
        return (
          <span className="text-sm">
            {standard ?? "default"}
            <span className="text-muted-foreground">
              {" "}
              ({min ?? "…"} to {max ?? "…"})
            </span>
          </span>
        )
      },
    }),
    helper.accessor("acme", {
      header: "ACME challenges",
      cell: ({ getValue }) => {
        const acme = getValue()
        if (!acme) return <span className="text-muted-foreground">—</span>
        return acme.challenges?.length
          ? acme.challenges.map((challenge) => CHALLENGE_LABELS[challenge] ?? challenge).join(", ")
          : "all three"
      },
    }),
    helper.display({
      id: "actions",
      header: () => <span className="sr-only">Actions</span>,
      meta: { className: "w-10" },
      cell: ({ row }) => (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon-sm" aria-label={`Actions for ${row.original.name}`}>
              <MoreHorizontal />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem onSelect={() => setViewing(row.original)}>
              <Braces /> Show as step-ca returns it
            </DropdownMenuItem>
            {can("admin") && (
              <>
                <DropdownMenuItem asChild>
                  <Link to="/provisioners/$name" params={{ name: row.original.name }}>
                    <Pencil /> Edit
                  </Link>
                </DropdownMenuItem>
                {!row.original.is_app_provisioner && (
                  <>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem variant="destructive" onSelect={() => setDeleting(row.original)}>
                      <Trash2 /> Delete…
                    </DropdownMenuItem>
                  </>
                )}
              </>
            )}
          </DropdownMenuContent>
        </DropdownMenu>
      ),
    }),
  ])

  return (
    <>
      <PageHeader
        title="Provisioners"
        description="How step-ca decides who gets a certificate: a password-protected key (JWK) or an ACME client proving it controls a name."
        actions={
          can("admin") && (
            <Button size="sm" onClick={() => setCreating(true)}>
              <Plus /> Add a provisioner
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
      <Dialog open={viewing !== null} onOpenChange={(open) => !open && setViewing(null)}>
        <DialogContent className="sm:max-w-3xl">
          <DialogHeader>
            <DialogTitle>{viewing?.name}</DialogTitle>
            <DialogDescription>As step-ca's Admin API returns it.</DialogDescription>
          </DialogHeader>
          <pre className="max-h-[60vh] overflow-auto rounded-md bg-muted p-4 font-mono text-xs">
            {JSON.stringify(viewing?.raw, null, 2)}
          </pre>
        </DialogContent>
      </Dialog>
      <DeleteProvisioner provisioner={deleting} onClose={() => setDeleting(null)} />
      <CreateProvisioner open={creating} onClose={() => setCreating(false)} />
    </>
  )
}

function DeleteProvisioner({ provisioner, onClose }: { provisioner: ProvisionerItem | null; onClose: () => void }) {
  const queryClient = useQueryClient()
  const remove = $api.useMutation("delete", "/api/v1/provisioners/{name}", {
    onSuccess: ({ message }) => {
      toast.success(message)
      queryClient.invalidateQueries()
      onClose()
    },
  })
  return (
    <AlertDialog
      open={provisioner !== null}
      onOpenChange={(open) => {
        if (!open) {
          onClose()
          remove.reset()
        }
      }}
    >
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Delete {provisioner?.name}?</AlertDialogTitle>
          <AlertDialogDescription>
            Nobody can get a certificate from it any more. The certificates it issued stay valid until they expire.
          </AlertDialogDescription>
        </AlertDialogHeader>
        {remove.error && (
          <p role="alert" className="text-sm text-revoked">
            {errorMessage(remove.error)}
          </p>
        )}
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <Button
            variant="destructive"
            disabled={remove.isPending}
            onClick={() => provisioner && remove.mutate({ params: { path: { name: provisioner.name } } })}
          >
            {remove.isPending ? "Deleting…" : "Delete provisioner"}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}

const createSchema = z
  .object({
    name: z.string().trim().min(1, "Give it a name"),
    type: z.enum(["ACME", "JWK"]),
    password: z.string(),
    durations: durationsSchema,
    acme: acmeSchema,
  })
  .refine((values) => values.type !== "JWK" || values.password.length >= 8, {
    path: ["password"],
    message: "At least 8 characters: it encrypts the provisioner's key",
  })

type CreateValues = z.infer<typeof createSchema>

function CreateProvisioner({ open, onClose }: { open: boolean; onClose: () => void }) {
  const queryClient = useQueryClient()
  const form = useForm<CreateValues>({
    resolver: zodResolver(createSchema),
    defaultValues: {
      name: "",
      type: "ACME",
      password: "",
      durations: { default: "", min: "", max: "" },
      acme: { challenges: [], require_eab: false, force_cn: false },
    },
  })
  const type = useWatch({ control: form.control, name: "type" })
  const { errors } = form.formState
  const create = $api.useMutation("post", "/api/v1/provisioners", {
    onSuccess: ({ message }) => {
      toast.success(message)
      queryClient.invalidateQueries()
      form.reset()
      onClose()
    },
  })
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) {
          onClose()
          create.reset()
        }
      }}
    >
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>Add a provisioner</DialogTitle>
          <DialogDescription>Its name and type can't be changed afterwards.</DialogDescription>
        </DialogHeader>
        <form
          id="create-provisioner"
          noValidate
          className="flex flex-col gap-5"
          onSubmit={form.handleSubmit((values) =>
            create.mutate({
              body: {
                name: values.name,
                type: values.type,
                password: values.type === "JWK" ? values.password : null,
                durations: durationsBody(values.durations),
                acme: values.type === "ACME" ? values.acme : null,
              },
            }),
          )}
        >
          <Tabs value={type} onValueChange={(value) => form.setValue("type", value as CreateValues["type"])}>
            <TabsList className="w-full">
              <TabsTrigger value="ACME">ACME</TabsTrigger>
              <TabsTrigger value="JWK">JWK (password)</TabsTrigger>
            </TabsList>
          </Tabs>
          <div className="flex flex-col gap-2">
            <Label htmlFor="provisioner-name">Name</Label>
            <Input id="provisioner-name" aria-invalid={!!errors.name} {...form.register("name")} />
            {errors.name && <p className="text-sm text-revoked">{errors.name.message}</p>}
          </div>
          {type === "JWK" && (
            <div className="flex flex-col gap-2">
              <Label htmlFor="provisioner-password">Password</Label>
              <Input
                id="provisioner-password"
                type="password"
                autoComplete="new-password"
                aria-invalid={!!errors.password}
                {...form.register("password")}
              />
              <p className="text-sm text-muted-foreground">
                Encrypts its key: whoever signs with it needs this password.
              </p>
              {errors.password && <p className="text-sm text-revoked">{errors.password.message}</p>}
            </div>
          )}
          <DurationFields form={form} />
          {type === "ACME" && <AcmeFields form={form} />}
          {create.error && (
            <p role="alert" className="rounded-md bg-revoked-soft px-3 py-2 text-sm text-revoked">
              {errorMessage(create.error)}
            </p>
          )}
        </form>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" form="create-provisioner" disabled={create.isPending}>
            {create.isPending ? "Adding…" : "Add provisioner"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
