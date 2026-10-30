import { useQueryClient } from "@tanstack/react-query"
import { createFileRoute } from "@tanstack/react-router"
import { MoreHorizontal, Plus, Trash2, UserCog } from "lucide-react"
import { useState } from "react"
import { $api, errorMessage } from "@/api/client"
import { useCan } from "@/api/session"
import type { AdminItem } from "@/api/types"
import { Identifier } from "@/components/copy-button"
import { columnHelper, DataTable } from "@/components/data-table"
import { Callout, PageHeader, Pill } from "@/components/kit"
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
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { formatDateTime } from "@/lib/format"

export const Route = createFileRoute("/_app/admins")({ component: Admins })

type AdminType = "ADMIN" | "SUPER_ADMIN"
const TYPE_LABELS: Record<string, string> = { ADMIN: "Admin", SUPER_ADMIN: "Super admin" }
const helper = columnHelper<AdminItem>()

function Admins() {
  const can = useCan()
  const queryClient = useQueryClient()
  const list = $api.useQuery("get", "/api/v1/admins")
  const manage = can("admin") && !!list.data?.manageable
  const [creating, setCreating] = useState(false)
  const [changing, setChanging] = useState<AdminItem | null>(null)
  const [deleting, setDeleting] = useState<AdminItem | null>(null)
  const done = ({ message }: { message: string }) => {
    toast.success(message)
    queryClient.invalidateQueries({ queryKey: ["get", "/api/v1/admins"] })
  }

  const columns = helper.columns([
    helper.accessor("subject", {
      header: "Subject",
      cell: ({ getValue }) => <span className="font-medium">{getValue() || "—"}</span>,
    }),
    helper.accessor("provisioner_name", {
      header: "Provisioner",
      cell: ({ row }) => row.original.provisioner_name ?? row.original.provisioner_id,
    }),
    helper.accessor("type", {
      header: "Type",
      cell: ({ getValue }) => (
        <Pill tone={getValue() === "SUPER_ADMIN" ? "brand" : "neutral"}>{TYPE_LABELS[getValue()] ?? getValue()}</Pill>
      ),
    }),
    helper.accessor("created_at", {
      header: "Added",
      meta: { className: "whitespace-nowrap text-muted-foreground" },
      cell: ({ getValue }) => formatDateTime(getValue()),
    }),
    helper.accessor("id", {
      header: "Id",
      meta: { className: "max-w-48" },
      cell: ({ getValue }) => <Identifier value={getValue()} label="admin id" truncate />,
    }),
    ...(manage
      ? [
          helper.display({
            id: "actions",
            header: () => <span className="sr-only">Actions</span>,
            meta: { className: "w-10" },
            cell: ({ row }) => (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" size="icon-sm" aria-label={`Actions for ${row.original.subject}`}>
                    <MoreHorizontal />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem onSelect={() => setChanging(row.original)}>
                    <UserCog /> Change type
                  </DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem variant="destructive" onSelect={() => setDeleting(row.original)}>
                    <Trash2 /> Delete…
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            ),
          }),
        ]
      : []),
  ])

  return (
    <>
      <PageHeader
        title="Admins"
        description="Who may change step-ca's configuration through its Admin API: provisioners, admins, policies."
        actions={
          manage && (
            <Button onClick={() => setCreating(true)}>
              <Plus strokeWidth={2.2} /> Add admin
            </Button>
          )
        }
      />
      {can("admin") && list.data && !list.data.manageable && (
        <Callout tone="brand">
          This app's identity on the CA is {list.data.identity_type ? `an ${list.data.identity_type}` : "unknown"}, not
          a SUPER_ADMIN, so admins are read-only here. Manage them with <span className="font-mono">step ca admin</span>
          .
        </Callout>
      )}
      <DataTable
        label="Admins"
        columns={columns}
        rows={list.data?.admins}
        rowId={(row) => row.id}
        isPending={list.isPending}
        error={list.error}
        onRetry={() => list.refetch()}
        empty="step-ca returned no admin."
      />
      {list.data && (
        <CreateAdmin
          open={creating}
          provisioners={list.data.provisioners.map((p) => p.name)}
          onClose={() => setCreating(false)}
          onDone={done}
        />
      )}
      <ChangeType admin={changing} onClose={() => setChanging(null)} onDone={done} />
      <DeleteAdmin admin={deleting} onClose={() => setDeleting(null)} onDone={done} />
    </>
  )
}

function TypeSelect({ id, value, onChange }: { id: string; value: AdminType; onChange: (value: AdminType) => void }) {
  return (
    <Select value={value} onValueChange={(next) => onChange(next as AdminType)}>
      <SelectTrigger id={id} className="w-full">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="ADMIN">Admin: provisioners and policies</SelectItem>
        <SelectItem value="SUPER_ADMIN">Super admin: also the admins</SelectItem>
      </SelectContent>
    </Select>
  )
}

function CreateAdmin({
  open,
  provisioners,
  onClose,
  onDone,
}: {
  open: boolean
  provisioners: string[]
  onClose: () => void
  onDone: (r: { message: string }) => void
}) {
  const [subject, setSubject] = useState("")
  const [provisioner, setProvisioner] = useState(provisioners[0] ?? "")
  const [type, setType] = useState<AdminType>("ADMIN")
  const create = $api.useMutation("post", "/api/v1/admins", {
    onSuccess: (result) => {
      onDone(result)
      setSubject("")
      onClose()
    },
  })
  return (
    <Dialog open={open} onOpenChange={(next) => !next && (onClose(), create.reset())}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add an admin</DialogTitle>
          <DialogDescription>
            They sign in to step-ca with a certificate for this subject from this provisioner.
          </DialogDescription>
        </DialogHeader>
        <form
          id="create-admin"
          className="flex flex-col gap-4"
          onSubmit={(event) => {
            event.preventDefault()
            create.mutate({ body: { subject: subject.trim(), provisioner, type } })
          }}
        >
          <div className="flex flex-col gap-2">
            <Label htmlFor="admin-subject">Subject</Label>
            <Input
              id="admin-subject"
              value={subject}
              onChange={(event) => setSubject(event.target.value)}
              placeholder="alice@example.org"
              required
            />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="admin-provisioner">Provisioner</Label>
            <Select value={provisioner} onValueChange={setProvisioner}>
              <SelectTrigger id="admin-provisioner" className="w-full">
                <SelectValue placeholder="Choose" />
              </SelectTrigger>
              <SelectContent>
                {provisioners.map((name) => (
                  <SelectItem key={name} value={name}>
                    {name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="admin-type">Type</Label>
            <TypeSelect id="admin-type" value={type} onChange={setType} />
          </div>
          {create.error && (
            <p role="alert" className="text-[13px] text-danger-fg">
              {errorMessage(create.error)}
            </p>
          )}
        </form>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" form="create-admin" disabled={create.isPending || !subject.trim() || !provisioner}>
            {create.isPending ? "Adding…" : "Add admin"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function ChangeType({
  admin,
  onClose,
  onDone,
}: {
  admin: AdminItem | null
  onClose: () => void
  onDone: (r: { message: string }) => void
}) {
  const [type, setType] = useState<AdminType>("ADMIN")
  const update = $api.useMutation("patch", "/api/v1/admins/{id}", {
    onSuccess: (result) => {
      onDone(result)
      onClose()
    },
  })
  return (
    <Dialog
      open={admin !== null}
      onOpenChange={(next) => {
        if (next && admin) setType(admin.type as AdminType)
        if (!next) {
          onClose()
          update.reset()
        }
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Change {admin?.subject}'s type</DialogTitle>
          <DialogDescription>
            step-ca only lets an admin's type change; the subject and provisioner stay.
          </DialogDescription>
        </DialogHeader>
        <TypeSelect id="change-type" value={type} onChange={setType} />
        {update.error && (
          <p role="alert" className="text-[13px] text-danger-fg">
            {errorMessage(update.error)}
          </p>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            disabled={update.isPending}
            onClick={() => admin && update.mutate({ params: { path: { id: admin.id } }, body: { type } })}
          >
            {update.isPending ? "Saving…" : "Save type"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function DeleteAdmin({
  admin,
  onClose,
  onDone,
}: {
  admin: AdminItem | null
  onClose: () => void
  onDone: (r: { message: string }) => void
}) {
  const remove = $api.useMutation("delete", "/api/v1/admins/{id}", {
    onSuccess: (result) => {
      onDone(result)
      onClose()
    },
  })
  return (
    <AlertDialog open={admin !== null} onOpenChange={(next) => !next && (onClose(), remove.reset())}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Delete the admin {admin?.subject}?</AlertDialogTitle>
          <AlertDialogDescription>They can no longer change step-ca's configuration.</AlertDialogDescription>
        </AlertDialogHeader>
        {remove.error && (
          <p role="alert" className="text-[13px] text-danger-fg">
            {errorMessage(remove.error)}
          </p>
        )}
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <Button
            variant="destructive"
            disabled={remove.isPending}
            onClick={() => admin && remove.mutate({ params: { path: { id: admin.id } } })}
          >
            {remove.isPending ? "Deleting…" : "Delete admin"}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
