import { useQueryClient } from "@tanstack/react-query"
import { useState } from "react"
import { $api, errorMessage, fetchClient } from "@/api/client"
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
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { plural } from "@/lib/format"

export type RevokeTarget = { serial: string; name: string }

/** Revokes certificates passively: step-ca stops vouching for them (CRL, renewals). It can't be undone. */
export function RevokeDialog({
  targets,
  onClose,
  onDone,
}: {
  targets: RevokeTarget[]
  onClose: () => void
  onDone?: () => void
}) {
  const queryClient = useQueryClient()
  const reference = $api.useQuery("get", "/api/v1/reference", {}, { staleTime: Infinity })
  const [reason, setReason] = useState("0")
  const [busy, setBusy] = useState(false)
  const [failures, setFailures] = useState<string[]>([])
  const one = targets.length === 1 ? targets[0] : undefined

  async function revoke() {
    setBusy(true)
    const failed: string[] = []
    for (const target of targets) {
      const { error } = await fetchClient.POST("/api/v1/certificates/{serial}/revoke", {
        params: { path: { serial: target.serial } },
        body: { reason_code: Number(reason) },
      })
      if (error) failed.push(`${target.name}: ${errorMessage(error)}`)
    }
    setBusy(false)
    await queryClient.invalidateQueries()
    const revoked = targets.length - failed.length
    if (revoked)
      toast.success(one && !failed.length ? `${one.name} revoked.` : `${plural(revoked, "certificate")} revoked.`)
    if (failed.length) {
      setFailures(failed)
      return
    }
    onDone?.()
    close()
  }

  function close() {
    setFailures([])
    setReason("0")
    onClose()
  }

  return (
    <AlertDialog open={targets.length > 0} onOpenChange={(open) => !open && !busy && close()}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>
            {one ? `Revoke ${one.name}?` : `Revoke ${plural(targets.length, "certificate")}?`}
          </AlertDialogTitle>
          <AlertDialogDescription>
            step-ca lists {one ? "it" : "them"} on its revocation list and refuses to renew {one ? "it" : "them"}. This
            can't be undone.
          </AlertDialogDescription>
        </AlertDialogHeader>
        {!one && targets.length > 0 && (
          <ul className="max-h-32 overflow-y-auto rounded-lg border bg-sidebar px-3 py-2 font-mono text-xs">
            {targets.map((target) => (
              <li key={target.serial} className="truncate">
                {target.name}
              </li>
            ))}
          </ul>
        )}
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="revoke-reason" className="text-[13px]">
            Reason
          </Label>
          <Select value={reason} onValueChange={setReason}>
            <SelectTrigger id="revoke-reason" className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {reference.data?.revocation_reasons.map((item) => (
                <SelectItem key={item.code} value={String(item.code)}>
                  {item.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        {failures.length > 0 && (
          <ul role="alert" className="rounded-lg bg-danger-bg px-3 py-2 text-[13px] text-danger-fg">
            {failures.map((failure) => (
              <li key={failure}>{failure}</li>
            ))}
          </ul>
        )}
        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>{failures.length ? "Close" : "Cancel"}</AlertDialogCancel>
          {!failures.length && (
            <Button variant="danger" disabled={busy || !targets.length} onClick={revoke}>
              {busy ? "Revoking…" : one ? "Revoke certificate" : `Revoke ${plural(targets.length, "certificate")}`}
            </Button>
          )}
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
