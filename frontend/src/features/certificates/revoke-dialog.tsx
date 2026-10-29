import { useQueryClient } from "@tanstack/react-query"
import { useState } from "react"
import { $api, errorMessage } from "@/api/client"
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

type Target = { serial: string; name: string }

/** Revokes a certificate passively: step-ca stops vouching for it (CRL, renewals), it can't be undone. */
export function RevokeDialog({ target, onClose }: { target: Target | null; onClose: () => void }) {
  const queryClient = useQueryClient()
  const reference = $api.useQuery("get", "/api/v1/reference", {}, { staleTime: Infinity })
  const [reason, setReason] = useState("0")
  const revoke = $api.useMutation("post", "/api/v1/certificates/{serial}/revoke", {
    onSuccess: () => {
      toast.success(`Certificate ${target?.name} revoked.`)
      queryClient.invalidateQueries()
      onClose()
    },
  })
  return (
    <AlertDialog
      open={target !== null}
      onOpenChange={(open) => {
        if (!open) {
          onClose()
          revoke.reset()
          setReason("0")
        }
      }}
    >
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Revoke {target?.name}?</AlertDialogTitle>
          <AlertDialogDescription>
            step-ca will list it on its revocation list and refuse to renew it. This can't be undone.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <div className="flex flex-col gap-2">
          <Label htmlFor="revoke-reason">Reason</Label>
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
        {revoke.error && (
          <p role="alert" className="text-sm text-revoked">
            {errorMessage(revoke.error)}
          </p>
        )}
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <Button
            variant="destructive"
            disabled={revoke.isPending || !target}
            onClick={() =>
              target &&
              revoke.mutate({ params: { path: { serial: target.serial } }, body: { reason_code: Number(reason) } })
            }
          >
            {revoke.isPending ? "Revoking…" : "Revoke certificate"}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
