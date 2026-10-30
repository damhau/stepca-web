import { createFileRoute } from "@tanstack/react-router"
import { Info, Play, RotateCw, Square } from "lucide-react"
import { useState } from "react"
import { $api, errorMessage } from "@/api/client"
import { useSession } from "@/api/session"
import { AdminOnly } from "@/components/admin-only"
import { PageHeader } from "@/components/kit"
import { Section } from "@/components/page"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Button } from "@/components/ui/button"

export const Route = createFileRoute("/_app/service")({
  component: () => (
    <AdminOnly>
      <Service />
    </AdminOnly>
  ),
})

type Action = "start" | "stop" | "restart" | "status"

const CONFIRM: Partial<Record<Action, string>> = {
  stop: "Nobody can get or renew a certificate until it is started again.",
  restart: "Requests to step-ca fail for the few seconds it takes to restart.",
}

function Service() {
  const session = useSession()
  const [confirming, setConfirming] = useState<Action | null>(null)
  const run = $api.useMutation("post", "/api/v1/service")
  if (!session.service_control) {
    return (
      <>
        <PageHeader title="Service" />
        <p className="text-sm text-muted-foreground">
          Service control is off: set SERVICE_CONTROL_ENABLED=true where step-ca runs as a systemd service.
        </p>
      </>
    )
  }
  const act = (action: Action) => (CONFIRM[action] ? setConfirming(action) : run.mutate({ body: { action } }))
  const output = run.data?.output ?? run.data?.error ?? (run.error ? errorMessage(run.error) : null)
  return (
    <>
      <PageHeader
        title="Service"
        description="The step-ca systemd unit on this machine, through the service control script."
      />
      <div className="mb-4 flex flex-wrap gap-2">
        <Button variant="outline" onClick={() => act("status")} disabled={run.isPending}>
          <Info /> Status
        </Button>
        <Button variant="outline" onClick={() => act("start")} disabled={run.isPending}>
          <Play /> Start
        </Button>
        <Button variant="outline" onClick={() => act("restart")} disabled={run.isPending}>
          <RotateCw /> Restart
        </Button>
        <Button variant="destructive" onClick={() => act("stop")} disabled={run.isPending}>
          <Square /> Stop
        </Button>
      </div>
      {output && (
        <Section title={run.data?.success ? "Output" : "It failed"}>
          <pre aria-live="polite" className="overflow-auto p-4 font-mono text-xs whitespace-pre-wrap">
            {output}
          </pre>
        </Section>
      )}
      <AlertDialog open={confirming !== null} onOpenChange={(open) => !open && setConfirming(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="capitalize">{confirming} step-ca?</AlertDialogTitle>
            <AlertDialogDescription>{confirming && CONFIRM[confirming]}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (confirming) run.mutate({ body: { action: confirming } })
                setConfirming(null)
              }}
            >
              <span className="capitalize">{confirming}</span>
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
