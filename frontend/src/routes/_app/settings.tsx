import { createFileRoute } from "@tanstack/react-router"
import { AlertTriangle } from "lucide-react"
import { $api } from "@/api/client"
import { AdminOnly } from "@/components/admin-only"
import { ErrorState, Fields, LoadingBlock, PageHeader, Section } from "@/components/page"

export const Route = createFileRoute("/_app/settings")({
  component: () => (
    <AdminOnly>
      <Settings />
    </AdminOnly>
  ),
})

function Settings() {
  const { data, error, refetch } = $api.useQuery("get", "/api/v1/settings")
  return (
    <>
      <PageHeader
        title="Settings"
        description="The configuration in effect, from the environment and settings.json. Passwords and keys are never shown. Change them where the app is deployed, then restart it."
      />
      {error ? (
        <ErrorState error={error} onRetry={() => refetch()} />
      ) : !data ? (
        <LoadingBlock lines={8} />
      ) : (
        <div className="flex flex-col gap-6">
          {data.warnings.map((warning) => (
            <p
              key={warning}
              role="alert"
              className="flex gap-2 rounded-lg border border-expiring/40 bg-expiring-soft/50 px-4 py-3 text-sm"
            >
              <AlertTriangle className="mt-0.5 size-4 shrink-0 text-expiring" aria-hidden />
              {warning}
            </p>
          ))}
          <div className="grid gap-6 xl:grid-cols-2">
            {data.sections.map((section) => (
              <Section key={section.title} title={section.title}>
                <Fields rows={section.items.map((item) => [item.label, item.value])} />
              </Section>
            ))}
          </div>
        </div>
      )}
    </>
  )
}
