import { zodResolver } from "@hookform/resolvers/zod"
import { useQueryClient } from "@tanstack/react-query"
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router"
import { ChevronLeft, Info } from "lucide-react"
import { useEffect } from "react"
import { useForm, useWatch } from "react-hook-form"
import { z } from "zod"
import { $api, errorMessage } from "@/api/client"
import { useCan } from "@/api/session"
import { Identifier } from "@/components/copy-button"
import { ErrorState, LoadingBlock, PageHeader } from "@/components/page"
import { toast } from "@/components/toaster"
import { Button } from "@/components/ui/button"
import {
  AcmeFields,
  acmeSchema,
  CheckboxField,
  DurationFields,
  durationsBody,
  durationsSchema,
} from "@/features/provisioner-fields"
import { formatDateTime } from "@/lib/format"

export const Route = createFileRoute("/_app/provisioners/$name")({ component: EditProvisioner })

const schema = z.object({
  disable_renewal: z.boolean(),
  allow_renewal_after_expiry: z.boolean(),
  durations: durationsSchema,
  acme: acmeSchema,
})

type Values = z.infer<typeof schema>

function EditProvisioner() {
  const { name } = Route.useParams()
  const can = useCan()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { data, error, refetch } = $api.useQuery("get", "/api/v1/provisioners/{name}", { params: { path: { name } } })
  const form = useForm<Values>({ resolver: zodResolver(schema) })
  useEffect(() => {
    if (!data) return
    form.reset({
      disable_renewal: data.disable_renewal,
      allow_renewal_after_expiry: data.allow_renewal_after_expiry,
      durations: {
        default: data.durations.default ?? "",
        min: data.durations.min ?? "",
        max: data.durations.max ?? "",
      },
      acme: data.acme ?? { challenges: [], require_eab: false, force_cn: false },
    })
  }, [data, form])
  const values = useWatch({ control: form.control })
  const save = $api.useMutation("put", "/api/v1/provisioners/{name}", {
    onSuccess: () => {
      toast.success(`Provisioner ${name} saved.`)
      queryClient.invalidateQueries()
      navigate({ to: "/provisioners" })
    },
  })
  const back = (
    <Link
      to="/provisioners"
      className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
    >
      <ChevronLeft className="size-4" aria-hidden /> Provisioners
    </Link>
  )
  if (error)
    return (
      <>
        {back}
        <ErrorState error={error} onRetry={() => refetch()} />
      </>
    )
  if (!data || !form.formState.defaultValues) return <LoadingBlock lines={6} />
  return (
    <>
      {back}
      <PageHeader
        title={data.name}
        description={
          <>
            {data.type} provisioner{data.created_at && `, created ${formatDateTime(data.created_at)}`}. Its name and
            type can't be changed.
          </>
        }
      />
      <form
        noValidate
        className="flex max-w-3xl flex-col gap-6 rounded-lg border bg-card p-5"
        onSubmit={form.handleSubmit((values) =>
          save.mutate({
            params: { path: { name } },
            body: {
              ...values,
              durations: durationsBody(values.durations),
              acme: data.type === "ACME" ? values.acme : null,
            },
          }),
        )}
      >
        {data.id && (
          <p className="flex items-center gap-2 text-sm text-muted-foreground">
            Id <Identifier value={data.id} label="provisioner id" />
          </p>
        )}
        {data.is_app_provisioner && (
          <p className="flex gap-2 rounded-md bg-accent px-3 py-2 text-sm text-accent-foreground">
            <Info className="mt-0.5 size-4 shrink-0" aria-hidden />
            This app signs in to step-ca with a 24-hour certificate from this provisioner: its maximum duration must
            stay at least 24 hours.
          </p>
        )}
        <DurationFields form={form} />
        <div className="flex flex-col gap-3">
          <CheckboxField
            id="disable-renewal"
            label="Refuse renewals"
            checked={!!values.disable_renewal}
            onChange={(checked) => form.setValue("disable_renewal", checked, { shouldDirty: true })}
          />
          <CheckboxField
            id="renew-after-expiry"
            label="Allow renewing expired certificates"
            checked={!!values.allow_renewal_after_expiry}
            onChange={(checked) => form.setValue("allow_renewal_after_expiry", checked, { shouldDirty: true })}
          />
        </div>
        {data.type === "ACME" && <AcmeFields form={form} />}
        {save.error && (
          <p role="alert" className="rounded-md bg-revoked-soft px-3 py-2 text-sm text-revoked">
            {errorMessage(save.error)}
          </p>
        )}
        <div className="flex gap-2">
          <Button type="submit" disabled={!can("admin") || save.isPending || !form.formState.isDirty}>
            {save.isPending ? "Saving…" : "Save changes"}
          </Button>
          <Button variant="outline" asChild>
            <Link to="/provisioners">Cancel</Link>
          </Button>
        </div>
      </form>
    </>
  )
}
