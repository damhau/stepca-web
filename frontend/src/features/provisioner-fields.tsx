import { useWatch, type FieldValues, type Path, type PathValue, type UseFormReturn } from "react-hook-form"
import { z } from "zod"
import { $api } from "@/api/client"
import { Checkbox } from "@/components/ui/checkbox"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

const GO_DURATION = /^(\d+(\.\d+)?(ns|us|µs|ms|s|m|h))+$/
const duration = z
  .string()
  .trim()
  .refine((value) => value === "" || GO_DURATION.test(value), "A duration such as 24h, 90m or 1h30m")

export const durationsSchema = z.object({ default: duration, min: duration, max: duration })
export const acmeSchema = z.object({
  challenges: z.array(z.enum(["HTTP_01", "DNS_01", "TLS_ALPN_01"])),
  require_eab: z.boolean(),
  force_cn: z.boolean(),
})

export type DurationValues = z.infer<typeof durationsSchema>
export type AcmeValues = z.infer<typeof acmeSchema>

/** Empty durations are left out: the CA's defaults apply. */
export function durationsBody(values: DurationValues) {
  return { default: values.default || null, min: values.min || null, max: values.max || null }
}

/** A form with the provisioner fields: durations, and acme for an ACME provisioner. */
type Values<T extends FieldValues> = T & { durations: DurationValues; acme: AcmeValues }
type ProvisionerForm<T extends FieldValues> = UseFormReturn<Values<T>>

function path<T extends FieldValues>(name: string) {
  return name as Path<Values<T>>
}

export function DurationFields<T extends FieldValues>({ form }: { form: ProvisionerForm<T> }) {
  const errors = form.formState.errors.durations as Record<string, { message?: string }> | undefined
  const fields = [
    ["default", "Default", "24h"],
    ["min", "Minimum", "5m"],
    ["max", "Maximum", "720h"],
  ] as const
  return (
    <fieldset className="flex flex-col gap-2">
      <legend className="mb-2 text-sm font-medium">Certificate durations</legend>
      <div className="grid gap-3 sm:grid-cols-3">
        {fields.map(([key, label, example]) => (
          <div key={key} className="flex flex-col gap-1.5">
            <Label htmlFor={`duration-${key}`} className="text-xs font-normal text-muted-foreground">
              {label}
            </Label>
            <Input
              id={`duration-${key}`}
              placeholder={`e.g. ${example}`}
              aria-invalid={!!errors?.[key]}
              {...form.register(path<T>(`durations.${key}`))}
            />
            {errors?.[key] && <p className="text-xs text-revoked">{errors[key].message}</p>}
          </div>
        ))}
      </div>
      <p className="text-sm text-muted-foreground">Go durations such as 24h, 90m or 1h30m. Empty: the CA's defaults.</p>
    </fieldset>
  )
}

export function CheckboxField({
  id,
  label,
  checked,
  onChange,
  hint,
}: {
  id: string
  label: string
  checked: boolean
  onChange: (checked: boolean) => void
  hint?: React.ReactNode
}) {
  return (
    <div className="flex items-start gap-2.5">
      <Checkbox id={id} checked={checked} onCheckedChange={(value) => onChange(value === true)} className="mt-0.5" />
      <div className="flex flex-col gap-0.5">
        <Label htmlFor={id} className="font-normal">
          {label}
        </Label>
        {hint && <p className="text-sm text-muted-foreground">{hint}</p>}
      </div>
    </div>
  )
}

export function AcmeFields<T extends FieldValues>({ form }: { form: ProvisionerForm<T> }) {
  const reference = $api.useQuery("get", "/api/v1/reference", {}, { staleTime: Infinity })
  const values = useWatch({ control: form.control }) as unknown as { acme?: Partial<AcmeValues> }
  const challenges: string[] = values.acme?.challenges ?? []
  const set = (name: string, value: unknown) =>
    form.setValue(path<T>(name), value as PathValue<Values<T>, Path<Values<T>>>, { shouldDirty: true })
  return (
    <fieldset className="flex flex-col gap-3">
      <legend className="mb-1 text-sm font-medium">ACME</legend>
      <div className="flex flex-wrap gap-x-6 gap-y-2">
        {reference.data?.acme_challenges.map((challenge) => (
          <CheckboxField
            key={challenge.value}
            id={`challenge-${challenge.value}`}
            label={challenge.label}
            checked={challenges.includes(challenge.value)}
            onChange={(checked) =>
              set(
                "acme.challenges",
                checked ? [...challenges, challenge.value] : challenges.filter((value) => value !== challenge.value),
              )
            }
          />
        ))}
      </div>
      <p className="text-sm text-muted-foreground">None ticked: step-ca allows http-01, dns-01 and tls-alpn-01.</p>
      <CheckboxField
        id="force-cn"
        label="Put a common name in each certificate"
        checked={!!values.acme?.force_cn}
        onChange={(checked) => set("acme.force_cn", checked)}
      />
      <CheckboxField
        id="require-eab"
        label="Require External Account Binding (EAB)"
        checked={!!values.acme?.require_eab}
        onChange={(checked) => set("acme.require_eab", checked)}
        hint="Open-source step-ca can't create EAB keys (only Smallstep's Certificate Manager can): no ACME client could register."
      />
    </fieldset>
  )
}
