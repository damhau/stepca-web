import { Plus } from "lucide-react"
import { $api } from "@/api/client"
import { FilterChip } from "@/components/kit"
import { Checkbox } from "@/components/ui/checkbox"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { keyLabel } from "@/lib/format"

type Filters = { provisioner?: string[]; key?: string[] }

const KINDS = [
  { field: "provisioner", label: "Provisioner", chip: "Provisioner is" },
  { field: "key", label: "Key type", chip: "Key type is" },
] as const

/** The list's filter chips, and "+ Add filter" with the values the certificates have. */
export function FilterBar({ value, onChange }: { value: Filters; onChange: (value: Filters) => void }) {
  const facets = $api.useQuery("get", "/api/v1/certificates/facets", {}, { staleTime: 60_000 })
  const options = { provisioner: facets.data?.provisioners ?? [], key: facets.data?.keys ?? [] }
  const toggle = (field: keyof Filters, option: string, on: boolean) => {
    const current = value[field] ?? []
    const next = on ? [...current, option] : current.filter((item) => item !== option)
    onChange({ ...value, [field]: next.length ? next : undefined })
  }
  return (
    <>
      {KINDS.map(({ field, chip }) =>
        value[field]?.length ? (
          <FilterChip
            key={field}
            label={chip}
            value={value[field]!.map((option) => (field === "key" ? keyLabel(option) : option)).join(", ")}
            onRemove={() => onChange({ ...value, [field]: undefined })}
          />
        ) : null,
      )}
      <Popover>
        <PopoverTrigger asChild>
          <button
            type="button"
            className="inline-flex min-h-8 items-center gap-1 rounded-full border border-dashed border-separator px-2.5 text-[13px] text-fg-2 hover:border-muted-foreground hover:text-foreground"
          >
            <Plus className="size-3.5" aria-hidden /> Add filter
          </button>
        </PopoverTrigger>
        <PopoverContent align="start" className="w-64 p-0">
          {KINDS.map(({ field, label }) => (
            <fieldset key={field} className="border-b border-border-subtle px-3 py-2.5 last:border-0">
              <legend className="mb-1.5 text-xs font-medium text-muted-foreground">{label}</legend>
              {options[field].length === 0 ? (
                <p className="text-[13px] text-muted-foreground">None yet.</p>
              ) : (
                <ul className="flex max-h-44 flex-col gap-0.5 overflow-y-auto">
                  {options[field].map((option) => {
                    const id = `filter-${field}-${option}`
                    return (
                      <li key={option}>
                        <label
                          htmlFor={id}
                          className="flex min-h-8 cursor-pointer items-center gap-2 rounded-md px-1 text-[13px] hover:bg-accent"
                        >
                          <Checkbox
                            id={id}
                            checked={value[field]?.includes(option) ?? false}
                            onCheckedChange={(on) => toggle(field, option, on === true)}
                          />
                          <span className={field === "provisioner" ? "font-mono" : undefined}>
                            {field === "key" ? keyLabel(option) : option}
                          </span>
                        </label>
                      </li>
                    )
                  })}
                </ul>
              )}
            </fieldset>
          ))}
        </PopoverContent>
      </Popover>
    </>
  )
}
