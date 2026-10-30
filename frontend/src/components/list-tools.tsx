import { Search } from "lucide-react"
import { useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"

/** A list's text filter: updates the URL a moment after typing stops. */
export function SearchBox({
  value,
  onChange,
  placeholder,
  id,
}: {
  value: string
  onChange: (value: string) => void
  placeholder: string
  id: string
}) {
  const [draft, setDraft] = useState(value)
  const [synced, setSynced] = useState(value)
  if (value !== synced) {
    setSynced(value)
    setDraft(value)
  }
  useEffect(() => {
    if (draft === value) return
    const timer = setTimeout(() => onChange(draft), 300)
    return () => clearTimeout(timer)
  }, [draft, value, onChange])
  return (
    <div className="relative w-full flex-[0_1_260px]">
      <Search
        className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground"
        aria-hidden
      />
      <label htmlFor={id} className="sr-only">
        {placeholder}
      </label>
      <Input
        id={id}
        type="search"
        value={draft}
        onChange={(event) => setDraft(event.target.value)}
        placeholder={placeholder}
        className="pl-8"
      />
    </div>
  )
}

/** A link to a list's CSV export: every row that matches the filters. */
export function ExportButton({
  path,
  query,
}: {
  path: string
  query: Record<string, string | number | boolean | null | undefined>
}) {
  const params = new URLSearchParams({ format: "csv" })
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== null && value !== "" && key !== "page" && key !== "per_page")
      params.set(key, String(value))
  }
  return (
    <Button variant="outline" asChild>
      <a href={`${path}?${params}`} download className="text-foreground no-underline hover:text-foreground">
        Export
      </a>
    </Button>
  )
}

export function ChoiceFilter({
  value,
  options,
  onChange,
  label,
  any,
}: {
  value?: string
  options: readonly string[]
  onChange: (value?: string) => void
  label: string
  any: string
}) {
  return (
    <Select value={value ?? "*"} onValueChange={(next) => onChange(next === "*" ? undefined : next)}>
      <SelectTrigger className="h-8 w-auto min-w-36 rounded-full text-[13px]" aria-label={label}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="*">{any}</SelectItem>
        {options.map((option) => (
          <SelectItem key={option} value={option}>
            {option}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}

export function Toolbar({ children }: { children: React.ReactNode }) {
  return <div className="-mt-1 flex flex-wrap items-center gap-2">{children}</div>
}
