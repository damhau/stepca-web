import { Download, Search } from "lucide-react"
import { useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"

/** The text filter of a list: updates the URL a moment after typing stops. */
export function FilterInput({
  value,
  onChange,
  placeholder,
}: {
  value: string
  onChange: (value: string) => void
  placeholder: string
}) {
  const [text, setText] = useState(value)
  // The URL changed some other way (back, a link): show its filter
  const [synced, setSynced] = useState(value)
  if (value !== synced) {
    setSynced(value)
    setText(value)
  }
  useEffect(() => {
    if (text === value) return
    const timer = setTimeout(() => onChange(text), 300)
    return () => clearTimeout(timer)
  }, [text, value, onChange])
  return (
    <div className="relative w-full sm:w-72">
      <Search
        className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground"
        aria-hidden
      />
      <Input
        type="search"
        value={text}
        onChange={(event) => setText(event.target.value)}
        placeholder={placeholder}
        aria-label={placeholder}
        className="pl-8"
      />
    </div>
  )
}

/** A link to the list's CSV export: every row that matches the filters, not only this page. */
export function ExportLink({
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
    <Button variant="outline" size="sm" asChild>
      <a href={`${path}?${params}`} download>
        <Download /> Export CSV
      </a>
    </Button>
  )
}

export function Toolbar({ children }: { children: React.ReactNode }) {
  return <div className="mb-3 flex flex-wrap items-center gap-2">{children}</div>
}
