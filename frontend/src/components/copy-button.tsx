import { Check, Copy } from "lucide-react"
import { useState } from "react"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

export function CopyButton({ value, label, className }: { value: string; label: string; className?: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <Button
      type="button"
      variant="ghost"
      size="icon-xs"
      className={cn("text-muted-foreground", className)}
      aria-label={copied ? "Copied" : `Copy ${label}`}
      title={copied ? "Copied" : `Copy ${label}`}
      onClick={async () => {
        await navigator.clipboard.writeText(value)
        setCopied(true)
        setTimeout(() => setCopied(false), 1500)
      }}
    >
      {copied ? <Check className="text-valid" /> : <Copy />}
    </Button>
  )
}

/** An identifier (serial, fingerprint, id) in the monospace face, with a copy button. */
export function Identifier({ value, label, truncate = false }: { value: string; label: string; truncate?: boolean }) {
  return (
    <span className="inline-flex max-w-full items-center gap-1">
      <code
        className={cn("font-mono text-[0.8125rem]", truncate ? "truncate" : "break-all")}
        title={truncate ? value : undefined}
      >
        {value}
      </code>
      <CopyButton value={value} label={label} />
    </span>
  )
}
