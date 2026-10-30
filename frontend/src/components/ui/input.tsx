import * as React from "react"
import { cn } from "@/lib/utils"

function Input({ className, type, ...props }: React.ComponentProps<"input">) {
  return (
    <input
      type={type}
      data-slot="input"
      className={cn(
        "h-9 w-full min-w-0 rounded-lg border border-input bg-card px-2.5 text-sm text-foreground transition-[color,box-shadow] outline-none placeholder:text-muted-foreground read-only:bg-sidebar focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/25 disabled:cursor-not-allowed disabled:opacity-50 aria-invalid:border-danger aria-invalid:ring-danger/20",
        className,
      )}
      {...props}
    />
  )
}

export { Input }
