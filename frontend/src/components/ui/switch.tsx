import * as React from "react"
import { Switch as SwitchPrimitive } from "radix-ui"
import { cn } from "@/lib/utils"

// 40 × 24, the accent colour when on
function Switch({ className, ...props }: React.ComponentProps<typeof SwitchPrimitive.Root>) {
  return (
    <SwitchPrimitive.Root
      data-slot="switch"
      className={cn(
        "peer relative inline-flex h-6 w-10 shrink-0 items-center rounded-full bg-separator transition-colors outline-none focus-visible:ring-[3px] focus-visible:ring-ring/40 disabled:cursor-not-allowed disabled:opacity-50 data-[state=checked]:bg-brand",
        className,
      )}
      {...props}
    >
      <SwitchPrimitive.Thumb
        data-slot="switch-thumb"
        className="pointer-events-none block size-[18px] translate-x-[3px] rounded-full bg-white shadow-sm transition-transform data-[state=checked]:translate-x-[19px]"
      />
    </SwitchPrimitive.Root>
  )
}

export { Switch }
