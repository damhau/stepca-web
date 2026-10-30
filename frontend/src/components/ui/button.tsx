import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { Slot } from "radix-ui"
import { cn } from "@/lib/utils"

// Primary is black, secondary white with a border; destructive is a red outline, "danger" solid red (danger zones)
const buttonVariants = cva(
  "inline-flex shrink-0 items-center justify-center gap-1.5 rounded-lg font-medium whitespace-nowrap transition-colors outline-none focus-visible:ring-[3px] focus-visible:ring-ring/40 disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-3.5",
  {
    variants: {
      variant: {
        default: "bg-primary text-primary-foreground hover:bg-primary/85",
        outline: "border border-border bg-card text-foreground hover:bg-accent",
        destructive: "border border-danger-border bg-card text-danger-fg hover:bg-danger-bg",
        danger: "bg-danger text-white hover:bg-danger/90",
        ghost: "text-fg-2 hover:bg-accent hover:text-foreground",
        link: "text-brand underline-offset-4 hover:text-brand-hover hover:underline",
        inverse: "bg-inverse-2 text-inverse-foreground hover:bg-inverse-2/80",
      },
      size: {
        default: "h-9 px-3.5 text-sm",
        sm: "h-8 px-2.5 text-[13px]",
        md: "h-[34px] px-3 text-[13px]",
        xs: "h-6 rounded-md px-2 text-xs",
        icon: "size-9",
        "icon-sm": "size-8 rounded-md",
        "icon-xs": "size-6 rounded-md",
      },
    },
    defaultVariants: { variant: "default", size: "default" },
  },
)

function Button({
  className,
  variant = "default",
  size = "default",
  asChild = false,
  ...props
}: React.ComponentProps<"button"> & VariantProps<typeof buttonVariants> & { asChild?: boolean }) {
  const Comp = asChild ? Slot.Root : "button"
  return (
    <Comp
      data-slot="button"
      data-variant={variant}
      data-size={size}
      className={cn(buttonVariants({ variant, size, className }))}
      {...props}
    />
  )
}

export { Button, buttonVariants }
