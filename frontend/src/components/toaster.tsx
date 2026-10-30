import { CircleAlert, CircleCheck, X } from "lucide-react"
import { useSyncExternalStore } from "react"
import { cn } from "@/lib/utils"

// A small toaster of our own: toast libraries inject <style> elements, which the CSP refuses
type Toast = { id: number; tone: "success" | "error"; message: string }

let toasts: Toast[] = []
let nextId = 1
const listeners = new Set<() => void>()

function publish(next: Toast[]) {
  toasts = next
  listeners.forEach((listener) => listener())
}

function dismiss(id: number) {
  publish(toasts.filter((item) => item.id !== id))
}

function show(tone: Toast["tone"], message: string) {
  const id = nextId++
  publish([...toasts.slice(-3), { id, tone, message }])
  // Errors stay until dismissed: they usually say what to fix
  if (tone === "success") setTimeout(() => dismiss(id), 5000)
}

export const toast = {
  success: (message: string) => show("success", message),
  error: (message: string) => show("error", message),
}

function subscribe(listener: () => void) {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

export function Toaster() {
  const items = useSyncExternalStore(subscribe, () => toasts)
  return (
    <div
      aria-live="polite"
      className="pointer-events-none fixed right-4 bottom-4 z-[60] flex w-[min(26rem,calc(100vw-2rem))] flex-col gap-2"
    >
      {items.map((item) => (
        <div
          key={item.id}
          role={item.tone === "error" ? "alert" : "status"}
          className={cn(
            "pointer-events-auto flex animate-in items-start gap-3 rounded-lg border bg-popover p-3 text-sm shadow-lg fade-in-0 slide-in-from-bottom-2",
            item.tone === "error" ? "border-danger-border" : "border-border",
          )}
        >
          {item.tone === "error" ? (
            <CircleAlert className="mt-0.5 size-4 shrink-0 text-danger-fg" aria-hidden />
          ) : (
            <CircleCheck className="mt-0.5 size-4 shrink-0 text-success" aria-hidden />
          )}
          <p className="min-w-0 flex-1 break-words">{item.message}</p>
          <button
            type="button"
            onClick={() => dismiss(item.id)}
            className="rounded text-muted-foreground hover:text-foreground"
            aria-label="Dismiss"
          >
            <X className="size-4" />
          </button>
        </div>
      ))}
    </div>
  )
}
