import { Monitor, Moon, Sun } from "lucide-react"
import { useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"

type Theme = "light" | "dark" | "system"

function stored(): Theme {
  try {
    const value = localStorage.getItem("theme")
    return value === "light" || value === "dark" ? value : "system"
  } catch {
    return "system"
  }
}

const systemDark = window.matchMedia("(prefers-color-scheme: dark)")

function apply(theme: Theme) {
  document.documentElement.classList.toggle("dark", theme === "system" ? systemDark.matches : theme === "dark")
}

/** Light, dark, or the system's; public/theme.js applies it before the first paint. */
export function ThemeMenu() {
  const [theme, setTheme] = useState<Theme>(stored)
  useEffect(() => {
    apply(theme)
    try {
      if (theme === "system") localStorage.removeItem("theme")
      else localStorage.setItem("theme", theme)
    } catch {
      // The choice then lasts for this page only
    }
    if (theme !== "system") return
    const follow = () => apply("system")
    systemDark.addEventListener("change", follow)
    return () => systemDark.removeEventListener("change", follow)
  }, [theme])
  const Icon = theme === "light" ? Sun : theme === "dark" ? Moon : Monitor
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon-sm" aria-label="Theme">
          <Icon />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuRadioGroup value={theme} onValueChange={(value) => setTheme(value as Theme)}>
          <DropdownMenuRadioItem value="light">Light</DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="dark">Dark</DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="system">System</DropdownMenuRadioItem>
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
