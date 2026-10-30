import { useEffect, useState } from "react"
import { DropdownMenuLabel, DropdownMenuRadioGroup, DropdownMenuRadioItem } from "@/components/ui/dropdown-menu"

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

/** Light, dark, or the system's, in the account menu; public/theme.js applies it before the first paint. */
export function ThemeItems() {
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
  return (
    <>
      <DropdownMenuLabel className="text-xs font-normal text-muted-foreground">Theme</DropdownMenuLabel>
      <DropdownMenuRadioGroup value={theme} onValueChange={(value) => setTheme(value as Theme)}>
        <DropdownMenuRadioItem value="light" onSelect={(event) => event.preventDefault()}>
          Light
        </DropdownMenuRadioItem>
        <DropdownMenuRadioItem value="dark" onSelect={(event) => event.preventDefault()}>
          Dark
        </DropdownMenuRadioItem>
        <DropdownMenuRadioItem value="system" onSelect={(event) => event.preventDefault()}>
          System
        </DropdownMenuRadioItem>
      </DropdownMenuRadioGroup>
    </>
  )
}
