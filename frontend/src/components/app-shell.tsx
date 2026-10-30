import { useQuery } from "@tanstack/react-query"
import { Link, useRouter } from "@tanstack/react-router"
import {
  BookOpen,
  FileText,
  House,
  KeyRound,
  ListChecks,
  LogOut,
  Menu,
  Network,
  Search,
  ShieldCheck,
  type LucideIcon,
} from "lucide-react"
import { useEffect, useState } from "react"
import { $api, errorMessage } from "@/api/client"
import { roleAtLeast, useSession, useSignOut } from "@/api/session"
import type { Role } from "@/api/types"
import { CommandPalette } from "@/components/command-palette"
import { Pill } from "@/components/kit"
import { ThemeItems } from "@/components/theme"
import { toast } from "@/components/toaster"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Sheet, SheetContent, SheetDescription, SheetTitle, SheetTrigger } from "@/components/ui/sheet"
import { IssueProvider } from "@/features/issue/issue-context"
import { cn } from "@/lib/utils"

type Item = {
  to: string
  label: string
  icon?: LucideIcon
  role?: Role
  exact?: boolean
  badge?: "expiring"
  feature?: "service_control"
}

const MAIN: Item[] = [
  { to: "/", label: "Overview", icon: House, exact: true },
  { to: "/certificates", label: "Certificates", icon: FileText, badge: "expiring" },
  { to: "/provisioners", label: "Provisioners", icon: KeyRound },
  { to: "/acme", label: "ACME", icon: Network },
  { to: "/audit", label: "Audit log", icon: ListChecks, role: "admin" },
]

const SETTINGS: Item[] = [
  { to: "/ca", label: "Authority" },
  { to: "/admins", label: "Admins" },
  { to: "/service", label: "Service", role: "admin", feature: "service_control" },
]

const LINK =
  "flex items-center gap-2.5 rounded-md px-2.5 text-fg-2 no-underline transition-colors hover:bg-nav-active/70 hover:text-foreground data-[status=active]:bg-nav-active data-[status=active]:font-medium data-[status=active]:text-foreground"

function Navigation({ onNavigate }: { onNavigate?: () => void }) {
  const session = useSession()
  const counts = $api.useQuery("get", "/api/v1/certificates/counts", {}, { staleTime: 60_000 })
  const visible = (item: Item) =>
    (!item.role || roleAtLeast(session.role, item.role)) && (!item.feature || session[item.feature])
  return (
    <nav aria-label="Primary" className="flex flex-col gap-[18px] px-2.5 py-4">
      <div className="flex flex-col gap-px">
        {MAIN.filter(visible).map((item) => (
          <Link
            key={item.to}
            to={item.to}
            onClick={onNavigate}
            activeOptions={{ exact: item.exact, includeSearch: false }}
            className={cn(LINK, "min-h-9")}
          >
            {item.icon && <item.icon className="size-4 shrink-0" strokeWidth={1.8} aria-hidden />}
            {item.label}
            {item.badge === "expiring" && !!counts.data?.expiring && (
              <Pill tone="warning" className="ml-auto text-[11px]">
                <span className="sr-only">expiring: </span>
                {counts.data.expiring}
              </Pill>
            )}
          </Link>
        ))}
      </div>
      <div className="flex flex-col gap-px">
        <p className="mb-1 px-2.5 text-xs text-muted-foreground">Settings</p>
        {SETTINGS.filter(visible).map((item) => (
          <Link
            key={item.to}
            to={item.to}
            onClick={onNavigate}
            activeOptions={{ includeSearch: false }}
            className={cn(LINK, "min-h-[34px]")}
          >
            {item.label}
          </Link>
        ))}
      </div>
    </nav>
  )
}

function initials(user: string | null) {
  const parts = (user ?? "?").split(/[\s._@-]+/).filter(Boolean)
  return ((parts[0]?.[0] ?? "?") + (parts[1]?.[0] ?? "")).toUpperCase()
}

function AccountMenu() {
  const session = useSession()
  const signOut = useSignOut()
  const router = useRouter()
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          aria-label={`Signed in as ${session.user}`}
          className="grid size-8 place-items-center rounded-full bg-inverse text-xs font-semibold text-inverse-foreground outline-none focus-visible:ring-[3px] focus-visible:ring-ring/40"
        >
          {initials(session.user)}
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-56">
        <DropdownMenuLabel className="font-normal">
          <span className="block truncate font-medium">{session.user}</span>
          <span className="text-xs text-muted-foreground capitalize">{session.role}</span>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <ThemeItems />
        <DropdownMenuSeparator />
        <DropdownMenuItem
          onSelect={() =>
            signOut.mutate(
              {},
              {
                onSuccess: () => router.navigate({ to: "/login", search: {} }),
                onError: (error) => toast.error(errorMessage(error)),
              },
            )
          }
        >
          <LogOut /> Sign out
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

function Authority() {
  const { authority } = useSession()
  const production = authority.environment?.toLowerCase().startsWith("prod")
  return (
    <Link
      to="/ca"
      className="inline-flex min-h-9 items-center gap-2 rounded-md px-2 font-medium text-foreground no-underline hover:bg-accent hover:text-foreground"
      title={authority.url}
    >
      <span className="max-w-56 truncate">{authority.name}</span>
      {authority.environment && (
        <span
          className={cn(
            "rounded-sm px-1.5 py-px text-[11px] font-medium",
            production ? "bg-success-bg text-success-fg" : "bg-warning-badge-bg text-warning-badge-fg",
          )}
        >
          {authority.environment}
        </span>
      )}
    </Link>
  )
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const [menu, setMenu] = useState(false)
  const [palette, setPalette] = useState(false)
  // Warm the counts used by the sidebar badge and the certificate tabs
  useQuery({ ...$api.queryOptions("get", "/api/v1/certificates/counts"), staleTime: 60_000 })
  useEffect(() => {
    const open = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement
      const typing = target.closest("input, textarea, select, [contenteditable]")
      if ((event.key === "k" && (event.metaKey || event.ctrlKey)) || (event.key === "/" && !typing)) {
        event.preventDefault()
        setPalette(true)
      }
    }
    document.addEventListener("keydown", open)
    return () => document.removeEventListener("keydown", open)
  }, [])
  const mac = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform)
  return (
    <IssueProvider>
      <div className="flex min-h-svh flex-col">
        <header className="sticky top-0 z-30 flex min-h-14 flex-wrap items-center justify-between gap-x-4 gap-y-2 border-b bg-card px-4">
          <div className="flex min-w-0 items-center gap-2.5">
            <Sheet open={menu} onOpenChange={setMenu}>
              <SheetTrigger asChild>
                <Button variant="ghost" size="icon-sm" className="lg:hidden" aria-label="Menu">
                  <Menu />
                </Button>
              </SheetTrigger>
              <SheetContent side="left" className="w-64 gap-0 bg-sidebar p-0">
                <SheetTitle className="sr-only">Menu</SheetTitle>
                <SheetDescription className="sr-only">The app's pages</SheetDescription>
                <Navigation onNavigate={() => setMenu(false)} />
              </SheetContent>
            </Sheet>
            <Link
              to="/"
              aria-label="Overview"
              className="grid size-7 shrink-0 place-items-center rounded-[7px] bg-inverse"
            >
              <ShieldCheck className="size-3.5 text-inverse-foreground" strokeWidth={2.5} aria-hidden />
            </Link>
            <span aria-hidden className="text-xl text-separator">
              /
            </span>
            <Authority />
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setPalette(true)}
              className="inline-flex min-h-9 items-center gap-2.5 rounded-lg border bg-sidebar pr-2 pl-3 text-muted-foreground hover:text-foreground sm:min-w-[220px]"
            >
              <Search className="size-3.5" aria-hidden />
              <span className="hidden sm:inline">Search or run a command</span>
              <span className="sr-only sm:hidden">Search</span>
              <kbd className="ml-auto hidden rounded border bg-card px-1.5 font-mono text-[11px] sm:inline">
                {mac ? "⌘K" : "Ctrl K"}
              </kbd>
            </button>
            <a
              href="https://smallstep.com/docs/step-ca"
              target="_blank"
              rel="noreferrer"
              className="hidden min-h-9 items-center gap-1.5 px-2.5 font-medium text-fg-2 no-underline hover:text-foreground sm:inline-flex"
            >
              <BookOpen className="size-3.5" aria-hidden /> Docs
            </a>
            <AccountMenu />
          </div>
        </header>
        <div className="flex flex-1">
          <aside className="hidden w-[220px] shrink-0 border-r bg-sidebar lg:block">
            <div className="sticky top-14">
              <Navigation />
            </div>
          </aside>
          <main className="flex min-w-0 flex-1 flex-col gap-5 px-[clamp(16px,3vw,40px)] pt-7 pb-14">{children}</main>
        </div>
      </div>
      <CommandPalette open={palette} onOpenChange={setPalette} />
    </IssueProvider>
  )
}
