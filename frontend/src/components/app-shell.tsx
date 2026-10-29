import { Link, useNavigate, useRouter, useRouterState } from "@tanstack/react-router"
import {
  Activity,
  BadgeCheck,
  ClipboardList,
  FileBadge,
  KeyRound,
  LayoutDashboard,
  ListChecks,
  LogOut,
  Menu,
  Power,
  Puzzle,
  Search,
  Settings,
  ShieldCheck,
  ShoppingCart,
  UserCog,
  Users,
  type LucideIcon,
} from "lucide-react"
import { useEffect, useRef, useState, useSyncExternalStore } from "react"
import { errorMessage } from "@/api/client"
import { roleAtLeast, useSession, useSignOut } from "@/api/session"
import type { Role } from "@/api/types"
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
import { Input } from "@/components/ui/input"
import { Sheet, SheetContent, SheetDescription, SheetTitle, SheetTrigger } from "@/components/ui/sheet"
import { cn } from "@/lib/utils"
import { ThemeMenu } from "./theme"

type Item = { to: string; label: string; icon: LucideIcon; role?: Role; exact?: boolean; feature?: "service_control" }

const NAVIGATION: { title: string; items: Item[] }[] = [
  {
    title: "Overview",
    items: [
      { to: "/", label: "Dashboard", icon: LayoutDashboard, exact: true },
      { to: "/certificates", label: "Certificates", icon: FileBadge },
    ],
  },
  {
    title: "ACME",
    items: [
      { to: "/acme/accounts", label: "Accounts", icon: Users },
      { to: "/acme/orders", label: "Orders", icon: ShoppingCart },
      { to: "/acme/authorizations", label: "Authorizations", icon: ListChecks },
      { to: "/acme/challenges", label: "Challenges", icon: Puzzle },
      { to: "/acme/certificates", label: "ACME certificates", icon: BadgeCheck },
    ],
  },
  {
    title: "Authority",
    items: [
      { to: "/ca", label: "CA status", icon: Activity },
      { to: "/provisioners", label: "Provisioners", icon: KeyRound },
      { to: "/admins", label: "Admins", icon: UserCog },
      { to: "/service", label: "Service", icon: Power, role: "admin", feature: "service_control" },
    ],
  },
  {
    title: "System",
    items: [
      { to: "/settings", label: "Settings", icon: Settings, role: "admin" },
      { to: "/audit", label: "Audit log", icon: ClipboardList, role: "admin" },
    ],
  },
]

function Navigation({ onNavigate }: { onNavigate?: () => void }) {
  const session = useSession()
  return (
    <nav aria-label="Main" className="flex flex-col gap-5 px-3 py-4">
      {NAVIGATION.map((group) => {
        const items = group.items.filter(
          (item) => (!item.role || roleAtLeast(session.role, item.role)) && (!item.feature || session[item.feature]),
        )
        if (items.length === 0) return null
        return (
          <div key={group.title}>
            <h2 className="px-2 pb-1.5 text-xs font-medium text-muted-foreground">{group.title}</h2>
            <ul className="flex flex-col gap-0.5">
              {items.map((item) => (
                <li key={item.to}>
                  <Link
                    to={item.to}
                    onClick={onNavigate}
                    activeOptions={{ exact: item.exact, includeSearch: false }}
                    className="flex items-center gap-2.5 rounded-md px-2 py-1.5 text-sm text-sidebar-foreground/85 transition-colors hover:bg-sidebar-accent/60 hover:text-sidebar-foreground data-[status=active]:bg-sidebar-accent data-[status=active]:font-medium data-[status=active]:text-sidebar-accent-foreground"
                  >
                    <item.icon className="size-4 shrink-0" aria-hidden />
                    {item.label}
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        )
      })}
    </nav>
  )
}

function Brand() {
  return (
    <Link to="/" className="flex items-center gap-2.5 px-5 py-4">
      <span className="grid size-7 place-items-center rounded-md bg-primary text-primary-foreground">
        <ShieldCheck className="size-4" aria-hidden />
      </span>
      <span className="font-semibold tracking-tight">Step CA</span>
    </Link>
  )
}

const WIDE = window.matchMedia("(min-width: 640px)")

function useWideScreen() {
  return useSyncExternalStore(
    (onChange) => {
      WIDE.addEventListener("change", onChange)
      return () => WIDE.removeEventListener("change", onChange)
    },
    () => WIDE.matches,
  )
}

/** The search box of the top bar; "/" focuses it from anywhere. */
function GlobalSearch() {
  const navigate = useNavigate()
  const input = useRef<HTMLInputElement>(null)
  // On the search page, the box shows what was searched for
  const searched = useRouterState({
    select: (state) =>
      state.location.pathname === "/search" ? ((state.location.search as { q?: string }).q ?? "") : "",
  })
  const wide = useWideScreen()
  const [query, setQuery] = useState(searched)
  const [shown, setShown] = useState(searched)
  if (searched !== shown) {
    setShown(searched)
    if (searched) setQuery(searched)
  }
  useEffect(() => {
    const focus = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement
      if (event.key === "/" && !target.closest("input, textarea, select, [contenteditable]")) {
        event.preventDefault()
        input.current?.focus()
      }
    }
    document.addEventListener("keydown", focus)
    return () => document.removeEventListener("keydown", focus)
  }, [])
  return (
    <form
      role="search"
      className="relative w-full max-w-md"
      onSubmit={(event) => {
        event.preventDefault()
        if (query.trim().length >= 2) navigate({ to: "/search", search: { q: query.trim() } })
      }}
    >
      <Search
        className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground"
        aria-hidden
      />
      <Input
        ref={input}
        type="search"
        value={query}
        onChange={(event) => setQuery(event.target.value)}
        placeholder={wide ? "Search serials, names, accounts, orders…" : "Search"}
        aria-label="Search"
        className="bg-background pr-8 pl-8"
      />
      <kbd className="pointer-events-none absolute top-1/2 right-2 hidden -translate-y-1/2 rounded border px-1.5 font-mono text-[0.6875rem] text-muted-foreground sm:block">
        /
      </kbd>
    </form>
  )
}

function UserMenu() {
  const session = useSession()
  const signOut = useSignOut()
  const router = useRouter()
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="sm" className="gap-2" aria-label={`Signed in as ${session.user}`}>
          <span
            className="grid size-6 place-items-center rounded-full bg-accent text-xs font-semibold text-accent-foreground uppercase"
            aria-hidden
          >
            {session.user?.slice(0, 1)}
          </span>
          <span className="hidden max-w-32 truncate sm:inline">{session.user}</span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-52">
        <DropdownMenuLabel className="font-normal">
          <span className="block truncate font-medium">{session.user}</span>
          <span className="text-xs text-muted-foreground capitalize">{session.role}</span>
        </DropdownMenuLabel>
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

export function AppShell({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="min-h-svh lg:grid lg:grid-cols-[15rem_1fr]">
      <div className="hidden border-r bg-sidebar lg:block">
        <aside className="sticky top-0 flex h-svh flex-col overflow-y-auto">
          <Brand />
          <Navigation />
        </aside>
      </div>
      <div className="flex min-w-0 flex-col">
        <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b bg-background/90 px-4 backdrop-blur sm:px-6">
          <Sheet open={open} onOpenChange={setOpen}>
            <SheetTrigger asChild>
              <Button variant="ghost" size="icon-sm" className="lg:hidden" aria-label="Menu">
                <Menu />
              </Button>
            </SheetTrigger>
            <SheetContent side="left" className="w-64 gap-0 bg-sidebar p-0">
              <SheetTitle className="sr-only">Menu</SheetTitle>
              <SheetDescription className="sr-only">The app's pages</SheetDescription>
              <Brand />
              <Navigation onNavigate={() => setOpen(false)} />
            </SheetContent>
          </Sheet>
          <GlobalSearch />
          <div className="ml-auto flex items-center gap-1">
            <ThemeMenu />
            <UserMenu />
          </div>
        </header>
        <main className={cn("mx-auto w-full max-w-[90rem] flex-1 px-4 py-6 sm:px-6 lg:py-8")}>{children}</main>
      </div>
    </div>
  )
}
