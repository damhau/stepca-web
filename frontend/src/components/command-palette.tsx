import { useNavigate } from "@tanstack/react-router"
import { Download, FileText, House, KeyRound, ListChecks, Network, Plus, Search, Server, UserCog } from "lucide-react"
import { useEffect, useState } from "react"
import { $api } from "@/api/client"
import { roleAtLeast, useSession } from "@/api/session"
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from "@/components/ui/command"
import { useIssue } from "@/features/issue/issue-context"

type Page = { to: string; label: string; icon: React.ComponentType<{ className?: string }>; admin?: boolean }

const PAGES: Page[] = [
  { to: "/", label: "Overview", icon: House },
  { to: "/certificates", label: "Certificates", icon: FileText },
  { to: "/provisioners", label: "Provisioners", icon: KeyRound },
  { to: "/acme/orders", label: "ACME orders", icon: Network },
  { to: "/acme/accounts", label: "ACME accounts", icon: Network },
  { to: "/audit", label: "Audit log", icon: ListChecks, admin: true },
  { to: "/ca", label: "Authority", icon: Server },
  { to: "/admins", label: "Admins", icon: UserCog },
]

function useDebounced(value: string, delay = 200) {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delay)
    return () => clearTimeout(timer)
  }, [value, delay])
  return debounced
}

/** ⌘K: go to a page, run an action, or open what the search finds (certificates, ACME, provisioners, admins). */
export function CommandPalette({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const navigate = useNavigate()
  const session = useSession()
  const issue = useIssue()
  const [text, setText] = useState("")
  const query = useDebounced(text.trim())
  const results = $api.useQuery(
    "get",
    "/api/v1/search",
    { params: { query: { q: query } } },
    { enabled: open && query.length >= 2 },
  )
  const needle = text.trim().toLowerCase()
  const pages = PAGES.filter(
    (page) => (!page.admin || roleAtLeast(session.role, "admin")) && page.label.toLowerCase().includes(needle),
  )
  const go = (action: () => void) => {
    onOpenChange(false)
    setText("")
    action()
  }
  const found = query.length >= 2 ? results.data : undefined
  // Typing (the debounce) counts as searching: "Nothing matches" only once the answer is in
  const searching = needle.length >= 2 && (text.trim() !== query || results.isFetching)
  const showNew = issue.allowed && "new certificate".includes(needle)
  const showExport = "export certificates csv".includes(needle)
  const showAll = needle.length >= 2
  return (
    <CommandDialog
      shouldFilter={false}
      open={open}
      onOpenChange={onOpenChange}
      title="Search or run a command"
      description="Pages, actions and search results"
    >
      <CommandInput
        value={text}
        onValueChange={setText}
        placeholder="Search certificates, ACME, provisioners, or type a page…"
      />
      <CommandList className="max-h-[min(60vh,420px)]">
        <CommandEmpty>{searching ? "Searching…" : "Nothing matches."}</CommandEmpty>
        {found && found.certificates.length > 0 && (
          <CommandGroup heading="Certificates">
            {found.certificates.slice(0, 8).map((cert) => (
              <CommandItem
                key={cert.serial}
                value={`cert-${cert.serial}`}
                onSelect={() => go(() => navigate({ to: "/certificates", search: { cert: cert.serial } }))}
              >
                <FileText />
                <span className="truncate font-mono text-[13px]">{cert.common_name ?? cert.subject}</span>
                <span className="ml-auto truncate font-mono text-xs text-muted-foreground">
                  {cert.serial_hex.slice(0, 12)}
                </span>
              </CommandItem>
            ))}
          </CommandGroup>
        )}
        {found && found.acme_orders.length > 0 && (
          <CommandGroup heading="ACME orders">
            {found.acme_orders.slice(0, 5).map((order) => (
              <CommandItem
                key={order.id}
                value={`order-${order.id}`}
                onSelect={() => go(() => navigate({ to: "/acme/orders/$id", params: { id: order.id } }))}
              >
                <Network />
                <span className="truncate">{order.identifiers.map((identifier) => identifier.value).join(", ")}</span>
                <span className="ml-auto text-xs text-muted-foreground">{order.status}</span>
              </CommandItem>
            ))}
          </CommandGroup>
        )}
        {found && found.acme_accounts.length > 0 && (
          <CommandGroup heading="ACME accounts">
            {found.acme_accounts.slice(0, 5).map((account) => (
              <CommandItem
                key={account.id}
                value={`account-${account.id}`}
                onSelect={() => go(() => navigate({ to: "/acme/accounts/$id", params: { id: account.id } }))}
              >
                <Network />
                <span className="truncate">
                  {account.contact.map((contact) => contact.replace(/^mailto:/, "")).join(", ") || account.id}
                </span>
              </CommandItem>
            ))}
          </CommandGroup>
        )}
        {found && found.provisioners.length > 0 && (
          <CommandGroup heading="Provisioners">
            {found.provisioners.map((provisioner) => (
              <CommandItem
                key={provisioner.id}
                value={`provisioner-${provisioner.id}`}
                onSelect={() => go(() => navigate({ to: "/provisioners/$name", params: { name: provisioner.name } }))}
              >
                <KeyRound />
                <span className="font-mono text-[13px]">{provisioner.name}</span>
                <span className="ml-auto text-xs text-muted-foreground">{provisioner.type}</span>
              </CommandItem>
            ))}
          </CommandGroup>
        )}
        {found && found.admins.length > 0 && (
          <CommandGroup heading="Admins">
            {found.admins.map((admin) => (
              <CommandItem
                key={admin.id}
                value={`admin-${admin.id}`}
                onSelect={() => go(() => navigate({ to: "/admins" }))}
              >
                <UserCog />
                {admin.subject}
                <span className="ml-auto text-xs text-muted-foreground">{admin.type}</span>
              </CommandItem>
            ))}
          </CommandGroup>
        )}
        {found && <CommandSeparator />}
        {(showNew || showExport || showAll) && (
          <CommandGroup heading="Actions">
            {showNew && (
              <CommandItem value="action-new" onSelect={() => go(issue.open)}>
                <Plus /> New certificate
              </CommandItem>
            )}
            {showExport && (
              <CommandItem
                value="action-export"
                onSelect={() => go(() => window.location.assign("/api/v1/certificates?format=csv"))}
              >
                <Download /> Export certificates (CSV)
              </CommandItem>
            )}
            {showAll && (
              <CommandItem
                value="action-search"
                onSelect={() => go(() => navigate({ to: "/search", search: { q: text.trim() } }))}
              >
                <Search /> See every result for “{text.trim()}”
              </CommandItem>
            )}
          </CommandGroup>
        )}
        {pages.length > 0 && (
          <CommandGroup heading="Go to">
            {pages.map((page) => (
              <CommandItem key={page.to} value={`page-${page.to}`} onSelect={() => go(() => navigate({ to: page.to }))}>
                <page.icon /> {page.label}
              </CommandItem>
            ))}
          </CommandGroup>
        )}
      </CommandList>
    </CommandDialog>
  )
}
