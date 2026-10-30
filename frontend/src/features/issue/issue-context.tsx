import { createContext, lazy, Suspense, useCallback, useContext, useMemo, useState } from "react"
import { roleAtLeast, useSession } from "@/api/session"

// The dialog and its X.509 library load on first use
const IssueDialog = lazy(() => import("./issue-dialog"))

type IssueContext = { open: () => void; allowed: boolean }

const Context = createContext<IssueContext>({ open: () => {}, allowed: false })

/** "New certificate" from anywhere: the page headers, ⌘K. Operators and admins only. */
export function IssueProvider({ children }: { children: React.ReactNode }) {
  const session = useSession()
  const allowed = roleAtLeast(session.role, "operator")
  const [opened, setOpened] = useState(false)
  const [loaded, setLoaded] = useState(false)
  const open = useCallback(() => {
    setLoaded(true)
    setOpened(true)
  }, [])
  const value = useMemo(() => ({ open, allowed }), [open, allowed])
  return (
    <Context.Provider value={value}>
      {children}
      {allowed && loaded && (
        <Suspense fallback={null}>
          <IssueDialog open={opened} onOpenChange={setOpened} />
        </Suspense>
      )}
    </Context.Provider>
  )
}

export function useIssue() {
  return useContext(Context)
}
