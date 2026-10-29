import { useQueryClient } from "@tanstack/react-query"
import { $api, setCsrfToken } from "./client"
import type { Role, SessionInfo } from "./types"

export const sessionQuery = $api.queryOptions("get", "/api/v1/session", {}, { staleTime: Infinity })

export function rememberSession(session: SessionInfo) {
  setCsrfToken(session.csrf_token)
  return session
}

/** The signed-in user; only rendered under the _app route, which guarantees a session. */
export function useSession(): SessionInfo {
  const { data } = $api.useQuery("get", "/api/v1/session", {}, { staleTime: Infinity, select: rememberSession })
  if (!data) throw new Error("useSession outside a signed-in page")
  return data
}

const ROLES: Role[] = ["viewer", "operator", "admin"]

export function roleAtLeast(role: Role | null | undefined, minimum: Role) {
  return !!role && ROLES.indexOf(role) >= ROLES.indexOf(minimum)
}

/** can("operator"): whether the signed-in user's role allows an action. The server checks it too. */
export function useCan() {
  const { role } = useSession()
  return (minimum: Role) => roleAtLeast(role, minimum)
}

export function useSignIn() {
  const queryClient = useQueryClient()
  return $api.useMutation("post", "/api/v1/session", {
    onSuccess: (session) => {
      // A new session: nothing cached for the previous one survives
      queryClient.removeQueries({ predicate: (query) => query.queryKey[1] !== "/api/v1/session" })
      queryClient.setQueryData(sessionQuery.queryKey, rememberSession(session))
    },
  })
}

export function useSignOut() {
  const queryClient = useQueryClient()
  return $api.useMutation("delete", "/api/v1/session", {
    onSuccess: (session) => {
      queryClient.clear()
      queryClient.setQueryData(sessionQuery.queryKey, rememberSession(session))
    },
  })
}
