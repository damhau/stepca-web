import { zodResolver } from "@hookform/resolvers/zod"
import { createFileRoute, redirect, useRouter } from "@tanstack/react-router"
import { KeyRound, ShieldCheck } from "lucide-react"
import { useForm } from "react-hook-form"
import { z } from "zod"
import { errorMessage } from "@/api/client"
import { rememberSession, sessionQuery, useSignIn } from "@/api/session"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { text } from "@/lib/search-params"

/** Only paths of this app: never a redirect to another site */
function safeRedirect(value: string | undefined) {
  return value && value.startsWith("/") && !value.startsWith("//") ? value : "/"
}

/** What the server's single sign-on sends the browser back with (/login?error=...): never its reason, which is in the audit log */
const SSO_ERRORS: Record<string, string> = {
  sso_failed: "Single sign-on failed. Try again, or ask an administrator to check the audit log.",
  no_access: "You signed in, but your account has no access to this app. Ask an administrator for a role.",
  sso_unavailable: "The identity provider could not be reached. Try again in a moment.",
}

export const Route = createFileRoute("/login")({
  validateSearch: (search: Record<string, unknown>): { redirect?: string; error?: string } => ({
    redirect: text(search.redirect, 2000),
    error: text(search.error, 50),
  }),
  beforeLoad: async ({ context, search }) => {
    const session = rememberSession(await context.queryClient.ensureQueryData(sessionQuery))
    if (session.authenticated) throw redirect({ href: safeRedirect(search.redirect) })
    return { session }
  },
  component: Login,
})

/** The server starts the sign-in and sends the browser to the identity provider: a page load, not an API call */
function ssoHref(target: string) {
  return target === "/" ? "/api/v1/session/oidc/login" : `/api/v1/session/oidc/login?next=${encodeURIComponent(target)}`
}

const schema = z.object({
  username: z.string().trim().min(1, "Enter your username"),
  password: z.string().min(1, "Enter your password"),
})

function Login() {
  const router = useRouter()
  const search = Route.useSearch()
  const { session } = Route.useRouteContext()
  const ssoError = search.error ? (SSO_ERRORS[search.error] ?? SSO_ERRORS.sso_failed) : undefined
  const signIn = useSignIn()
  const form = useForm({ resolver: zodResolver(schema), defaultValues: { username: "", password: "" } })
  const { errors } = form.formState

  const submit = form.handleSubmit((values) =>
    signIn.mutate(
      { body: values },
      {
        onSuccess: () => router.history.push(safeRedirect(search.redirect)),
        onError: () => form.setValue("password", ""),
      },
    ),
  )

  return (
    // Above the middle: centred, it sat low on a tall screen
    <main className="grid min-h-svh content-start justify-items-center px-4 pt-[max(3rem,20svh)] pb-12">
      <div className="w-full max-w-sm">
        {/* Centred over the card: left-aligned, it made the whole block look off-centre */}
        <div className="mb-6 flex flex-col items-center gap-3 text-center">
          <span className="grid size-10 place-items-center rounded-[10px] bg-inverse">
            <ShieldCheck className="size-5 text-inverse-foreground" strokeWidth={2.5} aria-hidden />
          </span>
          <div>
            <h1 className="text-xl font-semibold tracking-[-0.02em]">Sign in</h1>
            <p className="mt-0.5 text-[13px] text-muted-foreground">to manage the certificate authority</p>
          </div>
        </div>
        <div className="flex flex-col gap-4 rounded-2xl border bg-card p-6">
          {ssoError && (
            <p role="alert" className="rounded-lg bg-danger-bg px-3 py-2 text-[13px] text-danger-fg">
              {ssoError}
            </p>
          )}
          {session.sso_label && (
            <Button asChild variant={session.password_login ? "outline" : "default"}>
              <a href={ssoHref(safeRedirect(search.redirect))}>
                <KeyRound aria-hidden />
                {session.sso_label}
              </a>
            </Button>
          )}
          {session.sso_label && session.password_login && (
            <div className="flex items-center gap-3 text-xs text-muted-foreground" aria-hidden>
              <span className="h-px flex-1 bg-border" />
              or
              <span className="h-px flex-1 bg-border" />
            </div>
          )}
          {session.password_login && (
            <form onSubmit={submit} className="flex flex-col gap-4" noValidate>
              <div className="flex flex-col gap-2">
                <Label htmlFor="username">Username</Label>
                <Input
                  id="username"
                  autoComplete="username"
                  autoFocus
                  aria-invalid={!!errors.username}
                  {...form.register("username")}
                />
                {errors.username && <p className="text-[13px] text-danger-fg">{errors.username.message}</p>}
              </div>
              <div className="flex flex-col gap-2">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  type="password"
                  autoComplete="current-password"
                  aria-invalid={!!errors.password}
                  {...form.register("password")}
                />
                {errors.password && <p className="text-[13px] text-danger-fg">{errors.password.message}</p>}
              </div>
              {signIn.error && (
                <p role="alert" className="rounded-lg bg-danger-bg px-3 py-2 text-[13px] text-danger-fg">
                  {errorMessage(signIn.error)}
                </p>
              )}
              <Button type="submit" disabled={signIn.isPending} className="mt-2">
                {signIn.isPending ? "Signing in…" : "Sign in"}
              </Button>
            </form>
          )}
        </div>
      </div>
    </main>
  )
}
