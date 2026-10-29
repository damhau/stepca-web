import { zodResolver } from "@hookform/resolvers/zod"
import { createFileRoute, redirect, useRouter } from "@tanstack/react-router"
import { ShieldCheck } from "lucide-react"
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

export const Route = createFileRoute("/login")({
  validateSearch: (search: Record<string, unknown>): { redirect?: string } => ({
    redirect: text(search.redirect, 2000),
  }),
  beforeLoad: async ({ context, search }) => {
    const session = rememberSession(await context.queryClient.ensureQueryData(sessionQuery))
    if (session.authenticated) throw redirect({ href: safeRedirect(search.redirect) })
  },
  component: Login,
})

const schema = z.object({
  username: z.string().trim().min(1, "Enter your username"),
  password: z.string().min(1, "Enter your password"),
})

function Login() {
  const router = useRouter()
  const search = Route.useSearch()
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
    <main className="grid min-h-svh place-items-center px-4 py-12">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex items-center gap-3">
          <span className="grid size-10 place-items-center rounded-lg bg-primary text-primary-foreground">
            <ShieldCheck className="size-5" aria-hidden />
          </span>
          <div>
            <h1 className="text-lg font-semibold">Step CA</h1>
            <p className="text-sm text-muted-foreground">Sign in to manage the certificate authority</p>
          </div>
        </div>
        <form onSubmit={submit} className="flex flex-col gap-4 rounded-lg border bg-card p-6" noValidate>
          <div className="flex flex-col gap-2">
            <Label htmlFor="username">Username</Label>
            <Input
              id="username"
              autoComplete="username"
              autoFocus
              aria-invalid={!!errors.username}
              {...form.register("username")}
            />
            {errors.username && <p className="text-sm text-revoked">{errors.username.message}</p>}
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
            {errors.password && <p className="text-sm text-revoked">{errors.password.message}</p>}
          </div>
          {signIn.error && (
            <p role="alert" className="rounded-md bg-revoked-soft px-3 py-2 text-sm text-revoked">
              {errorMessage(signIn.error)}
            </p>
          )}
          <Button type="submit" disabled={signIn.isPending} className="mt-2">
            {signIn.isPending ? "Signing in…" : "Sign in"}
          </Button>
        </form>
      </div>
    </main>
  )
}
