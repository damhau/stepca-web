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
        <form onSubmit={submit} className="flex flex-col gap-4 rounded-2xl border bg-card p-6" noValidate>
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
      </div>
    </main>
  )
}
