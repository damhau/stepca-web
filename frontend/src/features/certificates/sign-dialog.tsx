import { zodResolver } from "@hookform/resolvers/zod"
import { useQueryClient } from "@tanstack/react-query"
import { useNavigate } from "@tanstack/react-router"
import { CircleAlert, FileUp } from "lucide-react"
import { useEffect, useState } from "react"
import { useForm, useWatch } from "react-hook-form"
import { z } from "zod"
import { $api, errorMessage, fetchClient } from "@/api/client"
import type { CsrDescription } from "@/api/types"
import { toast } from "@/components/toaster"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"

// A CSR is a few kilobytes
const MAX_CSR_BYTES = 64 * 1024
const GO_DURATION = /^(\d+(\.\d+)?(ns|us|µs|ms|s|m|h))+$/

const schema = z.object({
  provisioner: z.string().min(1, "Choose a provisioner"),
  password: z.string().min(1, "Enter the provisioner's password"),
  csr_pem: z.string().trim().min(1, "Paste a CSR or choose a file").max(MAX_CSR_BYTES, "The CSR is too large"),
  valid_for: z
    .string()
    .trim()
    .refine((value) => value === "" || GO_DURATION.test(value), "A duration such as 24h, 720h or 90m"),
})

type Values = z.infer<typeof schema>

function useCsrPreview(csr: string) {
  const [preview, setPreview] = useState<{ csr: string; result: CsrDescription | null; error?: string } | null>(null)
  useEffect(() => {
    const text = csr.trim()
    if (!text.includes("BEGIN CERTIFICATE REQUEST")) return
    const timer = setTimeout(async () => {
      const { data, error } = await fetchClient.POST("/api/v1/csr/preview", { body: { csr_pem: text } })
      setPreview({ csr: text, result: data ?? null, error: error ? errorMessage(error) : undefined })
    }, 300)
    return () => clearTimeout(timer)
  }, [csr])
  return preview && preview.csr === csr.trim() ? preview : null
}

/** Signs a CSR with a JWK provisioner's key, which its password decrypts on the server. */
export function SignDialog() {
  const [open, setOpen] = useState(false)
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const reference = $api.useQuery("get", "/api/v1/reference", {}, { staleTime: Infinity })
  const provisioners = reference.data?.signing_provisioners
  const form = useForm<Values>({
    resolver: zodResolver(schema),
    defaultValues: { provisioner: "", password: "", csr_pem: "", valid_for: "" },
  })
  const { errors } = form.formState
  const csr = useWatch({ control: form.control, name: "csr_pem" })
  const provisioner = useWatch({ control: form.control, name: "provisioner" })
  const preview = useCsrPreview(csr)
  useEffect(() => {
    if (!form.getValues("provisioner") && provisioners?.[0]) form.setValue("provisioner", provisioners[0])
  }, [provisioners, form])

  const sign = $api.useMutation("post", "/api/v1/certificates", {
    onSuccess: ({ serial }) => {
      toast.success(`Certificate ${serial} signed.`)
      queryClient.invalidateQueries()
      setOpen(false)
      form.reset()
      navigate({ to: "/certificates/$serial", params: { serial } })
    },
    onError: () => form.setValue("password", ""),
  })

  async function readFile(file: File | undefined) {
    if (!file) return
    if (file.size > MAX_CSR_BYTES) {
      form.setError("csr_pem", { message: "The CSR file is too large" })
      return
    }
    form.setValue("csr_pem", (await file.text()).trim(), { shouldValidate: true })
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next)
        if (!next) sign.reset()
      }}
    >
      <DialogTrigger asChild>
        <Button size="sm">
          <FileUp /> Sign a CSR
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Sign a certificate signing request</DialogTitle>
          <DialogDescription>
            The certificate gets the names the CSR asks for, from a JWK provisioner.
          </DialogDescription>
        </DialogHeader>
        <form
          id="sign-form"
          noValidate
          className="flex flex-col gap-4"
          onSubmit={form.handleSubmit((values) =>
            sign.mutate({ body: { ...values, csr_pem: values.csr_pem.trim(), valid_for: values.valid_for || null } }),
          )}
        >
          <div className="flex flex-col gap-2">
            <div className="flex items-center justify-between gap-2">
              <Label htmlFor="csr_pem">CSR (PEM)</Label>
              <Label
                htmlFor="csr_file"
                className="cursor-pointer text-sm font-normal text-primary underline-offset-4 hover:underline"
              >
                Choose a file…
              </Label>
              <input
                id="csr_file"
                type="file"
                accept=".csr,.pem,.req,.txt"
                className="sr-only"
                onChange={(event) => readFile(event.target.files?.[0])}
              />
            </div>
            <Textarea
              id="csr_pem"
              rows={7}
              spellCheck={false}
              placeholder="-----BEGIN CERTIFICATE REQUEST-----"
              className="font-mono text-xs"
              aria-invalid={!!errors.csr_pem}
              {...form.register("csr_pem")}
            />
            {errors.csr_pem && <p className="text-sm text-revoked">{errors.csr_pem.message}</p>}
            {preview && <CsrPreview preview={preview} />}
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="flex flex-col gap-2">
              <Label htmlFor="provisioner">Provisioner</Label>
              <Select
                value={provisioner}
                onValueChange={(value) => form.setValue("provisioner", value, { shouldValidate: true })}
              >
                <SelectTrigger id="provisioner" className="w-full" aria-invalid={!!errors.provisioner}>
                  <SelectValue placeholder={provisioners?.length ? "Choose" : "No JWK provisioner"} />
                </SelectTrigger>
                <SelectContent>
                  {provisioners?.map((name) => (
                    <SelectItem key={name} value={name}>
                      {name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {errors.provisioner && <p className="text-sm text-revoked">{errors.provisioner.message}</p>}
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="sign-password">Provisioner password</Label>
              <Input
                id="sign-password"
                type="password"
                autoComplete="off"
                aria-invalid={!!errors.password}
                {...form.register("password")}
              />
              {errors.password && <p className="text-sm text-revoked">{errors.password.message}</p>}
            </div>
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="valid_for">Valid for</Label>
            <Input
              id="valid_for"
              placeholder="The provisioner's default, such as 24h"
              aria-invalid={!!errors.valid_for}
              {...form.register("valid_for")}
            />
            <p className="text-sm text-muted-foreground">Within the provisioner's minimum and maximum durations.</p>
            {errors.valid_for && <p className="text-sm text-revoked">{errors.valid_for.message}</p>}
          </div>
          {sign.error && (
            <p role="alert" className="rounded-md bg-revoked-soft px-3 py-2 text-sm text-revoked">
              {errorMessage(sign.error)}
            </p>
          )}
        </form>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button type="submit" form="sign-form" disabled={sign.isPending}>
            {sign.isPending ? "Signing…" : "Sign certificate"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function CsrPreview({ preview }: { preview: { result: CsrDescription | null; error?: string } }) {
  if (!preview.result) {
    return (
      <p className="flex items-center gap-2 text-sm text-revoked">
        <CircleAlert className="size-4" aria-hidden /> {preview.error}
      </p>
    )
  }
  const csr = preview.result
  return (
    <dl
      aria-live="polite"
      className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 rounded-md border bg-muted/50 px-3 py-2 text-sm"
    >
      <dt className="text-muted-foreground">Subject</dt>
      <dd className="break-all">{csr.subject || "—"}</dd>
      <dt className="text-muted-foreground">Names</dt>
      <dd className="break-all">{csr.sans.join(", ") || "—"}</dd>
      <dt className="text-muted-foreground">Key</dt>
      <dd>{csr.key}</dd>
      <dt className="text-muted-foreground">Signature</dt>
      <dd className={csr.signature_valid ? "text-valid" : "text-revoked"}>
        {csr.signature_valid ? "Valid" : "Not valid: step-ca will refuse it"}
      </dd>
    </dl>
  )
}
