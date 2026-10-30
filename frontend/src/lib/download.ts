/** Saves text the browser made (a key, a bundle) as a file, without sending it anywhere. */
export function saveFile(filename: string, content: string, type = "application/x-pem-file") {
  const url = URL.createObjectURL(new Blob([content], { type }))
  const link = document.createElement("a")
  link.href = url
  link.download = filename
  document.body.append(link)
  link.click()
  link.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

/** The base64 of text, as Kubernetes Secrets hold their data. */
export function base64(text: string) {
  return btoa(String.fromCharCode(...new TextEncoder().encode(text)))
}
