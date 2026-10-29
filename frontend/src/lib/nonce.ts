// This page's Content-Security-Policy nonce, which the server writes into index.html. Style elements need
// it: the dialogs' scroll lock (through get-nonce) and the select list's (through its nonce prop)
const content = document.querySelector<HTMLMetaElement>('meta[name="csp-nonce"]')?.content
export const cspNonce = content && content !== "__CSP_NONCE__" ? content : undefined
