import { setNonce } from "get-nonce"
import { StrictMode } from "react"
import { createRoot } from "react-dom/client"

import { App } from "@/App"
import "@/index.css"

const styleNonce = document.querySelector<HTMLMetaElement>('meta[name="relayward-style-nonce"]')?.content
if (styleNonce) setNonce(styleNonce)

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
