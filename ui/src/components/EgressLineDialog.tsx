import { useState } from "react"

import { FormRow } from "@/components/FormControls"
import { Button } from "@/components/ui/button"
import { Combobox } from "@/components/ui/combobox"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { nextEgressLineDefaults } from "@/configuration"
import type { Translator } from "@/i18n"
import type { EgressLine, EgressType, NetworkAddress, ShadowsocksMethod } from "@/types"

export function EgressLineDialog({ initial, editingID, lines, addresses, t, onClose, onApply }: {
  initial: EgressLine; editingID: string | null; lines: EgressLine[]; addresses: NetworkAddress[]; t: Translator
  onClose: () => void; onApply: (line: EgressLine) => void
}) {
  const [value, setValue] = useState(initial)
  const fixed = editingID === "default"
  const duplicateID = lines.some((line) => line.line_id === value.line_id && line.line_id !== editingID)
  const duplicateRoute = lines.some((line) => line.vless_route === value.vless_route && line.line_id !== editingID)
  function changeType(type: EgressType) { setValue({ ...nextEgressLineDefaults(lines, type), line_id: value.line_id, display_name: value.display_name, enabled: value.enabled, vless_route: value.vless_route }) }
  function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (duplicateID || duplicateRoute || !event.currentTarget.reportValidity()) return
    onApply(normalize(value))
  }
  return (
    <Dialog open onOpenChange={(open) => { if (!open) onClose() }}>
      <DialogContent className="max-h-[calc(100vh-2rem)] overflow-y-auto sm:max-w-2xl lg:max-w-3xl" closeLabel={t("Close")}>
        <form className="grid gap-6" onSubmit={submit}>
          <DialogHeader><DialogTitle>{t(editingID == null ? "Add egress line" : "Edit egress line")}</DialogTitle><DialogDescription>{t("Configure how matching traffic leaves this node")}</DialogDescription></DialogHeader>
          <div className="grid gap-4">
            <FormRow label={t("Enabled")}><div className="flex min-h-10 items-center justify-between rounded-md border px-3"><span className="text-sm text-muted-foreground">{t(value.enabled ? "Enabled" : "Disabled status")}</span><Switch checked={value.enabled} disabled={fixed} onCheckedChange={(enabled) => setValue({ ...value, enabled })} /></div></FormRow>
            <FormRow id="egress-name" label={t("Name")}><Input id="egress-name" value={value.display_name} required maxLength={100} onChange={(event) => setValue({ ...value, display_name: event.target.value })} /></FormRow>
            <FormRow id="egress-id" label={t("Line ID")}><div className="grid gap-1"><Input id="egress-id" value={value.line_id} required disabled={editingID != null} pattern="[a-z0-9][a-z0-9._-]{0,63}" aria-invalid={duplicateID} onChange={(event) => setValue({ ...value, line_id: event.target.value })} />{duplicateID ? <p className="text-sm text-destructive">{t("Line ID already exists.")}</p> : null}</div></FormRow>
            <FormRow id="egress-route" label="VLESS route" help={t("A unique value encoded into subscription UUIDs for this line.")}><div className="grid gap-1"><Input id="egress-route" type="number" min={fixed ? 0 : 1} max={65535} disabled={fixed} value={value.vless_route} required aria-invalid={duplicateRoute} onChange={(event) => setValue({ ...value, vless_route: Number(event.target.value) })} />{duplicateRoute ? <p className="text-sm text-destructive">{t("VLESS route already exists.")}</p> : null}</div></FormRow>
            <FormRow id="egress-type" label={t("Type")}><Combobox id="egress-type" value={value.type} options={[{ value: "direct", label: t("Direct") }, { value: "socks5", label: "SOCKS5" }, { value: "shadowsocks", label: "Shadowsocks 2022" }]} searchPlaceholder={t("Search options")} emptyText={t("No matching options")} onValueChange={(type) => changeType(type as EgressType)} /></FormRow>
            {value.type === "direct" && value.direct ? <FormRow id="send-through" label={t("Source address")} help={t("Leave empty to use the operating system default route.")}><Combobox id="send-through" value={value.direct.send_through || "system"} options={[{ value: "system", label: t("System default") }, ...addresses.map((address) => ({ value: address.address, label: `${address.address} · ${address.interface}`, keywords: [address.family] }))]} searchPlaceholder={t("Search node addresses")} emptyText={t("No matching options")} onValueChange={(selected) => setValue({ ...value, direct: { send_through: selected === "system" ? "" : selected } })} /></FormRow> : null}
            {value.type === "socks5" && value.socks5 ? <SOCKSFields value={value} setValue={setValue} t={t} /> : null}
            {value.type === "shadowsocks" && value.shadowsocks ? <ShadowsocksFields value={value} setValue={setValue} t={t} /> : null}
          </div>
          <DialogFooter><Button type="button" variant="outline" onClick={onClose}>{t("Cancel")}</Button><Button type="submit">{t("Apply egress line")}</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function SOCKSFields({ value, setValue, t }: { value: EgressLine; setValue: (value: EgressLine) => void; t: Translator }) {
  const settings = value.socks5!
  const update = (next: Partial<typeof settings>) => setValue({ ...value, socks5: { ...settings, ...next } })
  return <><FormRow id="socks-address" label={t("Server address")}><Input id="socks-address" value={settings.address} required onChange={(event) => update({ address: event.target.value })} /></FormRow><FormRow id="socks-port" label={t("Server port")}><Input id="socks-port" type="number" min={1} max={65535} value={settings.port} required onChange={(event) => update({ port: Number(event.target.value) })} /></FormRow><FormRow label={t("Authentication")}><div className="flex min-h-10 items-center justify-between rounded-md border px-3"><span className="text-sm text-muted-foreground">{t(settings.use_authentication ? "Enabled" : "Disabled status")}</span><Switch checked={settings.use_authentication} onCheckedChange={(use_authentication) => update({ use_authentication, username: use_authentication ? settings.username : "", password: "" })} /></div></FormRow>{settings.use_authentication ? <><FormRow id="socks-user" label={t("Username")}><Input id="socks-user" value={settings.username} required onChange={(event) => update({ username: event.target.value })} /></FormRow><FormRow id="socks-password" label={t("Password")} help={settings.password_configured ? t("Leave empty to keep the saved password.") : undefined}><Input id="socks-password" type="password" value={settings.password} required={!settings.password_configured} onChange={(event) => update({ password: event.target.value })} /></FormRow></> : null}</>
}

function ShadowsocksFields({ value, setValue, t }: { value: EgressLine; setValue: (value: EgressLine) => void; t: Translator }) {
  const settings = value.shadowsocks!
  const update = (next: Partial<typeof settings>) => setValue({ ...value, shadowsocks: { ...settings, ...next } })
  return <><FormRow id="ss-address" label={t("Server address")}><Input id="ss-address" value={settings.address} required onChange={(event) => update({ address: event.target.value })} /></FormRow><FormRow id="ss-port" label={t("Server port")}><Input id="ss-port" type="number" min={1} max={65535} value={settings.port} required onChange={(event) => update({ port: Number(event.target.value) })} /></FormRow><FormRow id="ss-method" label={t("Encryption method")}><Combobox id="ss-method" value={settings.method} options={shadowsocksMethodOptions} searchPlaceholder={t("Search options")} emptyText={t("No matching options")} onValueChange={(method) => update({ method: method as ShadowsocksMethod })} /></FormRow><FormRow id="ss-password" label={t("Password")} help={settings.password_configured ? t("Leave empty to keep the saved password.") : undefined}><Input id="ss-password" type="password" value={settings.password} required={!settings.password_configured} onChange={(event) => update({ password: event.target.value })} /></FormRow></>
}

const shadowsocksMethodOptions = [
  { value: "2022-blake3-aes-128-gcm", label: "2022-blake3-aes-128-gcm" },
  { value: "2022-blake3-aes-256-gcm", label: "2022-blake3-aes-256-gcm" },
]

function normalize(value: EgressLine): EgressLine {
  const result = { ...value, line_id: value.line_id.trim(), display_name: value.display_name.trim() }
  if (result.socks5) result.socks5 = { ...result.socks5, address: result.socks5.address.trim(), username: result.socks5.username.trim() }
  if (result.shadowsocks) result.shadowsocks = { ...result.shadowsocks, address: result.shadowsocks.address.trim() }
  return result
}
