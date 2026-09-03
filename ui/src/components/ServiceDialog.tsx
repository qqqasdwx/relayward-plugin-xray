import { Dices } from "lucide-react"
import { useState } from "react"

import { FormRow } from "@/components/FormControls"
import { Button } from "@/components/ui/button"
import { Combobox } from "@/components/ui/combobox"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { randomServicePort } from "@/configuration"
import type { Translator } from "@/i18n"
import type { ProxyService, ServiceType, ShadowsocksMethod } from "@/types"

export function ServiceDialog({ initial, editingID, existingIDs, occupiedPorts, serviceTypes, createService, busy, t, onClose, onApply }: {
  initial: ProxyService; editingID: string | null; existingIDs: string[]; occupiedPorts: number[]; serviceTypes: ServiceType[]
  createService: (type: string) => ProxyService; busy: boolean; t: Translator; onClose: () => void; onApply: (value: ProxyService) => void
}) {
  const [value, setValue] = useState(initial)
  const duplicateID = existingIDs.some((id) => id === value.service_id && id !== editingID)
  const duplicatePort = occupiedPorts.includes(value.port)
  function changeType(type: string) { setValue(createService(type)) }
  function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (duplicateID || duplicatePort || !event.currentTarget.reportValidity()) return
    onApply({ ...value, service_id: value.service_id.trim(), display_name: value.display_name.trim(), vless_reality: value.vless_reality == null ? undefined : { target: value.vless_reality.target.trim() } })
  }
  return (
    <Dialog open onOpenChange={(open) => { if (!open) onClose() }}>
      <DialogContent className="max-h-[calc(100vh-2rem)] overflow-y-auto sm:max-w-2xl lg:max-w-3xl" closeLabel={t("Close")}>
        <form className="grid gap-6" onSubmit={submit}>
          <DialogHeader><DialogTitle>{t(editingID == null ? "Add inbound" : "Edit inbound")}</DialogTitle><DialogDescription>{value.type === "vless-reality" ? "VLESS + RAW + REALITY + Vision" : "Shadowsocks 2022"}</DialogDescription></DialogHeader>
          <div className="grid gap-4">
            <FormRow label={t("Enabled")}><div className="flex min-h-10 items-center justify-between rounded-md border px-3"><span className="text-sm text-muted-foreground">{t(value.enabled ? "Enabled" : "Disabled status")}</span><Switch checked={value.enabled} onCheckedChange={(enabled) => setValue({ ...value, enabled })} /></div></FormRow>
            <FormRow id="service-type" label={t("Protocol")} help={t("The protocol cannot be changed after the inbound is created.")}><Combobox id="service-type" value={value.type} disabled={editingID != null} options={serviceTypes.map((type) => ({ value: type.id, label: type.display_name }))} searchPlaceholder={t("Search options")} emptyText={t("No matching options")} onValueChange={changeType} /></FormRow>
            <FormRow id="service-name" label={t("Remark")}><Input id="service-name" value={value.display_name} maxLength={100} required onChange={(event) => setValue({ ...value, display_name: event.target.value })} /></FormRow>
            <FormRow id="service-id" label={t("Inbound tag")} help={t("Used by authorizations, access rules, and telemetry.")}><div className="grid gap-1"><Input id="service-id" value={value.service_id} disabled={editingID != null} pattern="[a-z0-9][a-z0-9._-]{0,63}" required aria-invalid={duplicateID} onChange={(event) => setValue({ ...value, service_id: event.target.value })} />{duplicateID ? <p className="text-sm text-destructive">{t("Inbound tag already exists.")}</p> : null}</div></FormRow>
            <FormRow id="service-port" label={t("Listening port")} help={t("Use a random high port to avoid common scanned service ports.")}><div className="grid gap-1"><div className="flex gap-2"><Input id="service-port" type="number" min={1024} max={65535} value={value.port} required aria-invalid={duplicatePort} onChange={(event) => setValue({ ...value, port: Number(event.target.value) })} /><Button type="button" variant="outline" size="icon" aria-label={t("Generate another random port")} onClick={() => setValue({ ...value, port: randomServicePort(occupiedPorts, value.port) })}><Dices /></Button></div>{duplicatePort ? <p className="text-sm text-destructive">{t("This port conflicts with another inbound.")}</p> : null}</div></FormRow>
            <FormRow label="PROXY Protocol" help={t("Enable only when a trusted upstream relay sends PROXY Protocol.")}><div className="flex min-h-10 items-center justify-between rounded-md border px-3"><span className="text-sm text-muted-foreground">{value.accept_proxy_protocol ? t("Enabled") : t("Disabled status")}</span><Switch checked={value.accept_proxy_protocol} onCheckedChange={(accept_proxy_protocol) => setValue({ ...value, accept_proxy_protocol })} /></div></FormRow>
            {value.type === "vless-reality" && value.vless_reality ? <FormRow id="reality-target" label={t("Camouflage target")} help={t("A lowercase TLS domain and port; its domain is the only allowed fallback SNI.")}><Input id="reality-target" value={value.vless_reality.target} placeholder="www.tesla.com:443" required onChange={(event) => setValue({ ...value, vless_reality: { target: event.target.value } })} /></FormRow> : null}
            {value.type === "shadowsocks" && value.shadowsocks ? <FormRow id="ss-method" label={t("Encryption method")}><Combobox id="ss-method" value={value.shadowsocks.method} options={shadowsocksMethodOptions} searchPlaceholder={t("Search options")} emptyText={t("No matching options")} onValueChange={(method) => setValue({ ...value, shadowsocks: { method: method as ShadowsocksMethod } })} /></FormRow> : null}
          </div>
          <DialogFooter><Button type="button" variant="outline" onClick={onClose}>{t("Cancel")}</Button><Button type="submit" disabled={busy}>{t("Apply inbound")}</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

const shadowsocksMethodOptions = [
  { value: "2022-blake3-aes-128-gcm", label: "2022-blake3-aes-128-gcm" },
  { value: "2022-blake3-aes-256-gcm", label: "2022-blake3-aes-256-gcm" },
]
