import { Search } from "lucide-react"
import { useMemo, useState } from "react"

import { FormRow } from "@/components/FormControls"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Combobox } from "@/components/ui/combobox"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { csv } from "@/configuration"
import type { Translator } from "@/i18n"
import type { AccessRule, EgressLine, NodeAuthorization, ProxyService, RoutingProtocol } from "@/types"

const protocols: RoutingProtocol[] = ["http", "tls", "quic", "bittorrent"]

export function AccessRuleDialog({ initial, authorizations, services, lines, t, onClose, onApply }: {
  initial: AccessRule; authorizations: NodeAuthorization[]; services: ProxyService[]; lines: EgressLine[]; t: Translator
  onClose: () => void; onApply: (rule: AccessRule) => void
}) {
  const [value, setValue] = useState(initial)
  const [sourceIPs, setSourceIPs] = useState(initial.source_ips.join(", "))
  const [destinationIPs, setDestinationIPs] = useState(initial.destination_ips.join(", "))
  const [domains, setDomains] = useState(initial.domains.join(", "))
  const [authorizationSearch, setAuthorizationSearch] = useState("")
  const [error, setError] = useState("")
  const visibleAuthorizations = useMemo(() => {
    const search = authorizationSearch.trim().toLocaleLowerCase()
    return search === "" ? authorizations : authorizations.filter((item) => `${item.user_identifier} ${item.id}`.toLocaleLowerCase().includes(search))
  }, [authorizationSearch, authorizations])
  function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const candidate = { ...value, display_name: value.display_name.trim(), source_ips: csv(sourceIPs), destination_ips: csv(destinationIPs), domains: csv(domains), destination_port: compact(value.destination_port) }
    if (!hasCondition(candidate)) { setError(t("An access rule needs at least one match condition.")); return }
    if (!event.currentTarget.reportValidity()) return
    onApply(candidate)
  }
  function toggle(field: "authorization_ids" | "service_ids" | "protocols", item: string, checked: boolean) {
    const selected = new Set(value[field] as string[])
    if (checked) selected.add(item); else selected.delete(item)
    setValue({ ...value, [field]: [...selected] })
  }
  return (
    <Dialog open onOpenChange={(open) => { if (!open) onClose() }}>
      <DialogContent className="max-h-[calc(100vh-2rem)] overflow-y-auto sm:max-w-3xl lg:max-w-4xl" closeLabel={t("Close")}>
        <form className="grid gap-6" onSubmit={submit}>
          <DialogHeader><DialogTitle>{t(initial.display_name === "" ? "Add access rule" : "Edit access rule")}</DialogTitle><DialogDescription>{t("Values in one field use OR; populated fields are combined with AND")}</DialogDescription></DialogHeader>
          <section className="grid gap-4"><h3 className="text-sm font-semibold">{t("Rule")}</h3><FormRow label={t("Enabled")}><div className="flex min-h-10 items-center justify-between rounded-md border px-3"><span className="text-sm text-muted-foreground">{t(value.enabled ? "Enabled" : "Disabled status")}</span><Switch checked={value.enabled} onCheckedChange={(enabled) => setValue({ ...value, enabled })} /></div></FormRow><FormRow id="rule-name" label={t("Name")}><Input id="rule-name" value={value.display_name} required maxLength={100} onChange={(event) => setValue({ ...value, display_name: event.target.value })} /></FormRow></section>
          <section className="grid gap-4 border-t pt-6"><h3 className="text-sm font-semibold">{t("Source")}</h3><FormRow id="source-ip" label={t("Source IP")} help={t("Comma-separated IP addresses, CIDRs, or geoip expressions.")}><Input id="source-ip" value={sourceIPs} placeholder="203.0.113.0/24, geoip:cn" onChange={(event) => setSourceIPs(event.target.value)} /></FormRow><FormRow label={t("Authorizations")} align="start"><ChoiceList search={authorizationSearch} onSearch={setAuthorizationSearch} searchPlaceholder={t("Search authorizations")} empty={t("No matching authorizations")}>{visibleAuthorizations.map((authorization) => <Choice key={authorization.id} label={authorization.user_identifier} detail={authorization.id} checked={value.authorization_ids.includes(authorization.id)} onChange={(checked) => toggle("authorization_ids", authorization.id, checked)} />)}</ChoiceList></FormRow><FormRow label={t("Inbounds")} align="start"><ChoiceList empty={t("Any inbound")}>{services.map((service) => <Choice key={service.service_id} label={service.display_name} detail={service.service_id} checked={value.service_ids.includes(service.service_id)} onChange={(checked) => toggle("service_ids", service.service_id, checked)} />)}</ChoiceList></FormRow></section>
          <section className="grid gap-4 border-t pt-6"><h3 className="text-sm font-semibold">{t("Traffic and destination")}</h3><FormRow id="rule-network" label={t("Network")}><Combobox id="rule-network" value={value.network || "any"} options={[{ value: "any", label: t("Any") }, { value: "tcp", label: "TCP" }, { value: "udp", label: "UDP" }, { value: "tcp,udp", label: "TCP / UDP" }]} searchPlaceholder={t("Search options")} emptyText={t("No matching options")} onValueChange={(network) => setValue({ ...value, network: network === "any" ? "" : network as AccessRule["network"] })} /></FormRow><FormRow label={t("Sniffed protocols")} align="start"><ChoiceList empty={t("Any")}>{protocols.map((protocol) => <Choice key={protocol} label={protocol === "bittorrent" ? "BitTorrent" : protocol.toUpperCase()} checked={value.protocols.includes(protocol)} onChange={(checked) => toggle("protocols", protocol, checked)} />)}</ChoiceList></FormRow><FormRow id="destination-ip" label={t("Destination IP")}><Input id="destination-ip" value={destinationIPs} placeholder="10.0.0.0/8, geoip:private" onChange={(event) => setDestinationIPs(event.target.value)} /></FormRow><FormRow id="rule-domains" label={t("Domain")}><Input id="rule-domains" value={domains} placeholder="domain:example.com, geosite:cn" onChange={(event) => setDomains(event.target.value)} /></FormRow><FormRow id="destination-port" label={t("Destination port")}><Input id="destination-port" value={value.destination_port} placeholder="80,443,1000-2000" onChange={(event) => setValue({ ...value, destination_port: event.target.value })} /></FormRow></section>
          <section className="grid gap-4 border-t pt-6"><h3 className="text-sm font-semibold">{t("Action")}</h3><FormRow id="rule-action" label={t("Action")}><Combobox id="rule-action" value={value.action} options={[{ value: "block", label: t("Block") }, { value: "egress", label: t("Use egress line") }]} searchPlaceholder={t("Search options")} emptyText={t("No matching options")} onValueChange={(action) => setValue({ ...value, action: action as AccessRule["action"], egress_line_id: action === "egress" ? value.egress_line_id ?? "default" : undefined })} /></FormRow>{value.action === "egress" ? <FormRow id="rule-egress" label={t("Egress line")}><Combobox id="rule-egress" value={value.egress_line_id ?? "default"} options={lines.filter((line) => line.enabled).map((line) => ({ value: line.line_id, label: line.display_name, keywords: [line.line_id] }))} searchPlaceholder={t("Search egress lines")} emptyText={t("No matching options")} onValueChange={(egress_line_id) => setValue({ ...value, egress_line_id })} /></FormRow> : null}</section>
          {error ? <p className="text-sm text-destructive" role="alert">{error}</p> : null}
          <DialogFooter><Button type="button" variant="outline" onClick={onClose}>{t("Cancel")}</Button><Button type="submit">{t("Apply rule")}</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function ChoiceList({ search, onSearch, searchPlaceholder, empty, children }: { search?: string; onSearch?: (value: string) => void; searchPlaceholder?: string; empty: string; children: React.ReactNode }) {
  const items = Array.isArray(children) ? children : [children]
  return <div className="grid max-h-52 overflow-hidden rounded-md border">{onSearch ? <div className="relative border-b"><Search className="absolute left-3 top-3 size-4 text-muted-foreground" /><Input className="border-0 pl-9 shadow-none focus-visible:ring-0" value={search} placeholder={searchPlaceholder} onChange={(event) => onSearch(event.target.value)} /></div> : null}<div className="grid overflow-y-auto p-2">{items.length > 0 ? children : <span className="p-2 text-sm text-muted-foreground">{empty}</span>}</div></div>
}
function Choice({ label, detail, checked, onChange }: { label: string; detail?: string; checked: boolean; onChange: (checked: boolean) => void }) {
  return <Label className="flex cursor-pointer items-start gap-3 rounded-md px-2 py-2 hover:bg-muted"><Checkbox className="mt-0.5" checked={checked} onCheckedChange={(next) => onChange(next === true)} /><span className="min-w-0"><strong className="block truncate text-sm font-medium">{label}</strong>{detail ? <span className="block truncate text-xs text-muted-foreground">{detail}</span> : null}</span></Label>
}
function compact(value: string): string { return value.split(",").map((item) => item.trim()).filter(Boolean).join(",") }
function hasCondition(value: AccessRule): boolean { return value.source_ips.length + value.protocols.length + value.destination_ips.length + value.domains.length + value.authorization_ids.length + value.service_ids.length > 0 || value.network !== "" || value.destination_port !== "" }
