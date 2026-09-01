import { HelpCircle, Plus, Trash2 } from "lucide-react"
import { useState } from "react"

import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import type { Translator } from "@/i18n"
import type { ProxyService, RoutingProtocol, RoutingRule, XrayOutbound } from "@/types"

const protocols: RoutingProtocol[] = ["http", "tls", "bittorrent", "quic"]

interface RoutingRuleDialogProps {
  initial: RoutingRule
  editingID: string | null
  services: ProxyService[]
  outbounds: XrayOutbound[]
  t: Translator
  onClose: () => void
  onApply: (rule: RoutingRule) => void
}

interface AttributeEntry {
  key: string
  value: string
}

export function RoutingRuleDialog({ initial, editingID, services, outbounds, t, onClose, onApply }: RoutingRuleDialogProps) {
  const [value, setValue] = useState<RoutingRule>(() => cloneRule(initial))
  const [sourceIPs, setSourceIPs] = useState(initial.source_ips.join(", "))
  const [destinationIPs, setDestinationIPs] = useState(initial.destination_ips.join(", "))
  const [domains, setDomains] = useState(initial.domains.join(", "))
  const [users, setUsers] = useState(initial.users.join(", "))
  const [attributes, setAttributes] = useState<AttributeEntry[]>(() => Object.entries(initial.attributes).map(([key, item]) => ({ key, value: item })))
  const [error, setError] = useState("")

  function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (attributes.some((item) => item.key.trim() === "" || item.value.trim() === "")) {
      setError(t("Complete or remove every attribute row."))
      return
    }
    const candidate: RoutingRule = {
      ...value,
      display_name: value.display_name.trim(),
      source_ips: csv(sourceIPs),
      source_port: normalizePorts(value.source_port),
      vless_route: normalizePorts(value.vless_route),
      destination_ips: csv(destinationIPs),
      domains: csv(domains),
      users: csv(users),
      destination_port: normalizePorts(value.destination_port),
      attributes: Object.fromEntries(attributes.map((item) => [item.key.trim(), item.value.trim()])),
    }
    if (!hasMatchField(candidate)) {
      setError(t("A routing rule needs at least one match field."))
      return
    }
    if (candidate.display_name === "") candidate.display_name = suggestedRuleName(candidate, t)
    setError("")
    if (!event.currentTarget.reportValidity()) return
    onApply(candidate)
  }

  function toggleProtocol(protocol: RoutingProtocol, checked: boolean) {
    setValue((current) => {
      const selected = new Set(current.protocols)
      if (checked) selected.add(protocol); else selected.delete(protocol)
      return { ...current, protocols: protocols.filter((item) => selected.has(item)) }
    })
  }

  function toggleInbound(tag: string, checked: boolean) {
    setValue((current) => {
      const selected = new Set(current.inbound_tags)
      if (checked) selected.add(tag); else selected.delete(tag)
      return { ...current, inbound_tags: services.map((service) => service.service_id).filter((item) => selected.has(item)) }
    })
  }

  return (
    <Dialog open onOpenChange={(open) => { if (!open) onClose() }}>
      <DialogContent className="max-h-[calc(100vh-2rem)] overflow-y-auto sm:max-w-3xl lg:max-w-4xl" closeLabel={t("Close")}>
        <form className="grid gap-5" onSubmit={submit}>
          <DialogHeader>
            <DialogTitle>{t(editingID == null ? "Add routing rule" : "Edit routing rule")}</DialogTitle>
            <DialogDescription>{t("Configure an Xray field routing rule")}</DialogDescription>
          </DialogHeader>

          <div className="grid gap-4">
            <div className="flex items-center justify-between gap-4 rounded-lg border px-4 py-3">
              <Label htmlFor="routing-enabled">{t("Enabled")}</Label>
              <Switch id="routing-enabled" checked={value.enabled} onCheckedChange={(enabled) => setValue((current) => ({ ...current, enabled }))} />
            </div>
            <TextField id="routing-name" label={t("Remark (optional)")} value={value.display_name} placeholder={t("For example: Block BitTorrent")} maxLength={100} onChange={(display_name) => setValue((current) => ({ ...current, display_name }))} />

            <TextField id="routing-source-ip" label={t("Source IP")} help={t("Comma-separated source IP addresses, CIDRs, or geoip expressions")} value={sourceIPs} placeholder="0.0.0.0/8, fc00::/7, geoip:cn" onChange={setSourceIPs} />
            <TextField id="routing-source-port" label={t("Source port")} help={t("Comma-separated ports and ranges")} value={value.source_port} placeholder="53,443,1000-2000" onChange={(source_port) => setValue((current) => ({ ...current, source_port }))} />
            <TextField id="routing-vless-route" label={t("VLESS route")} help={t("Match the VLESS route port metadata")} value={value.vless_route} placeholder="53,443,1000-2000" onChange={(vless_route) => setValue((current) => ({ ...current, vless_route }))} />

            <SelectField id="routing-network" label={t("Network")} help={t("Match the transport network")} value={value.network || "any"} onValueChange={(network) => setValue((current) => ({ ...current, network: network === "any" ? "" : network as RoutingRule["network"] }))}>
              <SelectItem value="any">{t("Any")}</SelectItem>
              <SelectItem value="tcp">TCP</SelectItem>
              <SelectItem value="udp">UDP</SelectItem>
              <SelectItem value="tcp,udp">TCP, UDP</SelectItem>
            </SelectField>

            <CheckboxField label={t("Protocol")} help={t("Match a protocol detected by sniffing")} emptyLabel={t("Any")}>
              {protocols.map((protocol) => (
                <CheckboxOption key={protocol} label={protocol === "bittorrent" ? "BitTorrent" : protocol.toUpperCase()} checked={value.protocols.includes(protocol)} onCheckedChange={(checked) => toggleProtocol(protocol, checked)} />
              ))}
            </CheckboxField>

            <div className="grid gap-2">
              <div className="flex items-center justify-between gap-3">
                <FieldLabel label={t("Attributes")} help={t("HTTP attribute names and regular expressions; all configured attributes must match")} />
                <Button type="button" variant="outline" size="sm" onClick={() => setAttributes((current) => [...current, { key: "", value: "" }])}><Plus />{t("Add")}</Button>
              </div>
              {attributes.length === 0 ? <p className="text-sm text-muted-foreground">{t("Any")}</p> : (
                <div className="grid gap-2">
                  {attributes.map((item, index) => (
                    <div key={index} className="grid grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto] gap-2">
                      <Input aria-label={t("Attribute name")} value={item.key} placeholder={t("Attribute name")} onChange={(event) => setAttributes((current) => current.map((entry, itemIndex) => itemIndex === index ? { ...entry, key: event.target.value } : entry))} />
                      <Input aria-label={t("Regular expression")} value={item.value} placeholder={t("Regular expression")} onChange={(event) => setAttributes((current) => current.map((entry, itemIndex) => itemIndex === index ? { ...entry, value: event.target.value } : entry))} />
                      <Button type="button" variant="outline" size="icon" aria-label={t("Remove attribute")} onClick={() => setAttributes((current) => current.filter((_, itemIndex) => itemIndex !== index))}><Trash2 /></Button>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <TextField id="routing-destination-ip" label={t("Destination IP")} help={t("Comma-separated destination IP addresses, CIDRs, or geoip expressions")} value={destinationIPs} placeholder="0.0.0.0/8, fc00::/7, geoip:private" onChange={setDestinationIPs} />
            <TextField id="routing-domain" label={t("Domain")} help={t("Comma-separated Xray domain expressions")} value={domains} placeholder="domain:google.com, geosite:cn" onChange={setDomains} />
            <TextField id="routing-user" label={t("User")} help={t("Comma-separated Xray user email values")} value={users} placeholder="user@example.com" onChange={setUsers} />
            <TextField id="routing-destination-port" label={t("Destination port")} help={t("Comma-separated ports and ranges")} value={value.destination_port} placeholder="53,443,1000-2000" onChange={(destination_port) => setValue((current) => ({ ...current, destination_port }))} />

            <CheckboxField label={t("Inbounds")} help={t("Leave all unselected to match any inbound")} emptyLabel={t("Any inbound")}>
              {services.map((service) => (
                <CheckboxOption key={service.service_id} label={service.display_name} checked={value.inbound_tags.includes(service.service_id)} onCheckedChange={(checked) => toggleInbound(service.service_id, checked)} />
              ))}
            </CheckboxField>

            <SelectField id="routing-outbound" label={t("Outbound")} value={value.outbound_tag} onValueChange={(outbound_tag) => setValue((current) => ({ ...current, outbound_tag }))}>
              {outbounds.map((outbound) => <SelectItem key={outbound.tag} value={outbound.tag}>{outbound.tag} ({outbound.protocol})</SelectItem>)}
            </SelectField>
          </div>

          {error ? <p role="alert" className="text-sm text-destructive">{error}</p> : null}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>{t("Cancel")}</Button>
            <Button type="submit">{t(editingID == null ? "Add rule" : "Apply rule")}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function TextField({ id, label, help, value, placeholder, maxLength = 8192, onChange }: {
  id: string
  label: string
  help?: string
  value: string
  placeholder?: string
  maxLength?: number
  onChange: (value: string) => void
}) {
  return (
    <div className="grid gap-2 sm:grid-cols-[11rem_minmax(0,1fr)] sm:items-center">
      <FieldLabel htmlFor={id} label={label} help={help} />
      <Input id={id} value={value} maxLength={maxLength} placeholder={placeholder} onChange={(event) => onChange(event.target.value)} />
    </div>
  )
}

function SelectField({ id, label, help, value, onValueChange, children }: {
  id: string
  label: string
  help?: string
  value: string
  onValueChange: (value: string) => void
  children: React.ReactNode
}) {
  return (
    <div className="grid gap-2 sm:grid-cols-[11rem_minmax(0,1fr)] sm:items-center">
      <FieldLabel htmlFor={id} label={label} help={help} />
      <Select value={value} onValueChange={onValueChange}>
        <SelectTrigger id={id} className="w-full"><SelectValue /></SelectTrigger>
        <SelectContent>{children}</SelectContent>
      </Select>
    </div>
  )
}

function CheckboxField({ label, help, emptyLabel, children }: { label: string; help?: string; emptyLabel: string; children: React.ReactNode }) {
  const items = Array.isArray(children) ? children : [children]
  return (
    <div className="grid gap-2 sm:grid-cols-[11rem_minmax(0,1fr)] sm:items-start">
      <FieldLabel label={label} help={help} className="sm:pt-2.5" />
      <div className="flex min-h-10 flex-wrap items-center gap-2 rounded-md border p-2">
        {items.length === 0 ? <span className="px-1 text-sm text-muted-foreground">{emptyLabel}</span> : children}
      </div>
    </div>
  )
}

function CheckboxOption({ label, checked, onCheckedChange }: { label: string; checked: boolean; onCheckedChange: (checked: boolean) => void }) {
  return (
    <Label className="cursor-pointer rounded-md border px-3 py-2 transition-colors hover:bg-muted/40">
      <Checkbox checked={checked} onCheckedChange={(value) => onCheckedChange(value === true)} />
      {label}
    </Label>
  )
}

function FieldLabel({ htmlFor, label, help, className = "" }: { htmlFor?: string; label: string; help?: string; className?: string }) {
  return (
    <div className={`flex items-center gap-1.5 ${className}`}>
      <Label htmlFor={htmlFor}>{label}</Label>
      {help ? (
        <Tooltip>
          <TooltipTrigger asChild><button type="button" className="cursor-help text-muted-foreground" aria-label={help}><HelpCircle className="size-4" /></button></TooltipTrigger>
          <TooltipContent className="max-w-72">{help}</TooltipContent>
        </Tooltip>
      ) : null}
    </div>
  )
}

function cloneRule(value: RoutingRule): RoutingRule {
  return {
    ...value,
    source_ips: [...value.source_ips],
    protocols: [...value.protocols],
    attributes: { ...value.attributes },
    destination_ips: [...value.destination_ips],
    domains: [...value.domains],
    users: [...value.users],
    inbound_tags: [...value.inbound_tags],
  }
}

function csv(value: string): string[] {
  return [...new Set(value.split(",").map((item) => item.trim()).filter(Boolean))]
}

function normalizePorts(value: string): string {
  return value.split(",").map((item) => item.trim()).filter(Boolean).join(",")
}

function hasMatchField(value: RoutingRule): boolean {
  return value.source_ips.length > 0 || value.source_port !== "" || value.vless_route !== "" || value.network !== "" ||
    value.protocols.length > 0 || Object.keys(value.attributes).length > 0 || value.destination_ips.length > 0 ||
    value.domains.length > 0 || value.users.length > 0 || value.destination_port !== "" || value.inbound_tags.length > 0
}

function suggestedRuleName(value: RoutingRule, t: Translator): string {
  const target = value.domains[0] ?? value.destination_ips[0] ?? value.protocols[0] ?? value.inbound_tags[0] ?? t("Custom traffic")
  return `${value.outbound_tag} ${target}`
}
