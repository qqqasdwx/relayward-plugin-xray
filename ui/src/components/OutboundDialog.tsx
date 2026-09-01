import { Plus, Trash2 } from "lucide-react"
import { useState } from "react"

import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { nextOutboundDefaults } from "@/configuration"
import type { Translator } from "@/i18n"
import type { FreedomFinalRule, FreedomNoise, OutboundDomainStrategy, OutboundProtocol, XrayOutbound } from "@/types"

const domainStrategies: OutboundDomainStrategy[] = [
  "AsIs", "UseIP", "UseIPv4", "UseIPv6", "UseIPv6v4", "UseIPv4v6",
  "ForceIP", "ForceIPv6v4", "ForceIPv6", "ForceIPv4v6", "ForceIPv4",
]

interface OutboundDialogProps {
  initial: XrayOutbound
  editingTag: string | null
  outbounds: XrayOutbound[]
  t: Translator
  onClose: () => void
  onApply: (outbound: XrayOutbound) => void
}

export function OutboundDialog({ initial, editingTag, outbounds, t, onClose, onApply }: OutboundDialogProps) {
  const [value, setValue] = useState<XrayOutbound>(() => cloneOutbound(initial))
  const [duplicate, setDuplicate] = useState(false)
  const required = editingTag === "direct" || editingTag === "blocked"

  function changeProtocol(protocol: OutboundProtocol) {
    setValue({ ...nextOutboundDefaults(outbounds, protocol), tag: value.tag })
  }

  function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const candidate = normalizeOutbound(value)
    const duplicateTag = outbounds.some((outbound) => outbound.tag === candidate.tag && outbound.tag !== editingTag)
    setDuplicate(duplicateTag)
    if (duplicateTag || !event.currentTarget.reportValidity()) return
    onApply(candidate)
  }

  return (
    <Dialog open onOpenChange={(open) => { if (!open) onClose() }}>
      <DialogContent className="max-h-[calc(100vh-2rem)] overflow-y-auto sm:max-w-3xl lg:max-w-4xl" closeLabel={t("Close")}>
        <form className="grid gap-6" onSubmit={submit}>
          <DialogHeader>
            <DialogTitle>{t(editingTag == null ? "Add outbound" : "Edit outbound")}</DialogTitle>
            <DialogDescription>{t("Configure an Xray outbound")}</DialogDescription>
          </DialogHeader>

          <section className="grid gap-4" aria-labelledby="outbound-identity-title">
            <h3 id="outbound-identity-title" className="text-sm font-semibold">{t("Identity")}</h3>
            <FormRow id="outbound-tag" label={t("Outbound tag")}>
              <div className="grid gap-1.5">
                <Input id="outbound-tag" value={value.tag} maxLength={100} required disabled={required} aria-invalid={duplicate} onChange={(event) => { setValue({ ...value, tag: event.target.value }); setDuplicate(false) }} />
                {duplicate ? <p className="text-sm text-destructive">{t("Outbound tag already exists.")}</p> : null}
              </div>
            </FormRow>
            <FormRow id="outbound-protocol" label={t("Protocol")}>
              <Select value={value.protocol} disabled={required} onValueChange={(protocol: OutboundProtocol) => changeProtocol(protocol)}>
                <SelectTrigger id="outbound-protocol" className="w-full"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="freedom">freedom</SelectItem>
                  <SelectItem value="blackhole">blackhole</SelectItem>
                </SelectContent>
              </Select>
            </FormRow>
          </section>

          {value.protocol === "freedom" && value.freedom ? (
            <FreedomFields value={value} setValue={setValue} t={t} />
          ) : value.blackhole ? (
            <section className="grid gap-4 border-t pt-6" aria-labelledby="blackhole-settings-title">
              <h3 id="blackhole-settings-title" className="text-sm font-semibold">blackhole</h3>
              <FormRow id="blackhole-response" label={t("Response type")}>
                <Select value={value.blackhole.response_type || "empty"} onValueChange={(responseType) => setValue({ ...value, blackhole: { response_type: responseType === "empty" ? "" : responseType as "none" | "http" } })}>
                  <SelectTrigger id="blackhole-response" className="w-full"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="empty">{t("Silent drop")}</SelectItem>
                    <SelectItem value="none">none</SelectItem>
                    <SelectItem value="http">http</SelectItem>
                  </SelectContent>
                </Select>
              </FormRow>
            </section>
          ) : null}

          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>{t("Cancel")}</Button>
            <Button type="submit">{t("Apply outbound")}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function FreedomFields({ value, setValue, t }: { value: XrayOutbound; setValue: (value: XrayOutbound) => void; t: Translator }) {
  const freedom = value.freedom!
  function update(next: Partial<typeof freedom>) {
    setValue({ ...value, freedom: { ...freedom, ...next } })
  }
  function updateNoise(index: number, next: Partial<FreedomNoise>) {
    update({ noises: freedom.noises.map((noise, itemIndex) => itemIndex === index ? { ...noise, ...next } : noise) })
  }
  function updateFinalRule(index: number, next: Partial<FreedomFinalRule>) {
    update({ final_rules: freedom.final_rules.map((rule, itemIndex) => itemIndex === index ? { ...rule, ...next } : rule) })
  }
  return (
    <section className="grid gap-4 border-t pt-6" aria-labelledby="freedom-settings-title">
      <h3 id="freedom-settings-title" className="text-sm font-semibold">freedom</h3>
      <FormRow id="freedom-domain-strategy" label={t("Domain strategy")}>
        <Select value={freedom.domain_strategy || "none"} onValueChange={(domainStrategy) => update({ domain_strategy: domainStrategy === "none" ? "" : domainStrategy as OutboundDomainStrategy })}>
          <SelectTrigger id="freedom-domain-strategy" className="w-full"><SelectValue /></SelectTrigger>
          <SelectContent><SelectItem value="none">{t("None")}</SelectItem>{domainStrategies.map((strategy) => <SelectItem key={strategy} value={strategy}>{strategy}</SelectItem>)}</SelectContent>
        </Select>
      </FormRow>
      <FormRow id="freedom-redirect" label={t("Redirect")}><Input id="freedom-redirect" value={freedom.redirect} maxLength={512} onChange={(event) => update({ redirect: event.target.value })} /></FormRow>
      <FormRow id="freedom-user-level" label={t("User level")}><Input id="freedom-user-level" type="number" min={0} max={4294967295} value={freedom.user_level} onChange={(event) => update({ user_level: Number(event.target.value) })} /></FormRow>
      <FormRow id="freedom-proxy-protocol" label="PROXY Protocol">
        <Select value={String(freedom.proxy_protocol)} onValueChange={(proxyProtocol) => update({ proxy_protocol: Number(proxyProtocol) as 0 | 1 | 2 })}>
          <SelectTrigger id="freedom-proxy-protocol" className="w-full"><SelectValue /></SelectTrigger>
          <SelectContent><SelectItem value="0">{t("None")}</SelectItem><SelectItem value="1">v1</SelectItem><SelectItem value="2">v2</SelectItem></SelectContent>
        </Select>
      </FormRow>

      <div className="flex items-center justify-between gap-4 rounded-lg border px-4 py-3">
        <Label htmlFor="freedom-fragment">Fragment</Label>
        <Switch id="freedom-fragment" checked={freedom.fragment != null} onCheckedChange={(enabled) => update({ fragment: enabled ? { packets: "tlshello", length: "100-200", interval: "10-20", max_split: "300-400" } : undefined })} />
      </div>
      {freedom.fragment ? (
        <div className="grid gap-4 rounded-lg border p-4">
          <FormRow id="fragment-packets" label={t("Packets")}><Input id="fragment-packets" value={freedom.fragment.packets} onChange={(event) => update({ fragment: { ...freedom.fragment!, packets: event.target.value } })} /></FormRow>
          <FormRow id="fragment-length" label={t("Length")}><Input id="fragment-length" value={freedom.fragment.length} onChange={(event) => update({ fragment: { ...freedom.fragment!, length: event.target.value } })} /></FormRow>
          <FormRow id="fragment-interval" label={t("Interval")}><Input id="fragment-interval" value={freedom.fragment.interval} onChange={(event) => update({ fragment: { ...freedom.fragment!, interval: event.target.value } })} /></FormRow>
          <FormRow id="fragment-max-split" label={t("Maximum split")}><Input id="fragment-max-split" value={freedom.fragment.max_split} onChange={(event) => update({ fragment: { ...freedom.fragment!, max_split: event.target.value } })} /></FormRow>
        </div>
      ) : null}

      <CollectionHeader title={t("Noise")} count={freedom.noises.length} t={t} onAdd={() => update({ noises: [...freedom.noises, { type: "rand", packet: "10-20", delay: "10-16", apply_to: "ip" }] })} />
      {freedom.noises.map((noise, index) => (
        <div key={index} className="grid gap-4 rounded-lg border p-4">
          <CollectionTitle title={t("Noise {number}", { number: index + 1 })} t={t} onDelete={() => update({ noises: freedom.noises.filter((_, itemIndex) => itemIndex !== index) })} />
          <FormRow label={t("Type")}>
            <Select value={noise.type} onValueChange={(type: FreedomNoise["type"]) => updateNoise(index, { type })}><SelectTrigger className="w-full"><SelectValue /></SelectTrigger><SelectContent>{["rand", "str", "base64", "hex"].map((type) => <SelectItem key={type} value={type}>{type}</SelectItem>)}</SelectContent></Select>
          </FormRow>
          <FormRow label={t("Packet")}><Input value={noise.packet} required onChange={(event) => updateNoise(index, { packet: event.target.value })} /></FormRow>
          <FormRow label={t("Delay")}><Input value={noise.delay} required onChange={(event) => updateNoise(index, { delay: event.target.value })} /></FormRow>
          <FormRow label={t("Apply to")}>
            <Select value={noise.apply_to} onValueChange={(apply_to: FreedomNoise["apply_to"]) => updateNoise(index, { apply_to })}><SelectTrigger className="w-full"><SelectValue /></SelectTrigger><SelectContent>{["ip", "ipv4", "ipv6"].map((target) => <SelectItem key={target} value={target}>{target}</SelectItem>)}</SelectContent></Select>
          </FormRow>
        </div>
      ))}

      <CollectionHeader title={t("Final rules")} count={freedom.final_rules.length} t={t} onAdd={() => update({ final_rules: [...freedom.final_rules, { action: "allow", network: "", port: "", ips: [], block_delay: "" }] })} />
      {freedom.final_rules.map((rule, index) => (
        <div key={index} className="grid gap-4 rounded-lg border p-4">
          <CollectionTitle title={t("Rule {number}", { number: index + 1 })} t={t} onDelete={() => update({ final_rules: freedom.final_rules.filter((_, itemIndex) => itemIndex !== index) })} />
          <FormRow label={t("Action")}>
            <Select value={rule.action} onValueChange={(action: FreedomFinalRule["action"]) => updateFinalRule(index, { action, block_delay: action === "allow" ? "" : rule.block_delay })}><SelectTrigger className="w-full"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="allow">allow</SelectItem><SelectItem value="block">block</SelectItem></SelectContent></Select>
          </FormRow>
          <FormRow label={t("Network")}>
            <Select value={rule.network || "any"} onValueChange={(network) => updateFinalRule(index, { network: network === "any" ? "" : network as FreedomFinalRule["network"] })}><SelectTrigger className="w-full"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="any">{t("Any")}</SelectItem><SelectItem value="tcp">TCP</SelectItem><SelectItem value="udp">UDP</SelectItem><SelectItem value="tcp,udp">TCP, UDP</SelectItem></SelectContent></Select>
          </FormRow>
          <FormRow label={t("Port")}><Input value={rule.port} placeholder="80,443,1000-2000" onChange={(event) => updateFinalRule(index, { port: event.target.value })} /></FormRow>
          <FormRow label="IP / CIDR / geoip"><Input value={rule.ips.join(", ")} placeholder="10.0.0.0/8, geoip:private" onChange={(event) => updateFinalRule(index, { ips: csv(event.target.value) })} /></FormRow>
          {rule.action === "block" ? <FormRow label={t("Block delay")}><Input value={rule.block_delay} placeholder="5000-10000" onChange={(event) => updateFinalRule(index, { block_delay: event.target.value })} /></FormRow> : null}
        </div>
      ))}
    </section>
  )
}

function FormRow({ id, label, children }: { id?: string; label: string; children: React.ReactNode }) {
  return <div className="grid gap-2 sm:grid-cols-[11rem_minmax(0,1fr)] sm:items-center"><Label htmlFor={id}>{label}</Label><div className="min-w-0">{children}</div></div>
}

function CollectionHeader({ title, count, t, onAdd }: { title: string; count: number; t: Translator; onAdd: () => void }) {
  return <div className="flex items-center justify-between gap-3 border-t pt-6"><h4 className="text-sm font-semibold">{title} ({count})</h4><Button type="button" variant="outline" size="sm" onClick={onAdd}><Plus />{t("Add")}</Button></div>
}

function CollectionTitle({ title, t, onDelete }: { title: string; t: Translator; onDelete: () => void }) {
  return <div className="flex items-center justify-between gap-3"><strong className="text-sm">{title}</strong><Button type="button" variant="ghost" size="icon" aria-label={t("Delete")} className="text-destructive hover:text-destructive" onClick={onDelete}><Trash2 /></Button></div>
}

function cloneOutbound(value: XrayOutbound): XrayOutbound {
  return {
    ...value,
    freedom: value.freedom == null ? undefined : {
      ...value.freedom,
      fragment: value.freedom.fragment == null ? undefined : { ...value.freedom.fragment },
      noises: value.freedom.noises.map((noise) => ({ ...noise })),
      final_rules: value.freedom.final_rules.map((rule) => ({ ...rule, ips: [...rule.ips] })),
    },
    blackhole: value.blackhole == null ? undefined : { ...value.blackhole },
  }
}

function normalizeOutbound(value: XrayOutbound): XrayOutbound {
  const cloned = cloneOutbound(value)
  cloned.tag = cloned.tag.trim()
  if (cloned.freedom) {
    cloned.freedom.redirect = cloned.freedom.redirect.trim()
    if (cloned.freedom.fragment) {
      cloned.freedom.fragment = {
        packets: cloned.freedom.fragment.packets.trim(),
        length: cloned.freedom.fragment.length.trim(),
        interval: cloned.freedom.fragment.interval.trim(),
        max_split: cloned.freedom.fragment.max_split.trim(),
      }
      if (cloned.freedom.fragment.length === "" && cloned.freedom.fragment.interval === "" && cloned.freedom.fragment.max_split === "") {
        cloned.freedom.fragment = undefined
      }
    }
    cloned.freedom.noises = cloned.freedom.noises.map((noise) => ({ ...noise, packet: noise.packet.trim(), delay: noise.delay.trim() }))
    cloned.freedom.final_rules = cloned.freedom.final_rules.map((rule) => ({ ...rule, port: compactCSV(rule.port), block_delay: rule.block_delay.trim(), ips: rule.ips.map((item) => item.trim()).filter(Boolean) }))
  }
  return cloned
}

function csv(value: string): string[] {
  return [...new Set(value.split(",").map((item) => item.trim()).filter(Boolean))]
}

function compactCSV(value: string): string {
  return value.split(",").map((item) => item.trim()).filter(Boolean).join(",")
}
