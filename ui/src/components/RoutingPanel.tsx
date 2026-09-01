import { ArrowRight, LockKeyhole, Plus } from "lucide-react"

import { EmptyList } from "@/components/EmptyList"
import { EntityActions } from "@/components/EntityActions"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import type { Translator } from "@/i18n"
import { inboundNames, routingCriteria, systemRoutingProtections, type RoutingCriterion } from "@/routingPresentation"
import type { ProxyService, RoutingRule } from "@/types"

interface RoutingPanelProps {
  services: ProxyService[]
  rules: RoutingRule[]
  busy: boolean
  t: Translator
  onAdd: () => void
  onEdit: (rule: RoutingRule) => void
  onDelete: (rule: RoutingRule) => void
  onMove: (index: number, offset: number) => void
  onToggle: (rule: RoutingRule, enabled: boolean) => void
}

export function RoutingPanel({ services, rules, busy, t, onAdd, onEdit, onDelete, onMove, onToggle }: RoutingPanelProps) {
  const protections = systemRoutingProtections(services)
  return (
    <div className="grid min-w-0 gap-6">
      <section className="grid min-w-0 gap-4" aria-labelledby="system-routing-title">
        <div className="grid min-w-0 gap-1">
          <h2 id="system-routing-title" className="font-semibold">{t("System routing rules")}</h2>
          <p className="break-words text-sm text-muted-foreground">{t("Relayward maintains these protections for enabled REALITY inbounds")}</p>
        </div>
        {protections.length === 0 ? (
          <EmptyList title={t("No system routing rules")} detail={t("Enable a VLESS REALITY inbound to generate its protected tunnel routes")} />
        ) : (
          <div className="grid min-w-0 gap-3">
            {protections.flatMap((protection) => [
              <SystemRuleCard key={`${protection.serviceID}-allow`} indexLabel={t("System")} source={t("{name} REALITY fallback", { name: protection.serviceName })} outbound="direct" criterion={{ kind: "sni", values: [protection.sni] }} t={t} />,
              <SystemRuleCard key={`${protection.serviceID}-block`} indexLabel={t("System")} source={t("{name} REALITY fallback", { name: protection.serviceName })} outbound="blocked" criterion={{ kind: "other_sni", values: [t("All remaining values")] }} t={t} />,
            ])}
          </div>
        )}
      </section>

      <section className="grid min-w-0 gap-4 border-t pt-6" aria-labelledby="custom-routing-title">
        <div className="flex min-w-0 flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="grid min-w-0 gap-1">
            <h2 id="custom-routing-title" className="font-semibold">{t("Custom routing rules")}</h2>
            <p className="break-words text-sm text-muted-foreground">{t("The first enabled rule whose populated conditions all match is applied")}</p>
          </div>
          <Button type="button" disabled={busy} onClick={onAdd}><Plus />{t("Add rule")}</Button>
        </div>

        {rules.length === 0 ? (
          <EmptyList title={t("No custom routing rules")} detail={t("Unmatched traffic uses the direct outbound")} />
        ) : (
          <div className="grid min-w-0 gap-3">
            {rules.map((rule, index) => (
              <article
                key={rule.rule_id}
                className={`min-w-0 cursor-pointer rounded-lg border p-4 transition-colors hover:border-primary/40 hover:bg-muted/20 ${rule.enabled ? "" : "opacity-60"}`}
                onClick={() => { if (!busy) onEdit(rule) }}
              >
                <div className="flex min-w-0 flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
                  <div className="flex min-w-0 flex-wrap items-center gap-2">
                    <Badge variant="outline">#{index + 1}</Badge>
                    <strong className="min-w-0 break-words text-sm font-medium">{rule.display_name}</strong>
                  </div>
                  <div className="flex shrink-0 items-center justify-between gap-3 sm:justify-end" onClick={(event) => event.stopPropagation()}>
                    <Switch checked={rule.enabled} disabled={busy} aria-label={t("Toggle rule {name}", { name: rule.display_name })} onCheckedChange={(enabled) => onToggle(rule, enabled)} />
                    <EntityActions busy={busy} index={index} count={rules.length} t={t} onMove={(offset) => onMove(index, offset)} onEdit={() => onEdit(rule)} onDelete={() => onDelete(rule)} />
                  </div>
                </div>
                <RuleFlow source={summarize(inboundNames(rule, services), t("Any inbound"), t)} outbound={rule.outbound_tag} t={t} />
                <Criteria criteria={routingCriteria(rule)} t={t} />
              </article>
            ))}
          </div>
        )}
      </section>
    </div>
  )
}

function SystemRuleCard({ indexLabel, source, outbound, criterion, t }: { indexLabel: string; source: string; outbound: string; criterion: RoutingCriterion; t: Translator }) {
  return (
    <article className="min-w-0 rounded-lg border p-4">
      <div className="flex min-w-0 flex-wrap items-center gap-2">
        <LockKeyhole className="size-4 shrink-0 text-primary" aria-hidden="true" />
        <Badge variant="outline">{indexLabel}</Badge>
        <Badge variant="secondary">{t("Automatically managed")}</Badge>
      </div>
      <RuleFlow source={source} outbound={outbound} t={t} />
      <Criteria criteria={[criterion]} t={t} />
    </article>
  )
}

function RuleFlow({ source, outbound, t }: { source: string; outbound: string; t: Translator }) {
  return (
    <div className="mt-4 grid min-w-0 gap-3 rounded-md border bg-muted/20 p-3 sm:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] sm:items-center">
      <div className="grid min-w-0 gap-1">
        <span className="text-xs text-muted-foreground">{t("Inbounds")}</span>
        <span className="min-w-0 break-words text-sm font-medium">{source}</span>
      </div>
      <ArrowRight className="hidden size-4 text-muted-foreground sm:block" aria-hidden="true" />
      <div className="grid min-w-0 gap-1 sm:justify-items-end">
        <span className="text-xs text-muted-foreground">{t("Outbound")}</span>
        <Badge className="w-fit" variant={outbound === "blocked" ? "destructive" : "secondary"}>{outbound}</Badge>
      </div>
    </div>
  )
}

function Criteria({ criteria, t }: { criteria: RoutingCriterion[]; t: Translator }) {
  if (criteria.length === 0) return null
  return (
    <div className="mt-3 flex min-w-0 flex-wrap gap-2">
      {criteria.map((criterion) => {
        const full = criterion.values.join(", ")
        return (
          <Tooltip key={`${criterion.kind}-${full}`}>
            <TooltipTrigger asChild>
              <Badge variant="outline" className="max-w-full cursor-default gap-1 whitespace-normal text-left">
                <span className="text-muted-foreground">{t(criterionLabel(criterion.kind))}</span>
                <span className="min-w-0 break-all">{summarize(criterion.values, "", t)}</span>
              </Badge>
            </TooltipTrigger>
            <TooltipContent className="max-w-80 break-all">{full}</TooltipContent>
          </Tooltip>
        )
      })}
    </div>
  )
}

function criterionLabel(kind: string): string {
  switch (kind) {
    case "source_ips": return "Source IP"
    case "source_port": return "Source port"
    case "vless_route": return "VLESS route"
    case "network": return "Network"
    case "protocols": return "Protocol"
    case "attributes": return "Attributes"
    case "destination_ips": return "Destination IP"
    case "domains": return "Domain"
    case "users": return "User"
    case "destination_port": return "Destination port"
    case "sni": return "Destination SNI"
    default: return "Other SNI"
  }
}

function summarize(values: string[], empty: string, t: Translator): string {
  if (values.length === 0) return empty
  if (values.length <= 2) return values.join(", ")
  return `${values.slice(0, 2).join(", ")}${t(" and {count} more", { count: values.length - 2 })}`
}
