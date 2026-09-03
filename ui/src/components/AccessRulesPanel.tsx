import { Plus } from "lucide-react"

import { EntityActions } from "@/components/EntityActions"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import type { Translator } from "@/i18n"
import type { AccessRule, EgressLine } from "@/types"

export function AccessRulesPanel({ rules, lines, busy, t, onAdd, onEdit, onDelete, onMove, onToggle }: {
  rules: AccessRule[]; lines: EgressLine[]; busy: boolean; t: Translator
  onAdd: () => void; onEdit: (rule: AccessRule) => void; onDelete: (rule: AccessRule) => void
  onMove: (index: number, offset: number) => void; onToggle: (rule: AccessRule, enabled: boolean) => void
}) {
  return (
    <div className="grid min-w-0 gap-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"><div><h2 className="font-semibold">{t("Access rules")}</h2><p className="text-sm text-muted-foreground">{t("Rules are evaluated from top to bottom; the first match wins")}</p></div><Button type="button" disabled={busy} onClick={onAdd}><Plus />{t("Add rule")}</Button></div>
      <div className="divide-y rounded-lg border">
        {rules.length === 0 ? <p className="p-6 text-sm text-muted-foreground">{t("No access rules configured")}</p> : rules.map((rule, index) => {
          const destination = rule.domains[0] ?? rule.destination_ips[0] ?? (rule.destination_port ? `${t("Port")} ${rule.destination_port}` : t("Any destination"))
          const action = rule.action === "block" ? t("Block") : lines.find((line) => line.line_id === rule.egress_line_id)?.display_name ?? rule.egress_line_id
          return (
            <article key={rule.rule_id} className="grid gap-4 p-4 lg:grid-cols-[auto_minmax(0,1fr)_minmax(12rem,0.7fr)_auto] lg:items-center">
              <Switch aria-label={t("Toggle rule {name}", { name: rule.display_name })} checked={rule.enabled} disabled={busy} onCheckedChange={(enabled) => onToggle(rule, enabled)} />
              <div className="min-w-0"><strong className="block truncate text-sm">{rule.display_name}</strong><p className="mt-1 truncate text-sm text-muted-foreground">{destination}</p></div>
              <div className="flex flex-wrap items-center gap-2"><Badge variant={rule.action === "block" ? "destructive" : "secondary"}>{action}</Badge><span className="text-sm text-muted-foreground">{matchCount(rule)} {t("conditions")}</span></div>
              <EntityActions busy={busy} index={index} count={rules.length} t={t} onMove={(offset) => onMove(index, offset)} onEdit={() => onEdit(rule)} onDelete={() => onDelete(rule)} />
            </article>
          )
        })}
      </div>
    </div>
  )
}

function matchCount(rule: AccessRule): number {
  return [rule.source_ips, rule.protocols, rule.destination_ips, rule.domains, rule.authorization_ids, rule.service_ids].filter((value) => value.length > 0).length + (rule.network ? 1 : 0) + (rule.destination_port ? 1 : 0)
}
