import { Plus } from "lucide-react"

import { EmptyList } from "@/components/EmptyList"
import { EntityActions } from "@/components/EntityActions"
import { StatusBadge } from "@/components/StatusBadge"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import type { Translator } from "@/i18n"
import type { RoutingRule } from "@/types"

interface RoutingPanelProps {
  rules: RoutingRule[]
  busy: boolean
  t: Translator
  onAdd: () => void
  onEdit: (rule: RoutingRule) => void
  onDelete: (rule: RoutingRule) => void
  onMove: (index: number, offset: number) => void
}

export function RoutingPanel({ rules, busy, t, onAdd, onEdit, onDelete, onMove }: RoutingPanelProps) {
  return (
    <div className="grid min-w-0 gap-6">
      <div className="flex min-w-0 flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="grid min-w-0 gap-1">
          <h2 className="font-semibold">{t("Static routing rules")}</h2>
          <p className="break-words text-sm text-muted-foreground">{t("Rules are evaluated from top to bottom after Relayward dynamic blocks")}</p>
        </div>
        <Button type="button" disabled={busy} onClick={onAdd}><Plus />{t("Add rule")}</Button>
      </div>

      {rules.length === 0 ? (
        <EmptyList title={t("No static routing rules")} detail={t("Unmatched traffic uses the direct outbound")} />
      ) : (
        <div className="min-w-0 divide-y rounded-lg border">
          {rules.map((rule, index) => (
            <article key={rule.rule_id} className="grid min-w-0 gap-4 px-4 py-4 md:grid-cols-[minmax(0,1fr)_minmax(15rem,0.8fr)_auto] md:items-center">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <strong className="truncate text-sm font-medium">{rule.display_name}</strong>
                  <StatusBadge enabled={rule.enabled} t={t} />
                  <Badge variant={rule.action === "blocked" ? "destructive" : "secondary"}>{t(rule.action === "blocked" ? "Block" : "Direct")}</Badge>
                </div>
                <p className="mt-1 truncate font-mono text-xs text-muted-foreground">{rule.rule_id}</p>
              </div>
              <p className="min-w-0 break-words text-sm text-muted-foreground">
                {t("Domains {domains} · CIDRs {cidrs} · Protocols {protocols}", {
                  domains: rule.domains.length,
                  cidrs: rule.ip_cidrs.length,
                  protocols: rule.protocols.length,
                })}
              </p>
              <EntityActions busy={busy} index={index} count={rules.length} t={t} onMove={(offset) => onMove(index, offset)} onEdit={() => onEdit(rule)} onDelete={() => onDelete(rule)} />
            </article>
          ))}
        </div>
      )}
    </div>
  )
}
