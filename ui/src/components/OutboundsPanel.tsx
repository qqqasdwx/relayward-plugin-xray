import { Plus } from "lucide-react"

import { EntityActions } from "@/components/EntityActions"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import type { Translator } from "@/i18n"
import type { XrayOutbound } from "@/types"

interface OutboundsPanelProps {
  outbounds: XrayOutbound[]
  busy: boolean
  t: Translator
  onAdd: () => void
  onEdit: (outbound: XrayOutbound) => void
  onDelete: (outbound: XrayOutbound) => void
  onMove: (index: number, offset: number) => void
}

export function OutboundsPanel({ outbounds, busy, t, onAdd, onEdit, onDelete, onMove }: OutboundsPanelProps) {
  return (
    <div className="grid min-w-0 gap-6">
      <div className="flex min-w-0 flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="grid min-w-0 gap-1">
          <h2 className="font-semibold">{t("Outbounds")}</h2>
          <p className="break-words text-sm text-muted-foreground">{t("The first outbound handles traffic that does not match a routing rule")}</p>
        </div>
        <Button type="button" disabled={busy} onClick={onAdd}><Plus />{t("Add outbound")}</Button>
      </div>

      <div className="min-w-0 divide-y rounded-lg border">
        {outbounds.map((outbound, index) => {
          const required = outbound.tag === "direct" || outbound.tag === "blocked"
          return (
            <article key={outbound.tag} className="grid min-w-0 gap-4 px-4 py-4 md:grid-cols-[minmax(0,1fr)_minmax(15rem,0.8fr)_auto] md:items-center">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <strong className="truncate text-sm font-medium">{outbound.tag}</strong>
                  <Badge variant="secondary">{outbound.protocol}</Badge>
                  {index === 0 ? <Badge variant="outline">{t("Default")}</Badge> : null}
                  {required ? <Badge variant="outline">{t("Required")}</Badge> : null}
                </div>
              </div>
              <div className="grid min-w-0 gap-1 text-sm text-muted-foreground">
                {outbound.freedom ? (
                  <>
                    <span>{t("Domain strategy")}: {outbound.freedom.domain_strategy || t("None")}</span>
                    <span>{t("Final rules {count}", { count: outbound.freedom.final_rules.length })}</span>
                  </>
                ) : (
                  <span>{t("Response type")}: {outbound.blackhole?.response_type || t("Silent drop")}</span>
                )}
              </div>
              <EntityActions
                busy={busy}
                index={index}
                count={outbounds.length}
                t={t}
                onMove={(offset) => onMove(index, offset)}
                onEdit={() => onEdit(outbound)}
                onDelete={required ? undefined : () => onDelete(outbound)}
              />
            </article>
          )
        })}
      </div>
    </div>
  )
}
