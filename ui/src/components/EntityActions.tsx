import { ArrowDown, ArrowUp, Pencil, Trash2 } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import type { Translator } from "@/i18n"

interface EntityActionsProps {
  busy: boolean
  index?: number
  count?: number
  t: Translator
  onMove?: (offset: number) => void
  onEdit: () => void
  onDelete?: () => void
}

function Action({ label, disabled, destructive = false, onClick, children }: {
  label: string
  disabled: boolean
  destructive?: boolean
  onClick: () => void
  children: React.ReactNode
}) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          type="button"
          variant="ghost"
          size="icon"
          aria-label={label}
          disabled={disabled}
          onClick={onClick}
          className={destructive ? "text-destructive hover:text-destructive" : undefined}
        >
          {children}
        </Button>
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  )
}

export function EntityActions({ busy, index, count, t, onMove, onEdit, onDelete }: EntityActionsProps) {
  return (
    <div className="flex shrink-0 items-center justify-end gap-1">
      {onMove != null && index != null && count != null ? (
        <>
          <Action label={t("Move up")} disabled={busy || index === 0} onClick={() => onMove(-1)}>
            <ArrowUp />
          </Action>
          <Action label={t("Move down")} disabled={busy || index === count - 1} onClick={() => onMove(1)}>
            <ArrowDown />
          </Action>
        </>
      ) : null}
      <Action label={t("Edit")} disabled={busy} onClick={onEdit}>
        <Pencil />
      </Action>
      {onDelete != null ? (
        <Action label={t("Delete")} disabled={busy} destructive onClick={onDelete}>
          <Trash2 />
        </Action>
      ) : null}
    </div>
  )
}
