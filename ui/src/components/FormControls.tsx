import { CircleHelp } from "lucide-react"
import type { ReactNode } from "react"

import { Label } from "@/components/ui/label"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"

export function FormRow({ id, label, help, children, align = "center" }: {
  id?: string; label: string; help?: string; children: ReactNode; align?: "center" | "start"
}) {
  return (
    <div className={`grid gap-2 sm:grid-cols-[12rem_minmax(0,1fr)] ${align === "center" ? "sm:items-center" : "sm:items-start"}`}>
      <div className={`flex items-center gap-1.5 ${align === "start" ? "sm:pt-2.5" : ""}`}>
        <Label htmlFor={id}>{label}</Label>
        {help ? (
          <Tooltip>
            <TooltipTrigger asChild><button type="button" className="text-muted-foreground" aria-label={help}><CircleHelp className="size-4" /></button></TooltipTrigger>
            <TooltipContent className="max-w-72">{help}</TooltipContent>
          </Tooltip>
        ) : null}
      </div>
      <div className="min-w-0">{children}</div>
    </div>
  )
}
