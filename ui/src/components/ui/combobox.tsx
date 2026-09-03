import * as React from "react"
import { CheckIcon, ChevronsUpDownIcon } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from "@/components/ui/command"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { cn } from "@/lib/utils"

export interface ComboboxOption {
  value: string
  label: string
  keywords?: string[]
}

interface ComboboxProps {
  value: string
  onValueChange: (value: string) => void
  options: ComboboxOption[]
  searchPlaceholder: string
  emptyText: string
  placeholder?: string
  disabled?: boolean
  required?: boolean
  id?: string
  className?: string
  "aria-label"?: string
  "aria-labelledby"?: string
}

function Combobox({ value, onValueChange, options, searchPlaceholder, emptyText, placeholder, disabled = false,
  required = false, id, className, ...ariaProps }: ComboboxProps) {
  const [open, setOpen] = React.useState(false)
  const [search, setSearch] = React.useState("")
  const [portalled, setPortalled] = React.useState(true)
  const triggerRef = React.useRef<HTMLButtonElement>(null)
  const searchRef = React.useRef<HTMLInputElement>(null)
  const suppressFocusOpen = React.useRef(false)
  const returnFocusOnClose = React.useRef(false)
  const selected = options.find((option) => option.value === value)
  const normalizedSearch = search.trim().toLocaleLowerCase()
  const filtered = normalizedSearch === "" ? options : options.filter((option) =>
    [option.value, option.label, ...(option.keywords ?? [])].some((candidate) => candidate.toLocaleLowerCase().includes(normalizedSearch)))

  function changeOpen(next: boolean) {
    if (next) setPortalled(triggerRef.current?.closest("[data-slot=dialog-content]") === null)
    else setSearch("")
    setOpen(next)
  }

  function select(next: string) {
    returnFocusOnClose.current = true
    onValueChange(next)
    changeOpen(false)
  }

  return (
    <Popover open={open} onOpenChange={changeOpen}>
      <PopoverTrigger asChild>
        <Button
          ref={triggerRef}
          id={id}
          className={cn("min-w-0 w-full justify-between overflow-hidden font-normal", className)}
          variant="outline"
          role="combobox"
          aria-expanded={open}
          aria-required={required || undefined}
          disabled={disabled}
          onFocus={() => {
            if (suppressFocusOpen.current) { suppressFocusOpen.current = false; return }
            changeOpen(true)
          }}
          onClick={(event) => { event.preventDefault(); changeOpen(true) }}
          type="button"
          {...ariaProps}
        >
          <span className={cn("block min-w-0 flex-1 truncate text-left", !selected && value === "" && "text-muted-foreground")}>{selected?.label ?? (value || placeholder)}</span>
          <ChevronsUpDownIcon className="size-4 shrink-0 opacity-50" />
        </Button>
      </PopoverTrigger>
      <PopoverContent
        align="start"
        className="w-[var(--radix-popover-trigger-width)] min-w-56 p-0"
        portalled={portalled}
        onOpenAutoFocus={(event) => { event.preventDefault(); window.requestAnimationFrame(() => searchRef.current?.focus()) }}
        onEscapeKeyDown={(event) => {
          event.preventDefault()
          event.stopPropagation()
          returnFocusOnClose.current = true
          window.queueMicrotask(() => changeOpen(false))
        }}
        onCloseAutoFocus={(event) => {
          event.preventDefault()
          if (!returnFocusOnClose.current) return
          returnFocusOnClose.current = false
          suppressFocusOpen.current = true
          triggerRef.current?.focus({ preventScroll: true })
        }}
      >
        <Command shouldFilter={false}>
          <CommandInput ref={searchRef} value={search} onValueChange={setSearch} placeholder={searchPlaceholder} />
          <CommandList>
            <CommandEmpty>{emptyText}</CommandEmpty>
            <CommandGroup>{filtered.map((option) => (
              <CommandItem key={option.value} value={option.value} keywords={[option.label, ...(option.keywords ?? [])]} onSelect={() => select(option.value)}>
                <CheckIcon className={cn("size-4", value === option.value ? "opacity-100" : "opacity-0")} />
                <span className="truncate">{option.label}</span>
              </CommandItem>
            ))}</CommandGroup>
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  )
}

export { Combobox }
