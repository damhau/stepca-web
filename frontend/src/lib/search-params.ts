// Readers for URL search parameters: whatever is in the URL, a page gets a valid value or none

export function int(value: unknown, min = 1, max = Number.MAX_SAFE_INTEGER): number | undefined {
  const number = typeof value === "number" ? value : typeof value === "string" ? Number(value) : NaN
  return Number.isInteger(number) && number >= min && number <= max ? number : undefined
}

export function text(value: unknown, max = 200): string | undefined {
  return typeof value === "string" && value.trim() !== "" ? value.slice(0, max) : undefined
}

export function oneOf<T extends string>(value: unknown, options: readonly T[]): T | undefined {
  return options.find((option) => option === value)
}

export type ListSearch = { page?: number; per_page?: number; q?: string }

export function listSearch(search: Record<string, unknown>): ListSearch {
  return { page: int(search.page), per_page: int(search.per_page, 1, 500), q: text(search.q) }
}
