const API = typeof window === "undefined" ? (process.env.API_URL ?? "http://backend:8000") : "/api";
export type RecordValue = Record<string, unknown>;

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = "ApiError";
  }
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
    cache: "no-store",
  });
  if (!response.ok) {
    const body = await response.text();
    let detail = body;
    try {
      const parsed = JSON.parse(body) as { detail?: unknown };
      if (typeof parsed.detail === "string") detail = parsed.detail;
    } catch {
      // Upstream did not return JSON; retain its readable response text.
    }
    throw new ApiError(response.status, detail || `Request failed with status ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export function errorMessage(error: unknown, context: string): string {
  if (error instanceof ApiError) return `${context}: ${error.message}`;
  if (error instanceof Error) return `${context}: ${error.message}`;
  return context;
}

export function displayValue(value: unknown, fallback = "Unknown"): string {
  if (value === null || value === undefined || value === "") return fallback;
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return value.length ? value.map((item) => displayValue(item)).join(", ") : "None";
  return fallback;
}
