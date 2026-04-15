const API_BASE_URL =
  (import.meta.env.VITE_API_BASE_URL as string | undefined)?.replace(/\/$/, "") ??
  "http://127.0.0.1:8000";

type ApiRequestInit = Omit<RequestInit, "headers"> & {
  headers?: HeadersInit;
};

function buildUrl(path: string): string {
  return `${API_BASE_URL}${path.startsWith("/") ? path : `/${path}`}`;
}

export async function fetchJson<T>(path: string, init?: ApiRequestInit): Promise<T> {
  const response = await fetch(buildUrl(path), init);
  if (response.ok) {
    return (await response.json()) as T;
  }

  const text = await response.text();
  throw new Error(`API request failed (${response.status}) ${path}: ${text}`);
}

export async function postJson<TResponse, TBody>(path: string, body: TBody): Promise<TResponse> {
  return fetchJson<TResponse>(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}
