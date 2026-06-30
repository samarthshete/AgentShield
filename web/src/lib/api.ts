import { getApiBaseUrl, getApiToken } from "./settings";

type ApiRequestInit = Omit<RequestInit, "headers"> & {
  headers?: HeadersInit;
  auth?: boolean;
};

export class ApiError extends Error {
  status: number;
  path: string;
  body: string;

  constructor(message: string, status: number, path: string, body: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.path = path;
    this.body = body;
  }
}

function buildUrl(path: string): string {
  const baseUrl = getApiBaseUrl();
  return `${baseUrl}${path.startsWith("/") ? path : `/${path}`}`;
}

function buildHeaders(init?: ApiRequestInit): Headers {
  const headers = new Headers(init?.headers);
  const token = getApiToken();
  if ((init?.auth ?? true) && token && !headers.has("Authorization") && !headers.has("X-API-Key")) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  return headers;
}

export async function fetchJson<T>(path: string, init?: ApiRequestInit): Promise<T> {
  const requestInit = init ? { ...init } : {};
  delete requestInit.auth;
  delete requestInit.headers;
  const response = await fetch(buildUrl(path), {
    ...requestInit,
    headers: buildHeaders(init),
  });
  if (response.ok) {
    return (await response.json()) as T;
  }

  const text = await response.text();
  if (response.status === 401) {
    throw new ApiError("Unauthorized (401) — set a valid API token in Settings.", response.status, path, text);
  }
  throw new ApiError(`API request failed (${response.status}) ${path}: ${text}`, response.status, path, text);
}

export async function postJson<TResponse, TBody>(path: string, body: TBody): Promise<TResponse> {
  return fetchJson<TResponse>(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export async function checkHealth(): Promise<"reachable" | "offline"> {
  try {
    await fetchJson<unknown>("/api/health", { auth: false });
    return "reachable";
  } catch {
    return "offline";
  }
}

export async function checkAuth(): Promise<"reachable" | "unauthorized" | "offline"> {
  try {
    await fetchJson<unknown>("/api/history/scans?limit=1");
    return "reachable";
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) {
      return "unauthorized";
    }
    if (err instanceof ApiError) {
      return "reachable";
    }
    return "offline";
  }
}
