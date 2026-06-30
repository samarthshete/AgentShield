const API_BASE_URL_STORAGE_KEY = "agentshield.apiBaseUrl";
const API_TOKEN_STORAGE_KEY = "agentshield.apiToken";
const DEFAULT_API_BASE_URL = "http://127.0.0.1:8000";

function canUseStorage(): boolean {
  return typeof window !== "undefined" && typeof window.localStorage !== "undefined";
}

function readStorage(key: string): string | null {
  if (!canUseStorage()) {
    return null;
  }

  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function writeStorage(key: string, value: string): void {
  if (!canUseStorage()) {
    return;
  }

  try {
    if (value.trim()) {
      window.localStorage.setItem(key, value.trim());
    } else {
      window.localStorage.removeItem(key);
    }
  } catch {
    // Ignore storage failures so API calls can still use env/default values.
  }
}

function normalizeBaseUrl(value: string): string {
  return value.trim().replace(/\/+$/, "");
}

export function getApiBaseUrl(): string {
  const stored = readStorage(API_BASE_URL_STORAGE_KEY);
  if (stored !== null && stored.trim()) {
    return normalizeBaseUrl(stored);
  }

  const envValue = import.meta.env.VITE_API_BASE_URL as string | undefined;
  if (envValue !== undefined && envValue.trim()) {
    return normalizeBaseUrl(envValue);
  }

  return DEFAULT_API_BASE_URL;
}

export function setApiBaseUrl(value: string): void {
  writeStorage(API_BASE_URL_STORAGE_KEY, normalizeBaseUrl(value));
}

export function getApiToken(): string {
  const stored = readStorage(API_TOKEN_STORAGE_KEY);
  if (stored !== null && stored.trim()) {
    return stored.trim();
  }

  const envValue = import.meta.env.VITE_API_TOKEN as string | undefined;
  return envValue?.trim() ?? "";
}

export function setApiToken(value: string): void {
  writeStorage(API_TOKEN_STORAGE_KEY, value);
}
