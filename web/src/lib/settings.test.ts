import { afterEach, describe, expect, it, vi } from "vitest";

import { getApiBaseUrl, getApiToken, setApiBaseUrl, setApiToken } from "./settings";

afterEach(() => {
  window.localStorage.clear();
  vi.unstubAllEnvs();
});

describe("API settings", () => {
  it("round-trips API base URL and token through localStorage", () => {
    setApiBaseUrl("http://localhost:9000/");
    setApiToken(" test-token ");

    expect(getApiBaseUrl()).toBe("http://localhost:9000");
    expect(getApiToken()).toBe("test-token");
  });

  it("uses Vite env values when localStorage is empty", () => {
    vi.stubEnv("VITE_API_BASE_URL", "http://env-api:8000/");
    vi.stubEnv("VITE_API_TOKEN", "env-token");

    expect(getApiBaseUrl()).toBe("http://env-api:8000");
    expect(getApiToken()).toBe("env-token");
  });
});
