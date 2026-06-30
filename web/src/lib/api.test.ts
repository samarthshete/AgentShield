import { afterEach, describe, expect, it, vi } from "vitest";

import { fetchJson } from "./api";
import { setApiBaseUrl, setApiToken } from "./settings";

afterEach(() => {
  window.localStorage.clear();
  vi.restoreAllMocks();
});

describe("fetchJson", () => {
  it("attaches the bearer token when one is configured", async () => {
    setApiBaseUrl("http://localhost:8000");
    setApiToken("secret-token");
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => {
      return new Response(JSON.stringify({ ok: true }), {
        headers: { "Content-Type": "application/json" },
        status: 200,
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    await expect(fetchJson<{ ok: boolean }>("/api/history/scans?limit=1")).resolves.toEqual({ ok: true });

    const [, init] = fetchMock.mock.calls[0];
    const headers = new Headers(init?.headers);
    expect(headers.get("Authorization")).toBe("Bearer secret-token");
  });

  it("throws the clear 401 Settings message", async () => {
    setApiBaseUrl("http://localhost:8000");
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => {
      return new Response("bad token", { status: 401 });
    });
    vi.stubGlobal("fetch", fetchMock);

    await expect(fetchJson<unknown>("/api/history/scans?limit=1")).rejects.toThrow(
      "Unauthorized (401) — set a valid API token in Settings."
    );
  });
});
