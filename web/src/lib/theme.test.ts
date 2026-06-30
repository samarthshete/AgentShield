import { afterEach, describe, expect, it } from "vitest";

import { applyTheme, getStoredTheme, resolveTheme, setTheme } from "./theme";

afterEach(() => {
  window.localStorage.clear();
  document.documentElement.classList.remove("dark");
});

describe("theme", () => {
  it("persists the chosen theme and toggles the dark class", () => {
    setTheme("dark");
    expect(getStoredTheme()).toBe("dark");
    expect(document.documentElement.classList.contains("dark")).toBe(true);

    setTheme("light");
    expect(getStoredTheme()).toBe("light");
    expect(document.documentElement.classList.contains("dark")).toBe(false);
  });

  it("resolves a stored preference over the system default", () => {
    setTheme("dark");
    expect(resolveTheme()).toBe("dark");
  });

  it("applyTheme toggles the dark class without writing storage", () => {
    applyTheme("dark");
    expect(document.documentElement.classList.contains("dark")).toBe(true);
    expect(getStoredTheme()).toBeNull();
  });
});
