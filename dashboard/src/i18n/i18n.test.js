import { afterEach, describe, expect, it, vi } from "vitest";
import en from "./en.json";
import tr from "./tr.json";
import {
  LANGUAGE_CHANGED_EVENT,
  LANGUAGE_STORAGE_KEY,
  detectLanguage,
  getLanguage,
  resetLanguage,
  setLanguage,
  supportedLanguage,
  translate,
} from "./index.js";

describe("translation files", () => {
  it("have the same keys", () => {
    expect(Object.keys(tr).sort()).toEqual(Object.keys(en).sort());
  });

  it("use the same placeholders for every key", () => {
    const placeholders = (text) => [...text.matchAll(/\{(\w+)\}/g)].map((match) => match[1]).sort();
    for (const key of Object.keys(en)) {
      expect(placeholders(tr[key]), key).toEqual(placeholders(en[key]));
    }
  });
});

describe("translate", () => {
  it("fills in placeholders and picks plural forms", () => {
    expect(translate("history.matching", { total: "1,234" }, "en")).toBe("1,234 matching scans");
    expect(translate("duration.day", { count: 1 }, "en")).toBe("1 day");
    expect(translate("duration.day", { count: 3 }, "en")).toBe("3 days");
    expect(translate("duration.day", { count: 3 }, "tr")).toBe("3 gün");
  });

  it("falls back to English, then to the key itself", () => {
    expect(translate("nav.scan", undefined, "xx")).toBe("Scan");
    expect(translate("no.such.key", undefined, "tr")).toBe("no.such.key");
  });
});

describe("language choice", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("recognizes supported language tags", () => {
    expect(supportedLanguage("tr-TR")).toBe("tr");
    expect(supportedLanguage("EN_us")).toBe("en");
    expect(supportedLanguage("de")).toBeNull();
    expect(supportedLanguage(undefined)).toBeNull();
  });

  it("follows the browser's preferred languages, else English", () => {
    vi.stubGlobal("navigator", { languages: ["de-DE", "tr-TR", "en"], language: "de-DE" });
    expect(detectLanguage()).toBe("tr");
    vi.stubGlobal("navigator", { languages: ["de-DE", "fr"], language: "de-DE" });
    expect(detectLanguage()).toBe("en");
  });

  it("prefers the language saved in this browser", () => {
    vi.stubGlobal("navigator", { languages: ["tr-TR"], language: "tr-TR" });
    localStorage.setItem(LANGUAGE_STORAGE_KEY, "en");
    expect(detectLanguage()).toBe("en");
  });

  it("remembers a switch, marks the page, and tells listeners", () => {
    const listener = vi.fn();
    window.addEventListener(LANGUAGE_CHANGED_EVENT, listener);
    setLanguage("tr");
    window.removeEventListener(LANGUAGE_CHANGED_EVENT, listener);

    expect(getLanguage()).toBe("tr");
    expect(localStorage.getItem(LANGUAGE_STORAGE_KEY)).toBe("tr");
    expect(document.documentElement.lang).toBe("tr");
    expect(listener).toHaveBeenCalledTimes(1);

    resetLanguage();
    expect(getLanguage()).toBe("tr");
  });

  it("treats an unsupported language as English", () => {
    setLanguage("xx");
    expect(getLanguage()).toBe("en");
  });
});
