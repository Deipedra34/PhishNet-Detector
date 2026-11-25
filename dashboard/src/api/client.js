// Shared client for the PhishNet Detector REST API (`phishnet serve`).
//
// By default every call uses a relative path ("/api/..."), so a dashboard served
// by `phishnet serve` - or by the Vite dev server with its /api proxy - talks to
// the API on its own origin. A different base URL can be set at build time
// (VITE_API_BASE_URL) or at runtime from the dashboard's settings, much like the
// browser extension's configurable API address.
//
// Every request asks for the dashboard's language (Accept-Language), so the API's
// error messages and scan result text come back in it.

import { getLanguage, translate } from "../i18n/index.js";

/** localStorage key holding a base URL chosen in the dashboard's settings. */
export const API_BASE_URL_KEY = "phishnet.apiBaseUrl";

/** localStorage key holding the API key entered on the dashboard's key screen. */
export const API_KEY_STORAGE_KEY = "phishnet.apiKey";

/** Request header carrying the API key (`phishnet serve` 2.9.0 and newer require it). */
export const API_KEY_HEADER = "X-API-Key";

/** Window event fired when the server rejects the stored API key, so the key screen can come back. */
export const UNAUTHORIZED_EVENT = "phishnet:unauthorized";

/** Window event fired when the stored API key is saved or forgotten. */
export const API_KEY_CHANGED_EVENT = "phishnet:api-key-changed";

/** A scan can include a live WHOIS lookup on the server, which may take several seconds. */
export const SCAN_TIMEOUT_MS = 30000;
/** Reads (history, stats, feed status) only query local files on the server. */
export const READ_TIMEOUT_MS = 10000;

export const RISK_LEVELS = ["LOW", "MEDIUM", "HIGH"];

/**
 * Tidies a base URL: blank means "same origin" (""), a trailing slash is dropped,
 * and both absolute URLs ("http://host:8080") and path prefixes ("/phishnet") are kept.
 *
 * @throws {Error} with a message that can be shown to the user as-is
 */
export function normalizeBaseUrl(input) {
  const text = (input ?? "").trim();
  if (!text) {
    return "";
  }
  if (text.startsWith("/")) {
    return text.replace(/\/+$/, "");
  }
  let url;
  try {
    url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `http://${text}`);
  } catch {
    throw new Error(translate("client.invalidAddress"));
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error(translate("client.protocol"));
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error(translate("client.addressExtras"));
  }
  return (url.origin + url.pathname).replace(/\/+$/, "");
}

function readStoredBaseUrl() {
  try {
    return globalThis.localStorage?.getItem(API_BASE_URL_KEY) ?? null;
  } catch {
    return null;
  }
}

/** The base URL in effect: the runtime setting, else the build-time default, else same origin. */
export function getConfiguredBaseUrl() {
  const stored = readStoredBaseUrl();
  if (stored !== null) {
    return stored;
  }
  return normalizeBaseUrl(import.meta.env?.VITE_API_BASE_URL ?? "");
}

/** Saves (or, with a blank value, clears) the runtime base URL setting. Returns the normalized value. */
export function setConfiguredBaseUrl(input) {
  const normalized = normalizeBaseUrl(input);
  try {
    if (normalized) {
      globalThis.localStorage?.setItem(API_BASE_URL_KEY, normalized);
    } else {
      globalThis.localStorage?.removeItem(API_BASE_URL_KEY);
    }
  } catch {
    // Storage unavailable (private mode, blocked site data): the setting just isn't remembered.
  }
  return normalized;
}

/**
 * Checks an API key typed by the user: surrounding spaces are dropped, blank means
 * "no key", and anything that can't be sent in an HTTP header is rejected.
 *
 * @throws {Error} with a message that can be shown to the user as-is
 */
export function normalizeApiKey(input) {
  const key = (input ?? "").trim();
  if (key && !/^[\x21-\x7e]+$/.test(key)) {
    throw new Error(translate("client.invalidKey"));
  }
  return key;
}

/** The API key saved in this browser, or "" when none is. */
export function getStoredApiKey() {
  try {
    return globalThis.localStorage?.getItem(API_KEY_STORAGE_KEY) ?? "";
  } catch {
    return "";
  }
}

/** Saves (or, with a blank value, forgets) the API key. Returns the normalized key. */
export function setStoredApiKey(input) {
  const key = normalizeApiKey(input);
  try {
    if (key) {
      globalThis.localStorage?.setItem(API_KEY_STORAGE_KEY, key);
    } else {
      globalThis.localStorage?.removeItem(API_KEY_STORAGE_KEY);
    }
  } catch {
    // Storage unavailable: the key just isn't remembered.
  }
  globalThis.dispatchEvent?.(new Event(API_KEY_CHANGED_EVENT));
  return key;
}

/** A failed API call, with a message ready to show to the user. */
export class ApiError extends Error {
  /**
   * @param {"unreachable"|"timeout"|"http"|"invalid"|"auth"|"rate"} kind
   * @param {number} [status] HTTP status, for kind "http"/"invalid"/"auth"/"rate"
   * @param {number} [retryAfterSeconds] for kind "rate": the server's Retry-After
   */
  constructor(kind, message, status, retryAfterSeconds) {
    super(message);
    this.name = "ApiError";
    this.kind = kind;
    this.status = status;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/** "?a=1&b=x", leaving out empty values; "" when nothing is left. */
export function buildQuery(params) {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params ?? {})) {
    if (value !== undefined && value !== null && value !== "") {
      search.set(key, String(value));
    }
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

/**
 * Creates an API client.
 *
 * @param {object} [options]
 * @param {string} [options.baseUrl] API base URL; "" (the default) for same-origin relative paths
 * @param {string} [options.apiKey] sent as the X-API-Key header on every request when set
 * @param {string} [options.language] sent as the Accept-Language header on every request when set
 * @param {() => void} [options.onUnauthorized] called when the server rejects the key (401)
 * @param {typeof fetch} [options.fetchImpl] fetch implementation (swapped out in tests)
 */
export function createApiClient({ baseUrl = "", apiKey = "", language, onUnauthorized, fetchImpl } = {}) {
  const base = normalizeBaseUrl(baseUrl);
  const where = base || translate("client.thisServer");
  const authHeaders = apiKey ? { [API_KEY_HEADER]: apiKey } : {};
  // Set explicitly: otherwise the browser sends its own preference, which may not be the dashboard's.
  const languageHeaders = language ? { "Accept-Language": language } : {};

  async function request(path, init, timeoutMs) {
    const doFetch = fetchImpl ?? globalThis.fetch.bind(globalThis);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      let response;
      try {
        response = await doFetch(base + path, {
          ...init,
          headers: { ...init.headers, ...languageHeaders, ...authHeaders },
          signal: controller.signal,
          credentials: "same-origin",
          cache: "no-store",
        });
      } catch {
        if (controller.signal.aborted) {
          throw new ApiError("timeout", translate("client.timeout", { where, seconds: timeoutMs / 1000 }));
        }
        throw new ApiError("unreachable", translate("client.unreachable", { where }));
      }

      let body = null;
      try {
        body = await response.json();
      } catch {
        // Not JSON - handled below.
      }
      if (!response.ok) {
        // The PhishNet API always explains its errors as {"error": "..."}.
        if (response.status === 401 && typeof body?.error === "string") {
          onUnauthorized?.();
          throw new ApiError("auth", translate(apiKey ? "client.keyRejected" : "client.keyRequired"), 401);
        }
        if (response.status === 429 && typeof body?.error === "string") {
          const retryAfter = Number.parseInt(response.headers?.get?.("Retry-After") ?? "", 10);
          throw new ApiError("rate", body.error, 429, Number.isFinite(retryAfter) ? retryAfter : undefined);
        }
        if (typeof body?.error === "string") {
          throw new ApiError("http", body.error, response.status);
        }
        throw new ApiError("invalid", translate("client.httpNotApi", { where, status: response.status }),
          response.status);
      }
      if (body === null || typeof body !== "object") {
        throw new ApiError("invalid", translate("client.notApi", { where }), response.status);
      }
      return body;
    } finally {
      clearTimeout(timer);
    }
  }

  function getJson(path, params, timeoutMs = READ_TIMEOUT_MS) {
    return request(path + buildQuery(params), { method: "GET" }, timeoutMs);
  }

  function postJson(path, payload, timeoutMs = SCAN_TIMEOUT_MS) {
    return request(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }, timeoutMs);
  }

  function checkScanResult(result) {
    if (typeof result.score !== "number" || !RISK_LEVELS.includes(result.level) || !Array.isArray(result.signals)) {
      throw new ApiError("invalid", translate("client.notScanResult", { where }));
    }
    return result;
  }

  return {
    baseUrl: base,

    /** `GET /api/health`; resolves to `{status: "ok"}`. Needs no API key. */
    health() {
      return getJson("/api/health");
    },

    /** `GET /api/auth/check`: resolves when the server accepts this client's API key (or needs none). */
    authCheck() {
      return getJson("/api/auth/check");
    },

    /** `POST /api/scan/url`. */
    async scanUrl(url) {
      return checkScanResult(await postJson("/api/scan/url", { url }));
    },

    /** `POST /api/scan/email` with the raw message text as JSON. */
    async scanEmailText(raw) {
      return checkScanResult(await postJson("/api/scan/email", { raw }));
    },

    /** `POST /api/scan/email` as a multipart upload of an .eml file. */
    async scanEmailFile(file) {
      const form = new FormData();
      form.append("file", file, file.name || "upload.eml");
      return checkScanResult(await request("/api/scan/email", { method: "POST", body: form }, SCAN_TIMEOUT_MS));
    },

    /**
     * `GET /api/history`: one page of past scans, newest first.
     *
     * @param {{limit?: number, offset?: number, target?: string, risk?: string, type?: string}} [params]
     * @returns {Promise<{total: number, limit: number, offset: number, scans: object[]}>}
     */
    async history(params = {}) {
      const body = await getJson("/api/history", params);
      if (!Array.isArray(body.scans)) {
        throw new ApiError("invalid", translate("client.notHistory", { where }));
      }
      return body;
    },

    /**
     * `GET /api/history/stats`: totals per risk level and type, first/last scan,
     * and the domains with the most MEDIUM/HIGH scans.
     *
     * @param {{top?: number}} [params]
     */
    async historyStats(params = {}) {
      const body = await getJson("/api/history/stats", params);
      if (typeof body.total !== "number" || typeof body.byRiskLevel !== "object") {
        throw new ApiError("invalid", translate("client.notStats", { where }));
      }
      return body;
    },

    /** `GET /api/feeds/status`: each threat feed's cache state (the server never downloads for this). */
    async feedsStatus() {
      const body = await getJson("/api/feeds/status");
      if (!Array.isArray(body.feeds)) {
        throw new ApiError("invalid", translate("client.notFeeds", { where }));
      }
      return body;
    },
  };
}

/** Tells the dashboard (its AuthGate) that the stored API key was rejected. */
export function notifyUnauthorized() {
  globalThis.dispatchEvent?.(new Event(UNAUTHORIZED_EVENT));
}

/** A client for the base URL, API key, and language currently configured. */
export function defaultClient() {
  return createApiClient({
    baseUrl: getConfiguredBaseUrl(),
    apiKey: getStoredApiKey(),
    language: getLanguage(),
    onUnauthorized: notifyUnauthorized,
  });
}
