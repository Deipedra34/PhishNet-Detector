// Shared client for the PhishNet Detector REST API (`phishnet serve`).
//
// By default every call uses a relative path ("/api/..."), so a dashboard served
// by `phishnet serve` - or by the Vite dev server with its /api proxy - talks to
// the API on its own origin. A different base URL can be set at build time
// (VITE_API_BASE_URL) or at runtime from the dashboard's settings, much like the
// browser extension's configurable API address.

/** localStorage key holding a base URL chosen in the dashboard's settings. */
export const API_BASE_URL_KEY = "phishnet.apiBaseUrl";

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
    throw new Error("That doesn't look like a valid address.");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("The address must start with http:// or https://");
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error("Use just the server address, without a login, query string, or #fragment.");
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

/** A failed API call, with a message ready to show to the user. */
export class ApiError extends Error {
  /**
   * @param {"unreachable"|"timeout"|"http"|"invalid"} kind
   * @param {number} [status] HTTP status, for kind "http"/"invalid"
   */
  constructor(kind, message, status) {
    super(message);
    this.name = "ApiError";
    this.kind = kind;
    this.status = status;
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
 * @param {typeof fetch} [options.fetchImpl] fetch implementation (swapped out in tests)
 */
export function createApiClient({ baseUrl = "", fetchImpl } = {}) {
  const base = normalizeBaseUrl(baseUrl);
  const where = base || "this server";

  async function request(path, init, timeoutMs) {
    const doFetch = fetchImpl ?? globalThis.fetch.bind(globalThis);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      let response;
      try {
        response = await doFetch(base + path, {
          ...init,
          signal: controller.signal,
          credentials: "same-origin",
          cache: "no-store",
        });
      } catch {
        if (controller.signal.aborted) {
          throw new ApiError("timeout", `The PhishNet API at ${where} didn't answer within ${timeoutMs / 1000} seconds.`);
        }
        throw new ApiError("unreachable", `Can't reach the PhishNet API at ${where}. Is "phishnet serve" running?`);
      }

      let body = null;
      try {
        body = await response.json();
      } catch {
        // Not JSON - handled below.
      }
      if (!response.ok) {
        // The PhishNet API always explains its errors as {"error": "..."}.
        if (typeof body?.error === "string") {
          throw new ApiError("http", body.error, response.status);
        }
        throw new ApiError("invalid", `${where} answered with HTTP ${response.status}, not like a PhishNet API.`,
          response.status);
      }
      if (body === null || typeof body !== "object") {
        throw new ApiError("invalid", `${where} answered, but not like a PhishNet API.`, response.status);
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
      throw new ApiError("invalid", `${where} answered, but not with a PhishNet scan result.`);
    }
    return result;
  }

  return {
    baseUrl: base,

    /** `GET /api/health`; resolves to `{status: "ok"}`. */
    health() {
      return getJson("/api/health");
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
        throw new ApiError("invalid", `${where} answered, but not with a PhishNet scan history.`);
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
        throw new ApiError("invalid", `${where} answered, but not with PhishNet history stats.`);
      }
      return body;
    },
  };
}

/** A client for the base URL currently configured. */
export function defaultClient() {
  return createApiClient({ baseUrl: getConfiguredBaseUrl() });
}
