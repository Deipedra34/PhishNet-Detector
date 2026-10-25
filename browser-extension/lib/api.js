// Shared by the popup and the options page: cross-browser extension APIs, the
// stored API address, and the calls to a PhishNet Detector REST API
// (`phishnet serve`).

/**
 * Firefox provides the promise-based `browser` namespace; Chrome and Edge
 * provide `chrome` (also promise-based under Manifest V3). Everything here
 * uses only APIs both have, so one shim is enough.
 */
export const ext = globalThis.browser ?? globalThis.chrome;

export const DEFAULT_API_URL = "http://localhost:8080";

/** A scan can include a live WHOIS lookup on the server, which may take several seconds. */
export const SCAN_TIMEOUT_MS = 20000;
const HEALTH_TIMEOUT_MS = 5000;

const API_URL_KEY = "apiBaseUrl";

/** Hosts covered by the manifest's host_permissions, so they never need a runtime permission prompt. */
const BUILT_IN_HOSTS = new Set(["localhost", "127.0.0.1"]);

export const RISK_LEVELS = ["LOW", "MEDIUM", "HIGH"];

// --- settings ---------------------------------------------------------------

export async function getApiBaseUrl() {
  const stored = await ext.storage.local.get(API_URL_KEY);
  return stored[API_URL_KEY] || DEFAULT_API_URL;
}

export async function setApiBaseUrl(url) {
  await ext.storage.local.set({ [API_URL_KEY]: url });
}

export async function resetApiBaseUrl() {
  await ext.storage.local.remove(API_URL_KEY);
}

/**
 * Checks and tidies an API address typed by the user. "localhost:9090" becomes
 * "http://localhost:9090"; a trailing slash is dropped; a path prefix (for a
 * server behind a reverse proxy) is kept.
 *
 * @throws {Error} with a message that can be shown to the user as-is
 */
export function normalizeApiBaseUrl(input) {
  const text = (input ?? "").trim();
  if (!text) {
    throw new Error(`Enter the API address, for example ${DEFAULT_API_URL}`);
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

/** Only regular web pages are worth scanning - not browser-internal, file, or extension pages. */
export function isScannablePageUrl(url) {
  return typeof url === "string" && /^https?:\/\//i.test(url);
}

/**
 * Asks for permission to reach a custom API host, so requests to it don't depend
 * on the server's CORS headers. Must be called straight from a click handler,
 * before any `await` (Firefox only shows the prompt during a user action).
 * Resolves to whether the permission is held; never rejects.
 */
export function requestHostPermission(apiBaseUrl) {
  const { protocol, hostname } = new URL(apiBaseUrl);
  if (BUILT_IN_HOSTS.has(hostname) || !ext.permissions?.request) {
    return Promise.resolve(BUILT_IN_HOSTS.has(hostname));
  }
  // Match patterns ignore the port, so this covers every port on that host.
  return ext.permissions.request({ origins: [`${protocol}//${hostname}/*`] }).catch(() => false);
}

// --- API calls --------------------------------------------------------------

/** A failed API call, with a message ready to show to the user. */
export class ApiError extends Error {
  /** @param {"unreachable"|"timeout"|"http"|"invalid"} kind */
  constructor(kind, message) {
    super(message);
    this.name = "ApiError";
    this.kind = kind;
  }
}

async function requestJson(apiBaseUrl, path, init, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    let response;
    try {
      response = await fetch(apiBaseUrl + path, {
        ...init,
        signal: controller.signal,
        credentials: "omit",
        cache: "no-store",
      });
    } catch {
      if (controller.signal.aborted) {
        throw new ApiError("timeout",
          `PhishNet API at ${apiBaseUrl} didn't answer within ${timeoutMs / 1000} seconds.`);
      }
      // Network failure, refused connection, or a request blocked by CORS all end up here.
      throw new ApiError("unreachable", `Can't reach PhishNet API at ${apiBaseUrl} — is "phishnet serve" running?`);
    }

    let body = null;
    try {
      body = await response.json();
    } catch {
      // Not JSON - handled below.
    }
    if (!response.ok) {
      // A PhishNet API always explains its errors as {"error": "..."}; anything else is some other server.
      if (typeof body?.error === "string") {
        throw new ApiError("http", `PhishNet API error: ${body.error}`);
      }
      throw new ApiError("invalid",
        `${apiBaseUrl} answered with HTTP ${response.status}, not like a PhishNet API. Check the address in Settings.`);
    }
    if (body === null || typeof body !== "object") {
      throw new ApiError("invalid",
        `${apiBaseUrl} answered, but not like a PhishNet API. Check the address in Settings.`);
    }
    return body;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Scans one URL with `POST /api/scan/url`. Resolves to the API's result object
 * (`score`, `level`, `signals`, `recommendation`, `domainAge`, ...).
 *
 * @throws {ApiError}
 */
export async function scanUrl(apiBaseUrl, pageUrl) {
  const result = await requestJson(apiBaseUrl, "/api/scan/url", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: pageUrl }),
  }, SCAN_TIMEOUT_MS);
  if (typeof result.score !== "number" || !RISK_LEVELS.includes(result.level) || !Array.isArray(result.signals)) {
    throw new ApiError("invalid",
      `${apiBaseUrl} answered, but not with a PhishNet scan result. Check the address in Settings.`);
  }
  return result;
}

/**
 * Checks `GET /api/health`.
 *
 * @throws {ApiError}
 */
export async function checkHealth(apiBaseUrl) {
  const body = await requestJson(apiBaseUrl, "/api/health", { method: "GET" }, HEALTH_TIMEOUT_MS);
  if (body.status !== "ok") {
    throw new ApiError("invalid", `${apiBaseUrl} answered, but not like a PhishNet API.`);
  }
}
