// Shared by the popup and the options page: cross-browser extension APIs, the
// stored API address and API key, and the calls to a PhishNet Detector REST API
// (`phishnet serve`).

import { currentLanguage, t } from "./i18n.js";

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
const API_KEY_KEY = "apiKey";

/** Request header carrying the API key (PhishNet 2.9.0 and newer require it). */
export const API_KEY_HEADER = "X-API-Key";

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

/** The stored API key, or "" when none is set. */
export async function getApiKey() {
  const stored = await ext.storage.local.get(API_KEY_KEY);
  return typeof stored[API_KEY_KEY] === "string" ? stored[API_KEY_KEY] : "";
}

/** Stores the API key; a blank key removes it (for servers started with --no-auth). */
export async function setApiKey(key) {
  if (key) {
    await ext.storage.local.set({ [API_KEY_KEY]: key });
  } else {
    await ext.storage.local.remove(API_KEY_KEY);
  }
}

/**
 * Checks an API key typed by the user: surrounding spaces are dropped, blank is
 * allowed (no key), and anything that can't be sent in an HTTP header is rejected.
 *
 * @throws {Error} with a message that can be shown to the user as-is
 */
export function normalizeApiKey(input) {
  const key = (input ?? "").trim();
  if (key && !/^[\x21-\x7e]+$/.test(key)) {
    throw new Error(t("errInvalidKey"));
  }
  return key;
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
    throw new Error(t("errEnterAddress", DEFAULT_API_URL));
  }
  let url;
  try {
    url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `http://${text}`);
  } catch {
    throw new Error(t("errInvalidAddress"));
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error(t("errProtocol"));
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error(t("errAddressExtras"));
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
  /**
   * @param {"unreachable"|"timeout"|"http"|"invalid"|"auth"|"rate"} kind
   * @param {number} [retryAfterSeconds] for kind "rate": the server's Retry-After
   * @param {number} [status] the HTTP status, when the server answered
   */
  constructor(kind, message, retryAfterSeconds, status) {
    super(message);
    this.name = "ApiError";
    this.kind = kind;
    this.retryAfterSeconds = retryAfterSeconds;
    this.status = status;
  }
}

async function requestJson(apiBaseUrl, path, init, timeoutMs, apiKey) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    let response;
    try {
      response = await fetch(apiBaseUrl + path, {
        ...init,
        // The API answers in this language (error messages, scan result text).
        headers: {
          ...init.headers,
          "Accept-Language": currentLanguage(),
          ...(apiKey ? { [API_KEY_HEADER]: apiKey } : {}),
        },
        signal: controller.signal,
        credentials: "omit",
        cache: "no-store",
      });
    } catch {
      if (controller.signal.aborted) {
        throw new ApiError("timeout", t("errTimeout", apiBaseUrl, timeoutMs / 1000));
      }
      // Network failure, refused connection, or a request blocked by CORS all end up here.
      throw new ApiError("unreachable", t("errUnreachable", apiBaseUrl));
    }

    let body = null;
    try {
      body = await response.json();
    } catch {
      // Not JSON - handled below.
    }
    if (!response.ok) {
      // A PhishNet API always explains its errors as {"error": "..."}; anything else is some other server.
      if (response.status === 401 && typeof body?.error === "string") {
        throw new ApiError("auth", t(apiKey ? "errKeyRejected" : "errKeyRequired"), undefined, 401);
      }
      if (response.status === 429 && typeof body?.error === "string") {
        const retryAfter = Number.parseInt(response.headers.get("Retry-After") ?? "", 10);
        throw new ApiError("rate", body.error, Number.isFinite(retryAfter) ? retryAfter : undefined, 429);
      }
      if (typeof body?.error === "string") {
        throw new ApiError("http", t("errApi", body.error), undefined, response.status);
      }
      throw new ApiError("invalid", t("errHttpNotApi", apiBaseUrl, response.status), undefined, response.status);
    }
    if (body === null || typeof body !== "object") {
      throw new ApiError("invalid", t("errNotApiCheckSettings", apiBaseUrl), undefined, response.status);
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
export async function scanUrl(apiBaseUrl, pageUrl, apiKey) {
  const result = await requestJson(apiBaseUrl, "/api/scan/url", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: pageUrl }),
  }, SCAN_TIMEOUT_MS, apiKey);
  if (typeof result.score !== "number" || !RISK_LEVELS.includes(result.level) || !Array.isArray(result.signals)) {
    throw new ApiError("invalid", t("errNotScanResult", apiBaseUrl));
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
    throw new ApiError("invalid", t("errNotApi", apiBaseUrl));
  }
}

/**
 * Checks the server is reachable (`GET /api/health`, which needs no key), then that
 * it accepts `apiKey` (`GET /api/auth/check`). Resolves to `{keyChecked}`: false for a
 * server older than 2.9.0, which has no API keys (and answers that endpoint with 404).
 *
 * @throws {ApiError} kind "auth" when the key is missing or wrong
 */
export async function checkConnection(apiBaseUrl, apiKey) {
  await checkHealth(apiBaseUrl);
  try {
    await requestJson(apiBaseUrl, "/api/auth/check", { method: "GET" }, HEALTH_TIMEOUT_MS, apiKey);
    return { keyChecked: true };
  } catch (error) {
    // By status, not message: the server's message is in the extension's language.
    if (error instanceof ApiError && error.kind === "http" && error.status === 404) {
      return { keyChecked: false };
    }
    throw error;
  }
}
