import { describe, expect, it, vi } from "vitest";
import {
  API_BASE_URL_KEY,
  API_KEY_STORAGE_KEY,
  ApiError,
  UNAUTHORIZED_EVENT,
  buildQuery,
  createApiClient,
  defaultClient,
  getConfiguredBaseUrl,
  getStoredApiKey,
  normalizeApiKey,
  normalizeBaseUrl,
  setConfiguredBaseUrl,
  setStoredApiKey,
} from "./client.js";

/** A fetch stand-in answering with `status`, a JSON body, and optional headers, recording each call. */
function fakeFetch(status, body, headers = {}) {
  return vi.fn(async () => ({
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (name) => headers[name] ?? null },
    json: async () => body,
  }));
}

const SCAN_RESULT = {
  target: "http://paypa1.tk/login",
  type: "URL",
  score: 70,
  level: "HIGH",
  recommendation: "Do not click.",
  signals: [{ id: "typosquatting", category: "URL", description: "Looks like paypal", evidence: "paypa1" }],
  domainAge: { status: "SKIPPED" },
};

describe("normalizeBaseUrl", () => {
  it("treats blank as same-origin", () => {
    expect(normalizeBaseUrl("")).toBe("");
    expect(normalizeBaseUrl("   ")).toBe("");
    expect(normalizeBaseUrl(undefined)).toBe("");
  });

  it("keeps path prefixes and drops trailing slashes", () => {
    expect(normalizeBaseUrl("/phishnet/")).toBe("/phishnet");
    expect(normalizeBaseUrl("http://localhost:8080/")).toBe("http://localhost:8080");
    expect(normalizeBaseUrl("https://scanner.example/api-root//")).toBe("https://scanner.example/api-root");
  });

  it("adds http:// to a bare host", () => {
    expect(normalizeBaseUrl("localhost:9090")).toBe("http://localhost:9090");
  });

  it("rejects other schemes, logins, queries, and fragments", () => {
    expect(() => normalizeBaseUrl("ftp://host")).toThrow(/http/);
    expect(() => normalizeBaseUrl("http://user:pw@host")).toThrow(/login/);
    expect(() => normalizeBaseUrl("http://host/?x=1")).toThrow(/query/);
  });
});

describe("configured base URL", () => {
  it("defaults to same-origin and remembers a runtime setting", () => {
    expect(getConfiguredBaseUrl()).toBe("");
    expect(setConfiguredBaseUrl("localhost:8081/")).toBe("http://localhost:8081");
    expect(localStorage.getItem(API_BASE_URL_KEY)).toBe("http://localhost:8081");
    expect(getConfiguredBaseUrl()).toBe("http://localhost:8081");

    setConfiguredBaseUrl("");
    expect(localStorage.getItem(API_BASE_URL_KEY)).toBeNull();
    expect(getConfiguredBaseUrl()).toBe("");
  });
});

describe("buildQuery", () => {
  it("leaves out empty values", () => {
    expect(buildQuery({ limit: 20, offset: 0, target: "", risk: undefined, type: null })).toBe("?limit=20&offset=0");
    expect(buildQuery({})).toBe("");
  });

  it("encodes values", () => {
    expect(buildQuery({ target: "50%_off & more" })).toBe("?target=50%25_off+%26+more");
  });
});

describe("createApiClient", () => {
  it("uses relative paths by default", async () => {
    const fetchImpl = fakeFetch(200, { status: "ok" });
    await createApiClient({ fetchImpl }).health();
    expect(fetchImpl).toHaveBeenCalledWith("/api/health", expect.objectContaining({ method: "GET" }));
  });

  it("prefixes the configured base URL", async () => {
    const fetchImpl = fakeFetch(200, { status: "ok" });
    await createApiClient({ baseUrl: "http://localhost:9090/", fetchImpl }).health();
    expect(fetchImpl.mock.calls[0][0]).toBe("http://localhost:9090/api/health");
  });

  it("posts a URL scan as JSON and returns the result", async () => {
    const fetchImpl = fakeFetch(200, SCAN_RESULT);
    const result = await createApiClient({ fetchImpl }).scanUrl("http://paypa1.tk/login");

    expect(result).toEqual(SCAN_RESULT);
    const [url, init] = fetchImpl.mock.calls[0];
    expect(url).toBe("/api/scan/url");
    expect(init.method).toBe("POST");
    expect(init.headers).toEqual({ "Content-Type": "application/json" });
    expect(JSON.parse(init.body)).toEqual({ url: "http://paypa1.tk/login" });
  });

  it("sends raw email text as JSON and an .eml file as multipart", async () => {
    const fetchImpl = fakeFetch(200, { ...SCAN_RESULT, type: "EMAIL" });
    const client = createApiClient({ fetchImpl });

    await client.scanEmailText("From: a@b.c\n\nhello");
    expect(JSON.parse(fetchImpl.mock.calls[0][1].body)).toEqual({ raw: "From: a@b.c\n\nhello" });

    const file = new File(["From: a@b.c\n\nhello"], "suspicious.eml", { type: "message/rfc822" });
    await client.scanEmailFile(file);
    const form = fetchImpl.mock.calls[1][1].body;
    expect(form).toBeInstanceOf(FormData);
    expect(form.get("file").name).toBe("suspicious.eml");
  });

  it("builds history queries from the filters that are set", async () => {
    const fetchImpl = fakeFetch(200, { total: 0, limit: 20, offset: 40, scans: [] });
    await createApiClient({ fetchImpl }).history({ limit: 20, offset: 40, target: "paypal", risk: "HIGH", type: "" });
    expect(fetchImpl.mock.calls[0][0]).toBe("/api/history?limit=20&offset=40&target=paypal&risk=HIGH");
  });

  it("reads stats and feed status", async () => {
    const stats = { total: 3, byRiskLevel: { LOW: 1, MEDIUM: 1, HIGH: 1 }, topFlaggedDomains: [] };
    const statsFetch = fakeFetch(200, stats);
    expect(await createApiClient({ fetchImpl: statsFetch }).historyStats({ top: 5 })).toEqual(stats);
    expect(statsFetch.mock.calls[0][0]).toBe("/api/history/stats?top=5");

    const feeds = { feeds: [{ source: "openphish", state: "FRESH" }] };
    const feedsFetch = fakeFetch(200, feeds);
    expect(await createApiClient({ fetchImpl: feedsFetch }).feedsStatus()).toEqual(feeds);
    expect(feedsFetch.mock.calls[0][0]).toBe("/api/feeds/status");
  });

  it("surfaces the API's own error message", async () => {
    const fetchImpl = fakeFetch(400, { error: "Missing required field 'url'" });
    const failure = createApiClient({ fetchImpl }).scanUrl("");

    await expect(failure).rejects.toBeInstanceOf(ApiError);
    await expect(failure).rejects.toMatchObject({ kind: "http", status: 400, message: "Missing required field 'url'" });
  });

  it("reports servers that aren't a PhishNet API", async () => {
    const notJson = vi.fn(async () => ({
      ok: false,
      status: 502,
      json: async () => {
        throw new SyntaxError("Unexpected token <");
      },
    }));
    await expect(createApiClient({ fetchImpl: notJson }).health()).rejects.toMatchObject({ kind: "invalid", status: 502 });

    const wrongShape = fakeFetch(200, { hello: "world" });
    await expect(createApiClient({ fetchImpl: wrongShape }).scanUrl("x")).rejects.toMatchObject({ kind: "invalid" });
    await expect(createApiClient({ fetchImpl: wrongShape }).history()).rejects.toMatchObject({ kind: "invalid" });
  });

  it("reports an unreachable server", async () => {
    const fetchImpl = vi.fn(async () => {
      throw new TypeError("Failed to fetch");
    });
    await expect(createApiClient({ fetchImpl }).health()).rejects.toMatchObject({
      kind: "unreachable",
      message: expect.stringContaining("phishnet serve"),
    });
  });
});

describe("API key", () => {
  const UNAUTHORIZED = { error: "Missing or invalid API key." };

  it("is stored in localStorage, trimmed, and forgotten when blank", () => {
    expect(getStoredApiKey()).toBe("");
    expect(setStoredApiKey("  abc123-key  ")).toBe("abc123-key");
    expect(localStorage.getItem(API_KEY_STORAGE_KEY)).toBe("abc123-key");
    expect(getStoredApiKey()).toBe("abc123-key");

    setStoredApiKey("");
    expect(localStorage.getItem(API_KEY_STORAGE_KEY)).toBeNull();
  });

  it("rejects keys that can't be sent in a header", () => {
    expect(normalizeApiKey(" ok-key ")).toBe("ok-key");
    expect(() => normalizeApiKey("has space")).toThrow(/spaces/);
    expect(() => normalizeApiKey("tab\tkey")).toThrow();
  });

  it("is sent as X-API-Key on every request, alongside other headers", async () => {
    const fetchImpl = fakeFetch(200, SCAN_RESULT);
    const client = createApiClient({ apiKey: "s3cret-key", fetchImpl });

    await client.scanUrl("http://paypa1.tk/login");
    expect(fetchImpl.mock.calls[0][1].headers).toEqual({
      "Content-Type": "application/json",
      "X-API-Key": "s3cret-key",
    });

    const file = new File(["From: a@b.c\n\nhello"], "x.eml");
    await client.scanEmailFile(file);
    expect(fetchImpl.mock.calls[1][1].headers).toEqual({ "X-API-Key": "s3cret-key" });
  });

  it("is not sent when none is set", async () => {
    const fetchImpl = fakeFetch(200, { status: "ok" });
    await createApiClient({ fetchImpl }).health();
    expect(fetchImpl.mock.calls[0][1].headers).toEqual({});
  });

  it("defaultClient uses the stored key", async () => {
    setStoredApiKey("stored-key-123");
    const fetchImpl = fakeFetch(200, { status: "ok" });
    vi.stubGlobal("fetch", fetchImpl);
    try {
      await defaultClient().authCheck();
    } finally {
      vi.unstubAllGlobals();
    }
    expect(fetchImpl.mock.calls[0][0]).toBe("/api/auth/check");
    expect(fetchImpl.mock.calls[0][1].headers).toEqual({ "Accept-Language": "en", "X-API-Key": "stored-key-123" });
  });

  it("turns 401 into an auth error and calls onUnauthorized", async () => {
    const onUnauthorized = vi.fn();
    const withKey = createApiClient({ apiKey: "wrong-key", onUnauthorized, fetchImpl: fakeFetch(401, UNAUTHORIZED) });
    await expect(withKey.history()).rejects.toMatchObject({ kind: "auth", status: 401, message: /rejected/ });
    expect(onUnauthorized).toHaveBeenCalledTimes(1);

    const withoutKey = createApiClient({ fetchImpl: fakeFetch(401, UNAUTHORIZED) });
    await expect(withoutKey.history()).rejects.toMatchObject({ kind: "auth", message: /requires an API key/ });
  });

  it("defaultClient announces a rejected key with a window event", async () => {
    const listener = vi.fn();
    window.addEventListener(UNAUTHORIZED_EVENT, listener);
    vi.stubGlobal("fetch", fakeFetch(401, UNAUTHORIZED));
    try {
      await expect(defaultClient().historyStats()).rejects.toBeInstanceOf(ApiError);
    } finally {
      vi.unstubAllGlobals();
      window.removeEventListener(UNAUTHORIZED_EVENT, listener);
    }
    expect(listener).toHaveBeenCalledTimes(1);
  });

  it("turns 429 into a rate error with the server's message and Retry-After", async () => {
    const fetchImpl = fakeFetch(429, { error: "Too many scan requests: try again in 12 seconds." }, { "Retry-After": "12" });
    await expect(createApiClient({ fetchImpl }).scanUrl("http://x.tk")).rejects.toMatchObject({
      kind: "rate",
      status: 429,
      retryAfterSeconds: 12,
      message: "Too many scan requests: try again in 12 seconds.",
    });
  });
});
