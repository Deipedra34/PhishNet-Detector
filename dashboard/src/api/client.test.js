import { describe, expect, it, vi } from "vitest";
import {
  API_BASE_URL_KEY,
  ApiError,
  buildQuery,
  createApiClient,
  getConfiguredBaseUrl,
  normalizeBaseUrl,
  setConfiguredBaseUrl,
} from "./client.js";

/** A fetch stand-in answering with `status` and a JSON body, recording each call. */
function fakeFetch(status, body) {
  return vi.fn(async () => ({
    ok: status >= 200 && status < 300,
    status,
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
