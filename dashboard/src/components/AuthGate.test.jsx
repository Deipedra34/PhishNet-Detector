import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { API_KEY_STORAGE_KEY, UNAUTHORIZED_EVENT } from "../api/client.js";
import AuthGate from "./AuthGate.jsx";

const VALID_KEY = "the-right-key-0123456789";

/**
 * A fake server: /api/auth/check answers 200 for VALID_KEY (or for any request when
 * `requireKey` is false), 401 otherwise.
 */
function fakeServer({ requireKey = true } = {}) {
  return vi.fn(async (url, init) => {
    const ok = !requireKey || init?.headers?.["X-API-Key"] === VALID_KEY;
    return {
      ok,
      status: ok ? 200 : 401,
      headers: { get: () => null },
      json: async () => (ok ? { status: "ok" } : { error: "Missing or invalid API key." }),
    };
  });
}

function renderGate() {
  return render(
    <AuthGate>
      <p>dashboard pages</p>
    </AuthGate>,
  );
}

describe("AuthGate", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("shows the pages when the server needs no key", async () => {
    vi.stubGlobal("fetch", fakeServer({ requireKey: false }));
    renderGate();
    expect(await screen.findByText("dashboard pages")).toBeInTheDocument();
  });

  it("shows the pages when the stored key is accepted", async () => {
    localStorage.setItem(API_KEY_STORAGE_KEY, VALID_KEY);
    vi.stubGlobal("fetch", fakeServer());
    renderGate();
    expect(await screen.findByText("dashboard pages")).toBeInTheDocument();
  });

  it("asks for a key, rejects a wrong one, and saves a right one", async () => {
    vi.stubGlobal("fetch", fakeServer());
    renderGate();

    expect(await screen.findByRole("heading", { name: "Enter your API key" })).toBeInTheDocument();
    expect(screen.queryByText("dashboard pages")).not.toBeInTheDocument();
    const input = screen.getByLabelText("API key");
    expect(input).toHaveAttribute("type", "password");

    fireEvent.change(input, { target: { value: "not-the-key-000000" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("The server rejected that key");
    expect(localStorage.getItem(API_KEY_STORAGE_KEY)).toBeNull();

    fireEvent.change(input, { target: { value: `  ${VALID_KEY}  ` } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByText("dashboard pages")).toBeInTheDocument();
    expect(localStorage.getItem(API_KEY_STORAGE_KEY)).toBe(VALID_KEY);
  });

  it("says so when the saved key stopped working", async () => {
    localStorage.setItem(API_KEY_STORAGE_KEY, "an-old-rotated-key-1234");
    vi.stubGlobal("fetch", fakeServer());
    renderGate();
    expect(await screen.findByRole("heading", { name: "Your API key was not accepted" })).toBeInTheDocument();
  });

  it("can show the key while typing", async () => {
    vi.stubGlobal("fetch", fakeServer());
    renderGate();
    const input = await screen.findByLabelText("API key");
    fireEvent.click(screen.getByLabelText("Show"));
    expect(input).toHaveAttribute("type", "text");
  });

  it("brings the key screen back when a later request is rejected", async () => {
    localStorage.setItem(API_KEY_STORAGE_KEY, VALID_KEY);
    vi.stubGlobal("fetch", fakeServer());
    renderGate();
    await screen.findByText("dashboard pages");

    act(() => {
      window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
    });
    await waitFor(() => expect(screen.queryByText("dashboard pages")).not.toBeInTheDocument());
    expect(screen.getByLabelText("API key")).toBeInTheDocument();
  });

  it("still shows the pages when the server can't be reached, so they report it", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => {
      throw new TypeError("Failed to fetch");
    }));
    renderGate();
    expect(await screen.findByText("dashboard pages")).toBeInTheDocument();
  });
});
