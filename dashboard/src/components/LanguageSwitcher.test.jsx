import { act, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { defaultClient } from "../api/client.js";
import { LANGUAGE_STORAGE_KEY, resetLanguage } from "../i18n/index.js";
import NotFoundPage from "../pages/NotFoundPage.jsx";
import Layout from "./Layout.jsx";

/** A server that needs no API key and answers every request with {"status": "ok"}. */
function okServer() {
  return vi.fn(async () => ({
    ok: true,
    status: 200,
    headers: { get: () => null },
    json: async () => ({ status: "ok" }),
  }));
}

function renderDashboard() {
  return render(
    <MemoryRouter initialEntries={["/somewhere"]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <Routes>
        <Route element={<Layout />}>
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Routes>
    </MemoryRouter>,
  );
}

describe("LanguageSwitcher", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("swaps the dashboard's text between English and Turkish", async () => {
    vi.stubGlobal("fetch", okServer());
    renderDashboard();

    expect(await screen.findByRole("heading", { name: "Page not found" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Scan" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Change" })).toBeInTheDocument();
    const picker = screen.getByRole("combobox", { name: "Language" });
    expect(picker).toHaveValue("en");

    fireEvent.change(picker, { target: { value: "tr" } });

    expect(screen.getByRole("heading", { name: "Sayfa bulunamadı" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Tarama" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Geçmiş" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Değiştir" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Scan" })).not.toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Dil" })).toHaveValue("tr");
    expect(document.documentElement.lang).toBe("tr");

    fireEvent.change(screen.getByRole("combobox", { name: "Dil" }), { target: { value: "en" } });
    expect(screen.getByRole("heading", { name: "Page not found" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Scan" })).toBeInTheDocument();
  });

  it("remembers the choice in local storage for the next visit", async () => {
    vi.stubGlobal("fetch", okServer());
    const { unmount } = renderDashboard();
    fireEvent.change(await screen.findByRole("combobox", { name: "Language" }), { target: { value: "tr" } });
    expect(localStorage.getItem(LANGUAGE_STORAGE_KEY)).toBe("tr");
    unmount();

    // A new visit: nothing in memory, only what's stored.
    act(() => resetLanguage());
    renderDashboard();
    expect(await screen.findByRole("heading", { name: "Sayfa bulunamadı" })).toBeInTheDocument();
  });

  it("asks the API for the chosen language", async () => {
    const fetchImpl = okServer();
    vi.stubGlobal("fetch", fetchImpl);
    renderDashboard();
    fireEvent.change(await screen.findByRole("combobox", { name: "Language" }), { target: { value: "tr" } });

    await defaultClient().health();
    expect(fetchImpl.mock.calls.at(-1)[1].headers["Accept-Language"]).toBe("tr");
  });
});
