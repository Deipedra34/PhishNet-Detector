import { act, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { setStoredApiKey } from "../api/client.js";
import ApiSettings from "./ApiSettings.jsx";

describe("ApiSettings", () => {
  it("offers to forget the API key once one is saved, even after rendering", () => {
    render(<ApiSettings />);
    expect(screen.queryByRole("button", { name: "Forget API key" })).not.toBeInTheDocument();

    act(() => {
      setStoredApiKey("a-saved-key-0123456789");
    });
    expect(screen.getByRole("button", { name: "Forget API key" })).toBeInTheDocument();

    act(() => {
      setStoredApiKey("");
    });
    expect(screen.queryByRole("button", { name: "Forget API key" })).not.toBeInTheDocument();
  });
});
