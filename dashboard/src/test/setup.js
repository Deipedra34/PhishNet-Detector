import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";
import { resetLanguage } from "../i18n/index.js";

afterEach(() => {
  cleanup();
  globalThis.localStorage?.clear();
  resetLanguage();
});
