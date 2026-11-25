import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App.jsx";
import { getLanguage } from "./i18n/index.js";
import "./index.css";

document.documentElement.lang = getLanguage();

createRoot(document.getElementById("root")).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
