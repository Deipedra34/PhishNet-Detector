import { useEffect, useState } from "react";
import { ApiError, UNAUTHORIZED_EVENT, defaultClient } from "../api/client.js";
import { useI18n } from "../i18n/index.js";
import ApiKeySetup from "./ApiKeySetup.jsx";

/**
 * Shows the pages once the server accepts this browser's API key, or the key screen
 * when it doesn't. A server that can't be reached (or is older than 2.9.0 and has no
 * keys) still shows the pages, which report their own errors. If a request is
 * rejected later - say, after the key was regenerated - the key screen comes back.
 */
export default function AuthGate({ children }) {
  const { t } = useI18n();
  const [state, setState] = useState("checking");

  useEffect(() => {
    let cancelled = false;
    defaultClient()
      .authCheck()
      .then(() => {
        if (!cancelled) {
          setState("ok");
        }
      })
      .catch((error) => {
        if (!cancelled) {
          setState(error instanceof ApiError && error.kind === "auth" ? "needs-key" : "ok");
        }
      });
    const onUnauthorized = () => setState("needs-key");
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
    return () => {
      cancelled = true;
      window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
    };
  }, []);

  if (state === "checking") {
    return <p className="muted">{t("auth.connecting")}</p>;
  }
  if (state === "needs-key") {
    return <ApiKeySetup onSaved={() => setState("ok")} />;
  }
  return children;
}
