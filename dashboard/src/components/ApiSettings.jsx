import { useEffect, useState } from "react";
import {
  API_KEY_CHANGED_EVENT,
  createApiClient,
  getConfiguredBaseUrl,
  getStoredApiKey,
  normalizeBaseUrl,
  setConfiguredBaseUrl,
  setStoredApiKey,
} from "../api/client.js";
import { useI18n } from "../i18n/index.js";

/**
 * Footer control for the API address. Blank (the default) means "the server this
 * dashboard was loaded from"; anything else is remembered in this browser.
 */
export default function ApiSettings() {
  const { t, language } = useI18n();
  const current = getConfiguredBaseUrl();
  const [editing, setEditing] = useState(false);
  const [value, setValue] = useState(current);
  const [message, setMessage] = useState(null);
  const [busy, setBusy] = useState(false);
  const [hasKey, setHasKey] = useState(() => Boolean(getStoredApiKey()));

  // The key screen can save a key after this footer has rendered.
  useEffect(() => {
    const update = () => setHasKey(Boolean(getStoredApiKey()));
    window.addEventListener(API_KEY_CHANGED_EVENT, update);
    return () => window.removeEventListener(API_KEY_CHANGED_EVENT, update);
  }, []);

  async function save(event) {
    event.preventDefault();
    let normalized;
    try {
      normalized = normalizeBaseUrl(value);
    } catch (e) {
      setMessage({ error: true, text: e.message });
      return;
    }
    setBusy(true);
    setMessage(null);
    try {
      await createApiClient({ baseUrl: normalized, language }).health();
    } catch (e) {
      setBusy(false);
      setMessage({ error: true, text: t("settings.notSaved", { message: e.message }) });
      return;
    }
    setConfiguredBaseUrl(normalized);
    // Every page reads the setting when it loads its data, so start over with it.
    window.location.reload();
  }

  function reset() {
    setConfiguredBaseUrl("");
    window.location.reload();
  }

  function forgetKey() {
    setStoredApiKey("");
    window.location.reload();
  }

  if (!editing) {
    return (
      <div className="api-settings">
        <span className="muted">
          {t("settings.api")} <code>{current || t("settings.thisServer")}</code>
        </span>
        <button type="button" className="link-button" onClick={() => setEditing(true)}>
          {t("settings.change")}
        </button>
        {hasKey ? (
          <button type="button" className="link-button" onClick={forgetKey}>
            {t("settings.forgetKey")}
          </button>
        ) : null}
      </div>
    );
  }

  return (
    <form className="api-settings" onSubmit={save}>
      <label htmlFor="api-base-url" className="muted">
        {t("settings.address")}
      </label>
      <input
        id="api-base-url"
        type="text"
        placeholder={t("settings.placeholder")}
        value={value}
        onChange={(event) => setValue(event.target.value)}
        disabled={busy}
      />
      <button type="submit" disabled={busy}>
        {busy ? t("common.checking") : t("common.save")}
      </button>
      {current ? (
        <button type="button" className="link-button" onClick={reset} disabled={busy}>
          {t("settings.useThisServer")}
        </button>
      ) : null}
      <button type="button" className="link-button" onClick={() => setEditing(false)} disabled={busy}>
        {t("common.cancel")}
      </button>
      {message ? (
        <p className={message.error ? "error" : "muted"} role="status">
          {message.text}
        </p>
      ) : null}
    </form>
  );
}
