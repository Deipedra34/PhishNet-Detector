import { useState } from "react";
import {
  ApiError,
  createApiClient,
  getConfiguredBaseUrl,
  getStoredApiKey,
  normalizeApiKey,
  setStoredApiKey,
} from "../api/client.js";
import { useI18n } from "../i18n/index.js";

/**
 * The screen for entering the API key. The key is checked against the server
 * (GET /api/auth/check) before it's saved in this browser's local storage.
 */
export default function ApiKeySetup({ onSaved }) {
  const { t, rich, language } = useI18n();
  const hadKey = Boolean(getStoredApiKey());
  const [value, setValue] = useState("");
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(null);

  async function save(event) {
    event.preventDefault();
    let key;
    try {
      key = normalizeApiKey(value);
    } catch (e) {
      setMessage(e.message);
      return;
    }
    if (!key) {
      setMessage(t("key.pasteFirst"));
      return;
    }
    setBusy(true);
    setMessage(null);
    try {
      await createApiClient({ baseUrl: getConfiguredBaseUrl(), apiKey: key, language }).authCheck();
    } catch (e) {
      setBusy(false);
      setMessage(e instanceof ApiError && e.kind === "auth" ? t("key.rejected") : e.message);
      return;
    }
    setStoredApiKey(key);
    onSaved();
  }

  return (
    <section className="key-setup" aria-labelledby="key-setup-title">
      <h1 id="key-setup-title">{t(hadKey ? "key.titleRejected" : "key.title")}</h1>
      <p>
        {t(hadKey ? "key.introRejected" : "key.intro")}{" "}
        {rich("key.where", {
          serve: <code>phishnet serve</code>,
          file: <code>~/.phishnet/api-key</code>,
          regenerate: <code>phishnet serve --regenerate-key</code>,
        })}
      </p>
      <form onSubmit={save}>
        <label htmlFor="api-key">{t("key.label")}</label>
        <div className="key-row">
          <input
            id="api-key"
            type={show ? "text" : "password"}
            autoComplete="off"
            spellCheck={false}
            value={value}
            onChange={(event) => setValue(event.target.value)}
            disabled={busy}
          />
          <label className="show-key">
            <input type="checkbox" checked={show} onChange={(event) => setShow(event.target.checked)} />{" "}
            {t("key.show")}
          </label>
        </div>
        <button type="submit" disabled={busy}>
          {busy ? t("common.checking") : t("common.save")}
        </button>
        {message ? (
          <p className="error" role="alert">
            {message}
          </p>
        ) : null}
      </form>
      <p className="muted small">{t("key.storageNote")}</p>
    </section>
  );
}
