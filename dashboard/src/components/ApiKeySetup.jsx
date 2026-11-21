import { useState } from "react";
import {
  ApiError,
  createApiClient,
  getConfiguredBaseUrl,
  getStoredApiKey,
  normalizeApiKey,
  setStoredApiKey,
} from "../api/client.js";

/**
 * The screen for entering the API key. The key is checked against the server
 * (GET /api/auth/check) before it's saved in this browser's local storage.
 */
export default function ApiKeySetup({ onSaved }) {
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
      setMessage("Paste the API key first.");
      return;
    }
    setBusy(true);
    setMessage(null);
    try {
      await createApiClient({ baseUrl: getConfiguredBaseUrl(), apiKey: key }).authCheck();
    } catch (e) {
      setBusy(false);
      setMessage(e instanceof ApiError && e.kind === "auth"
        ? "The server rejected that key. Check that you copied all of it."
        : e.message);
      return;
    }
    setStoredApiKey(key);
    onSaved();
  }

  return (
    <section className="key-setup" aria-labelledby="key-setup-title">
      <h1 id="key-setup-title">{hadKey ? "Your API key was not accepted" : "Enter your API key"}</h1>
      <p>
        {hadKey
          ? "The server rejected the API key saved in this browser - it may have been replaced. "
          : "This PhishNet server requires an API key. "}
        <code>phishnet serve</code> prints the key when it first starts and stores it in{" "}
        <code>~/.phishnet/api-key</code> on the server. To make a new one, run{" "}
        <code>phishnet serve --regenerate-key</code>.
      </p>
      <form onSubmit={save}>
        <label htmlFor="api-key">API key</label>
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
            <input type="checkbox" checked={show} onChange={(event) => setShow(event.target.checked)} /> Show
          </label>
        </div>
        <button type="submit" disabled={busy}>
          {busy ? "Checking..." : "Save"}
        </button>
        {message ? (
          <p className="error" role="alert">
            {message}
          </p>
        ) : null}
      </form>
      <p className="muted small">
        The key is kept in this browser&apos;s local storage. &quot;Forget API key&quot; at the bottom of the page
        removes it.
      </p>
    </section>
  );
}
