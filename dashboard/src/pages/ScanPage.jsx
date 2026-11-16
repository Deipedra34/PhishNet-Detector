import { useState } from "react";
import { defaultClient } from "../api/client.js";
import ScanResultCard from "../components/ScanResultCard.jsx";

export default function ScanPage() {
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  async function handleUrlSubmit(event) {
    event.preventDefault();
    const target = url.trim();
    if (!target) {
      setError("Enter a URL to scan.");
      return;
    }
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await defaultClient().scanUrl(target));
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section>
      <h1>Scan</h1>
      <p className="muted">Check a URL or an email message for phishing indicators.</p>

      <form className="scan-form" onSubmit={handleUrlSubmit}>
        <label htmlFor="scan-url">URL</label>
        <input
          id="scan-url"
          type="text"
          inputMode="url"
          placeholder="https://example.com/login"
          value={url}
          onChange={(event) => setUrl(event.target.value)}
          disabled={busy}
        />
        <button type="submit" disabled={busy}>
          {busy ? "Scanning..." : "Scan URL"}
        </button>
      </form>

      {error ? (
        <p className="error" role="alert">
          {error}
        </p>
      ) : null}
      {result ? <ScanResultCard result={result} /> : null}
    </section>
  );
}
