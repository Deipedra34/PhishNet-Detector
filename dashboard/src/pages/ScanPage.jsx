import { useRef, useState } from "react";
import { defaultClient } from "../api/client.js";
import ScanResultCard from "../components/ScanResultCard.jsx";

const MODES = [
  { id: "url", label: "URL" },
  { id: "email", label: "Email" },
];

/** Same limit the API enforces on request bodies. */
const MAX_EMAIL_BYTES = 5 * 1024 * 1024;

export default function ScanPage() {
  const [mode, setMode] = useState("url");
  const [url, setUrl] = useState("");
  const [rawEmail, setRawEmail] = useState("");
  const [emailFile, setEmailFile] = useState(null);
  const fileInput = useRef(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  async function runScan(scan) {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await scan(defaultClient()));
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  function handleUrlSubmit(event) {
    event.preventDefault();
    const target = url.trim();
    if (!target) {
      setError("Enter a URL to scan.");
      return;
    }
    runScan((client) => client.scanUrl(target));
  }

  function handleEmailSubmit(event) {
    event.preventDefault();
    if (emailFile) {
      if (emailFile.size === 0) {
        setError("The selected file is empty.");
        return;
      }
      if (emailFile.size > MAX_EMAIL_BYTES) {
        setError("The selected file is larger than the 5 MB the API accepts.");
        return;
      }
      runScan((client) => client.scanEmailFile(emailFile));
      return;
    }
    if (!rawEmail.trim()) {
      setError("Paste the full email source (headers and body), or choose an .eml file.");
      return;
    }
    runScan((client) => client.scanEmailText(rawEmail));
  }

  function clearFile() {
    setEmailFile(null);
    if (fileInput.current) {
      fileInput.current.value = "";
    }
  }

  function switchMode(next) {
    setMode(next);
    setError(null);
  }

  return (
    <section>
      <h1>Scan</h1>
      <p className="muted">Check a URL or an email message for phishing indicators.</p>

      <div className="tabs" role="tablist" aria-label="What to scan">
        {MODES.map((item) => (
          <button
            key={item.id}
            type="button"
            role="tab"
            aria-selected={mode === item.id}
            className={mode === item.id ? "tab active" : "tab"}
            onClick={() => switchMode(item.id)}
          >
            {item.label}
          </button>
        ))}
      </div>

      {mode === "url" ? (
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
      ) : (
        <form className="scan-form" onSubmit={handleEmailSubmit}>
          <label htmlFor="scan-email-file">Upload an .eml file</label>
          <div className="file-row">
            <input
              id="scan-email-file"
              ref={fileInput}
              type="file"
              accept=".eml,message/rfc822,text/plain"
              onChange={(event) => setEmailFile(event.target.files?.[0] ?? null)}
              disabled={busy}
            />
            {emailFile ? (
              <button type="button" className="link-button" onClick={clearFile} disabled={busy}>
                Clear
              </button>
            ) : null}
          </div>

          <label htmlFor="scan-email-raw">or paste the raw email source</label>
          <textarea
            id="scan-email-raw"
            rows={10}
            spellCheck={false}
            placeholder={"From: \"PayPal\" <service@paypa1-support.tk>\nSubject: Your account is suspended\n\n..."}
            value={rawEmail}
            onChange={(event) => setRawEmail(event.target.value)}
            disabled={busy || emailFile !== null}
          />
          <button type="submit" disabled={busy}>
            {busy ? "Scanning..." : "Scan email"}
          </button>
        </form>
      )}

      {error ? (
        <p className="error" role="alert">
          {error}
        </p>
      ) : null}
      {result ? <ScanResultCard result={result} /> : null}
    </section>
  );
}
