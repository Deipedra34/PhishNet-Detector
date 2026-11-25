import { useRef, useState } from "react";
import { defaultClient } from "../api/client.js";
import ScanResultCard from "../components/ScanResultCard.jsx";
import { useI18n } from "../i18n/index.js";

const MODES = [
  { id: "url", label: "scan.mode.url" },
  { id: "email", label: "scan.mode.email" },
];

/** Same limit the API enforces on request bodies. */
const MAX_EMAIL_BYTES = 5 * 1024 * 1024;

export default function ScanPage() {
  const { t } = useI18n();
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
      setError(t("scan.enterUrl"));
      return;
    }
    runScan((client) => client.scanUrl(target));
  }

  function handleEmailSubmit(event) {
    event.preventDefault();
    if (emailFile) {
      if (emailFile.size === 0) {
        setError(t("scan.fileEmpty"));
        return;
      }
      if (emailFile.size > MAX_EMAIL_BYTES) {
        setError(t("scan.fileTooLarge"));
        return;
      }
      runScan((client) => client.scanEmailFile(emailFile));
      return;
    }
    if (!rawEmail.trim()) {
      setError(t("scan.pasteEmail"));
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
      <h1>{t("scan.title")}</h1>
      <p className="muted">{t("scan.intro")}</p>

      <div className="tabs" role="tablist" aria-label={t("scan.modes")}>
        {MODES.map((item) => (
          <button
            key={item.id}
            type="button"
            role="tab"
            aria-selected={mode === item.id}
            className={mode === item.id ? "tab active" : "tab"}
            onClick={() => switchMode(item.id)}
          >
            {t(item.label)}
          </button>
        ))}
      </div>

      {mode === "url" ? (
        <form className="scan-form" onSubmit={handleUrlSubmit}>
          <label htmlFor="scan-url">{t("scan.urlLabel")}</label>
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
            {busy ? t("scan.scanning") : t("scan.scanUrl")}
          </button>
        </form>
      ) : (
        <form className="scan-form" onSubmit={handleEmailSubmit}>
          <label htmlFor="scan-email-file">{t("scan.uploadLabel")}</label>
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
                {t("common.clear")}
              </button>
            ) : null}
          </div>

          <label htmlFor="scan-email-raw">{t("scan.rawLabel")}</label>
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
            {busy ? t("scan.scanning") : t("scan.scanEmail")}
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
