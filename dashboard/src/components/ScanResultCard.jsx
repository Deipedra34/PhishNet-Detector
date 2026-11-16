import "./ScanResultCard.css";

/** Signal ids raised when a URL or its domain is listed in a threat intelligence feed. */
export const FEED_SIGNAL_IDS = {
  knownPhishingUrl: "Listed URL",
  knownPhishingDomain: "Listed domain",
};

const LEVEL_LABELS = {
  LOW: "Low risk",
  MEDIUM: "Medium risk",
  HIGH: "High risk",
};

/** CSS modifier for a risk level: "risk-low", "risk-medium", "risk-high", or "risk-unknown". */
export function riskClass(level) {
  return LEVEL_LABELS[level] ? `risk-${level.toLowerCase()}` : "risk-unknown";
}

/**
 * The ML layer's phishing probability as a whole percentage, or null when the
 * result doesn't carry one. The CLI's human-readable URL report shows it; API
 * results include it only when the server adds an `ml` object.
 */
export function mlConfidencePercent(result) {
  const probability = result?.ml?.probability ?? result?.mlProbability;
  if (typeof probability !== "number" || Number.isNaN(probability)) {
    return null;
  }
  const percent = probability <= 1 ? probability * 100 : probability;
  return Math.round(Math.min(100, Math.max(0, percent)));
}

/** One scan result as returned by POST /api/scan/url or /api/scan/email. */
export default function ScanResultCard({ result }) {
  const signals = result.signals ?? [];
  const feedMatches = signals.filter((signal) => FEED_SIGNAL_IDS[signal.id]);
  const ml = mlConfidencePercent(result);
  const score = Math.min(100, Math.max(0, Number(result.score) || 0));

  return (
    <article className={`result-card ${riskClass(result.level)}`} aria-label="Scan result">
      <header className="result-header">
        <div className="result-level">
          <span className="risk-badge" data-testid="risk-badge">
            {LEVEL_LABELS[result.level] ?? result.level}
          </span>
          <span className="result-type">{result.type}</span>
        </div>
        <div className="result-score" aria-label={`Risk score ${score} out of 100`}>
          <span className="result-score-value">{score}</span>
          <span className="result-score-max">/100</span>
        </div>
      </header>

      <div className="score-meter" role="presentation">
        <div className="score-meter-fill" style={{ width: `${score}%` }} />
      </div>

      <p className="result-target" title={result.target}>
        {result.target}
      </p>
      <p className="result-recommendation">{result.recommendation}</p>

      {feedMatches.length > 0 ? (
        <div className="feed-matches" aria-label="Threat feed matches">
          {feedMatches.map((signal, index) => (
            <span key={`${signal.id}-${index}`} className="feed-label" title={signal.description}>
              Threat feed: {FEED_SIGNAL_IDS[signal.id]}
            </span>
          ))}
        </div>
      ) : null}

      <div className="result-grid">
        {result.domainAge ? <DomainAge domainAge={result.domainAge} /> : null}
        {ml !== null ? (
          <section className="result-fact">
            <h3>ML confidence</h3>
            <p className="fact-value">{ml}% phishing</p>
            <div className="ml-meter" role="presentation">
              <div className="ml-meter-fill" style={{ width: `${ml}%` }} />
            </div>
            <p className="muted small">Experimental; an extra signal, not part of the score.</p>
          </section>
        ) : null}
      </div>

      <section className="result-section">
        <h3>Matched signals ({signals.length})</h3>
        {signals.length === 0 ? (
          <p className="muted">No phishing indicators matched.</p>
        ) : (
          <ul className="signal-list">
            {signals.map((signal, index) => (
              <li key={`${signal.id}-${index}`} className={FEED_SIGNAL_IDS[signal.id] ? "signal feed" : "signal"}>
                <span className="signal-category">{signal.category}</span>
                <span className="signal-text">
                  {signal.description}
                  {signal.evidence ? <code className="signal-evidence">{signal.evidence}</code> : null}
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>

      {result.email ? <EmailDetails email={result.email} /> : null}
    </article>
  );
}

function DomainAge({ domainAge }) {
  let value;
  let detail = null;
  switch (domainAge.status) {
    case "KNOWN":
      value = domainAge.age;
      detail = `${domainAge.domain}, registered ${domainAge.creationDate}`;
      break;
    case "UNKNOWN":
      value = "Unknown";
      detail = [domainAge.domain, domainAge.reason].filter(Boolean).join(": ");
      break;
    default:
      value = "Not checked";
      detail = "WHOIS lookups are turned off on this server.";
  }
  return (
    <section className="result-fact">
      <h3>Domain age</h3>
      <p className="fact-value">{value}</p>
      {detail ? <p className="muted small">{detail}</p> : null}
    </section>
  );
}

function EmailDetails({ email }) {
  const links = email.links ?? [];
  return (
    <section className="result-section">
      <h3>Email</h3>
      <dl className="details">
        <dt>From</dt>
        <dd>
          {email.displayName ? `${email.displayName} ` : ""}
          {email.from ? `<${email.from}>` : "(none)"}
        </dd>
        {email.replyTo ? (
          <>
            <dt>Reply-To</dt>
            <dd>{email.replyTo}</dd>
          </>
        ) : null}
        <dt>Subject</dt>
        <dd>{email.subject || "(none)"}</dd>
        <dt>Links ({links.length})</dt>
        <dd>
          {links.length === 0 ? (
            "None"
          ) : (
            <ul className="link-list">
              {links.map((link, index) => (
                <li key={index}>
                  <code>{link}</code>
                </li>
              ))}
            </ul>
          )}
        </dd>
      </dl>
    </section>
  );
}
