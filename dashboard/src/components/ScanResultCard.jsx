/** One scan result as returned by POST /api/scan/url or /api/scan/email. */
export default function ScanResultCard({ result }) {
  const signals = result.signals ?? [];
  return (
    <article className="result-card" aria-label="Scan result">
      <header>
        <h2>{result.level} risk</h2>
        <p>
          Score {result.score}/100 · {result.type}
        </p>
        <p className="result-target">{result.target}</p>
      </header>

      <p>{result.recommendation}</p>

      <h3>Matched signals ({signals.length})</h3>
      {signals.length === 0 ? (
        <p className="muted">No phishing indicators matched.</p>
      ) : (
        <ul>
          {signals.map((signal, index) => (
            <li key={`${signal.id}-${index}`}>
              {signal.description}
              {signal.evidence ? <code> {signal.evidence}</code> : null}
            </li>
          ))}
        </ul>
      )}

      {result.domainAge ? <DomainAge domainAge={result.domainAge} /> : null}
    </article>
  );
}

function DomainAge({ domainAge }) {
  let text;
  switch (domainAge.status) {
    case "KNOWN":
      text = `${domainAge.domain}: registered ${domainAge.creationDate} (${domainAge.age})`;
      break;
    case "UNKNOWN":
      text = `${domainAge.domain ?? "Domain"}: unknown${domainAge.reason ? ` (${domainAge.reason})` : ""}`;
      break;
    default:
      text = "Not checked (WHOIS lookups are off on this server)";
  }
  return (
    <>
      <h3>Domain age</h3>
      <p>{text}</p>
    </>
  );
}
