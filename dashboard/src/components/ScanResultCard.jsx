import { useI18n } from "../i18n/index.js";
import "./ScanResultCard.css";

/** Signal ids raised when a URL or its domain is listed in a threat intelligence feed, and their label keys. */
export const FEED_SIGNAL_IDS = {
  knownPhishingUrl: "result.feed.knownPhishingUrl",
  knownPhishingDomain: "result.feed.knownPhishingDomain",
};

const LEVELS = ["LOW", "MEDIUM", "HIGH"];

/** CSS modifier for a risk level: "risk-low", "risk-medium", "risk-high", or "risk-unknown". */
export function riskClass(level) {
  return LEVELS.includes(level) ? `risk-${level.toLowerCase()}` : "risk-unknown";
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

/**
 * One scan result as returned by POST /api/scan/url or /api/scan/email. Its
 * recommendation and signal descriptions are shown as the API wrote them (in the
 * language the client asked for).
 */
export default function ScanResultCard({ result }) {
  const { t } = useI18n();
  const signals = result.signals ?? [];
  const feedMatches = signals.filter((signal) => FEED_SIGNAL_IDS[signal.id]);
  const ml = mlConfidencePercent(result);
  const score = Math.min(100, Math.max(0, Number(result.score) || 0));

  return (
    <article className={`result-card ${riskClass(result.level)}`} aria-label={t("result.label")}>
      <header className="result-header">
        <div className="result-level">
          <span className="risk-badge" data-testid="risk-badge">
            {LEVELS.includes(result.level) ? t(`result.level.${result.level}`) : result.level}
          </span>
          <span className="result-type">{result.type}</span>
        </div>
        <div className="result-score" aria-label={t("result.scoreLabel", { score })}>
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
        <div className="feed-matches" aria-label={t("result.feedMatches")}>
          {feedMatches.map((signal, index) => (
            <span key={`${signal.id}-${index}`} className="feed-label" title={signal.description}>
              {t("result.feedMatch", { label: t(FEED_SIGNAL_IDS[signal.id]) })}
            </span>
          ))}
        </div>
      ) : null}

      <div className="result-grid">
        {result.domainAge ? <DomainAge domainAge={result.domainAge} /> : null}
        {ml !== null ? (
          <section className="result-fact">
            <h3>{t("result.ml.title")}</h3>
            <p className="fact-value">{t("result.ml.value", { percent: ml })}</p>
            <div className="ml-meter" role="presentation">
              <div className="ml-meter-fill" style={{ width: `${ml}%` }} />
            </div>
            <p className="muted small">{t("result.ml.note")}</p>
          </section>
        ) : null}
      </div>

      <section className="result-section">
        <h3>{t("result.signals.title", { count: signals.length })}</h3>
        {signals.length === 0 ? (
          <p className="muted">{t("result.signals.none")}</p>
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
  const { t } = useI18n();
  let value;
  let detail = null;
  switch (domainAge.status) {
    case "KNOWN":
      value = domainAge.age;
      detail = t("result.domainAge.registered", { domain: domainAge.domain, date: domainAge.creationDate });
      break;
    case "UNKNOWN":
      value = t("result.domainAge.unknown");
      detail = [domainAge.domain, domainAge.reason].filter(Boolean).join(": ");
      break;
    default:
      value = t("result.domainAge.notChecked");
      detail = t("result.domainAge.off");
  }
  return (
    <section className="result-fact">
      <h3>{t("result.domainAge.title")}</h3>
      <p className="fact-value">{value}</p>
      {detail ? <p className="muted small">{detail}</p> : null}
    </section>
  );
}

function EmailDetails({ email }) {
  const { t } = useI18n();
  const links = email.links ?? [];
  return (
    <section className="result-section">
      <h3>{t("result.email.title")}</h3>
      <dl className="details">
        <dt>{t("result.email.from")}</dt>
        <dd>
          {email.displayName ? `${email.displayName} ` : ""}
          {email.from ? `<${email.from}>` : t("common.none")}
        </dd>
        {email.replyTo ? (
          <>
            <dt>{t("result.email.replyTo")}</dt>
            <dd>{email.replyTo}</dd>
          </>
        ) : null}
        <dt>{t("result.email.subject")}</dt>
        <dd>{email.subject || t("common.none")}</dd>
        <dt>{t("result.email.links", { count: links.length })}</dt>
        <dd>
          {links.length === 0 ? (
            t("result.email.noLinks")
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
