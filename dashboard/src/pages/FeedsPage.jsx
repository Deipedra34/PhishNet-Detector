import { useCallback, useEffect, useState } from "react";
import { defaultClient } from "../api/client.js";
import { formatDateTime, formatDuration, formatNumber } from "../format.js";
import { useI18n } from "../i18n/index.js";

/**
 * How each state reads, as `phishnet feeds status` describes it: its color, and
 * whether it has its own explanation ("feeds.state.<STATE>.text"). The others show
 * the server's detail instead.
 */
const STATES = {
  FRESH: { tone: "good", explained: true },
  STALE: { tone: "warning", explained: true },
  MISSING: { tone: "critical", explained: true },
  DISABLED: { tone: "neutral", explained: true },
  NOT_CONFIGURED: { tone: "neutral", explained: false },
  OFF: { tone: "neutral", explained: false },
};

export default function FeedsPage() {
  const { t, rich } = useI18n();
  const [status, setStatus] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    setLoading(true);
    defaultClient()
      .feedsStatus()
      .then((body) => {
        setStatus(body);
        setError(null);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(load, [load]);

  return (
    <section>
      <div className="page-title-row">
        <h1>{t("feeds.title")}</h1>
        <button type="button" onClick={load} disabled={loading}>
          {loading ? t("common.checking") : t("feeds.refresh")}
        </button>
      </div>
      <p className="muted">{rich("feeds.intro", { command: <code>phishnet feeds update</code> })}</p>

      {error ? (
        <p className="error" role="alert">
          {error}
        </p>
      ) : null}

      {status ? (
        <>
          <dl className="details feed-meta">
            <dt>{t("feeds.cacheDirectory")}</dt>
            <dd>
              <code>{status.cacheDirectory}</code>
            </dd>
            <dt>{t("feeds.refreshInterval")}</dt>
            <dd>{formatDuration(status.refreshIntervalSeconds)}</dd>
          </dl>
          <div className="feed-cards">
            {status.feeds.map((feed) => (
              <FeedCard key={feed.source} feed={feed} />
            ))}
          </div>
        </>
      ) : null}
    </section>
  );
}

function FeedCard({ feed }) {
  const { t } = useI18n();
  const known = Object.hasOwn(STATES, feed.state);
  const state = known ? STATES[feed.state] : { tone: "neutral", explained: false };
  const label = known ? t(`feeds.state.${feed.state}`) : feed.state;
  const explanation = state.explained ? t(`feeds.state.${feed.state}.text`) : feed.detail;
  const showCacheFacts = feed.available || feed.state === "MISSING";
  return (
    <article className="panel feed-card" aria-label={t("feeds.cardLabel", { name: feed.name })}>
      <header className="feed-card-header">
        <h2>{feed.name}</h2>
        <span className={`state-badge tone-${state.tone}`}>{label}</span>
      </header>
      {explanation ? <p className="muted">{explanation}</p> : null}
      {showCacheFacts ? (
        <dl className="details">
          <dt>{t("feeds.lastRefresh")}</dt>
          <dd>
            {feed.refreshedAt
              ? t("feeds.refreshedAgo", { time: formatDateTime(feed.refreshedAt), age: formatDuration(feed.ageSeconds) })
              : t("feeds.never")}
          </dd>
          <dt>{t("feeds.entries")}</dt>
          <dd>{formatNumber(feed.entries)}</dd>
        </dl>
      ) : null}
      {feed.lastError ? (
        <p className="feed-error">
          <strong>{t("feeds.lastError")}</strong> {feed.lastError}
        </p>
      ) : null}
    </article>
  );
}
