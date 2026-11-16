import { useCallback, useEffect, useState } from "react";
import { defaultClient } from "../api/client.js";
import { formatDateTime, formatDuration, formatNumber } from "../format.js";

/** How each state reads, as `phishnet feeds status` describes it. */
const STATES = {
  FRESH: { label: "Fresh", tone: "good", text: "Cached and available to scans." },
  STALE: {
    label: "Stale",
    tone: "warning",
    text: "The cached copy is still used by scans; it's refreshed on the next CLI scan or `phishnet feeds update`.",
  },
  MISSING: {
    label: "Missing",
    tone: "critical",
    text: "Nothing cached yet, so scans skip this feed. Run `phishnet feeds update`.",
  },
  DISABLED: { label: "Disabled", tone: "neutral", text: "Turned off in the config." },
  NOT_CONFIGURED: { label: "Not configured", tone: "neutral", text: null },
  OFF: { label: "Off", tone: "neutral", text: null },
};

export default function FeedsPage() {
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
        <h1>Threat feeds</h1>
        <button type="button" onClick={load} disabled={loading}>
          {loading ? "Checking..." : "Refresh status"}
        </button>
      </div>
      <p className="muted">
        Cache state of the OpenPhish and PhishTank feeds scans are checked against. This page only reads the cache; to
        download the feeds now, run <code>phishnet feeds update</code>.
      </p>

      {error ? (
        <p className="error" role="alert">
          {error}
        </p>
      ) : null}

      {status ? (
        <>
          <dl className="details feed-meta">
            <dt>Cache directory</dt>
            <dd>
              <code>{status.cacheDirectory}</code>
            </dd>
            <dt>Refresh interval</dt>
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
  const state = STATES[feed.state] ?? { label: feed.state, tone: "neutral", text: null };
  const explanation = state.text ?? feed.detail;
  const showCacheFacts = feed.available || feed.state === "MISSING";
  return (
    <article className="panel feed-card" aria-label={`${feed.name} feed`}>
      <header className="feed-card-header">
        <h2>{feed.name}</h2>
        <span className={`state-badge tone-${state.tone}`}>{state.label}</span>
      </header>
      {explanation ? <p className="muted">{explanation}</p> : null}
      {showCacheFacts ? (
        <dl className="details">
          <dt>Last refresh</dt>
          <dd>
            {feed.refreshedAt
              ? `${formatDateTime(feed.refreshedAt)} (${formatDuration(feed.ageSeconds)} ago)`
              : "Never"}
          </dd>
          <dt>Entries</dt>
          <dd>{formatNumber(feed.entries)}</dd>
        </dl>
      ) : null}
      {feed.lastError ? (
        <p className="feed-error">
          <strong>Last download failed:</strong> {feed.lastError}
        </p>
      ) : null}
    </article>
  );
}
