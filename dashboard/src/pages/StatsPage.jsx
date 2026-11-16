import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { defaultClient, RISK_LEVELS } from "../api/client.js";
import { formatDateTime, formatNumber } from "../format.js";

const TOP_DOMAINS = 10;

const LEVEL_LABELS = { LOW: "Low", MEDIUM: "Medium", HIGH: "High" };

/** Share of `total`, as a whole percentage for labels. */
function percent(count, total) {
  return total > 0 ? Math.round((count / total) * 100) : 0;
}

export default function StatsPage() {
  const [stats, setStats] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    defaultClient()
      .historyStats({ top: TOP_DOMAINS })
      .then((body) => !cancelled && setStats(body))
      .catch((e) => !cancelled && setError(e.message));
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <section>
      <h1>Stats</h1>
      <p className="muted">Totals across the whole scan history, as `phishnet history stats` reports them.</p>

      {error ? (
        <p className="error" role="alert">
          {error}
        </p>
      ) : null}
      {!stats && !error ? <p className="muted">Loading...</p> : null}
      {stats ? <StatsView stats={stats} /> : null}
    </section>
  );
}

function StatsView({ stats }) {
  if (stats.total === 0) {
    return <p className="empty">No scans recorded yet, so there's nothing to summarize.</p>;
  }
  const flagged = (stats.byRiskLevel.MEDIUM ?? 0) + (stats.byRiskLevel.HIGH ?? 0);
  return (
    <>
      <div className="stat-tiles">
        <StatTile label="Total scans" value={formatNumber(stats.total)} />
        <StatTile
          label="Flagged (medium or high)"
          value={formatNumber(flagged)}
          note={`${percent(flagged, stats.total)}% of scans`}
        />
        <StatTile
          label="URLs / emails"
          value={`${formatNumber(stats.byType.URL ?? 0)} / ${formatNumber(stats.byType.EMAIL ?? 0)}`}
        />
        <StatTile label="First scan" value={formatDateTime(stats.firstScan)} small />
        <StatTile label="Last scan" value={formatDateTime(stats.lastScan)} small />
      </div>

      <div className="stats-grid">
        <section className="panel">
          <h2>Scans by risk level</h2>
          <ul className="bar-list">
            {RISK_LEVELS.map((level) => {
              const count = stats.byRiskLevel[level] ?? 0;
              return (
                <li key={level} className="bar-row" title={`${LEVEL_LABELS[level]}: ${formatNumber(count)} scans`}>
                  <Link className="bar-label" to={`/history?risk=${level}`}>
                    {LEVEL_LABELS[level]}
                  </Link>
                  <span className="bar-track">
                    <span
                      className={`bar-fill risk-${level.toLowerCase()}`}
                      style={{ width: `${percent(count, stats.total)}%` }}
                    />
                  </span>
                  <span className="bar-value">
                    {formatNumber(count)} <span className="muted">({percent(count, stats.total)}%)</span>
                  </span>
                </li>
              );
            })}
          </ul>
        </section>

        <section className="panel">
          <h2>Most frequently flagged domains</h2>
          {stats.topFlaggedDomains.length === 0 ? (
            <p className="muted">No domain has a medium or high risk scan yet.</p>
          ) : (
            <TopDomains domains={stats.topFlaggedDomains} />
          )}
        </section>
      </div>
    </>
  );
}

function StatTile({ label, value, note, small }) {
  return (
    <div className="stat-tile">
      <span className="stat-label">{label}</span>
      <span className={small ? "stat-value small-value" : "stat-value"}>{value}</span>
      {note ? <span className="muted small">{note}</span> : null}
    </div>
  );
}

function TopDomains({ domains }) {
  const max = Math.max(...domains.map((item) => item.count), 1);
  return (
    <ol className="bar-list">
      {domains.map((item) => (
        <li key={item.domain} className="bar-row" title={`${item.domain}: ${formatNumber(item.count)} flagged scans`}>
          <Link className="bar-label domain" to={`/history?target=${encodeURIComponent(item.domain)}`}>
            {item.domain}
          </Link>
          <span className="bar-track">
            <span className="bar-fill accent" style={{ width: `${(item.count / max) * 100}%` }} />
          </span>
          <span className="bar-value">{formatNumber(item.count)}</span>
        </li>
      ))}
    </ol>
  );
}
