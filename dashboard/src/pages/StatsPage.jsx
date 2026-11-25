import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { defaultClient, RISK_LEVELS } from "../api/client.js";
import { formatDateTime, formatNumber } from "../format.js";
import { useI18n } from "../i18n/index.js";

const TOP_DOMAINS = 10;

/** Share of `total`, as a whole percentage for labels. */
function percent(count, total) {
  return total > 0 ? Math.round((count / total) * 100) : 0;
}

export default function StatsPage() {
  const { t } = useI18n();
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
      <h1>{t("stats.title")}</h1>
      <p className="muted">{t("stats.intro")}</p>

      {error ? (
        <p className="error" role="alert">
          {error}
        </p>
      ) : null}
      {!stats && !error ? <p className="muted">{t("common.loading")}</p> : null}
      {stats ? <StatsView stats={stats} /> : null}
    </section>
  );
}

function StatsView({ stats }) {
  const { t } = useI18n();
  if (stats.total === 0) {
    return <p className="empty">{t("stats.empty")}</p>;
  }
  const flagged = (stats.byRiskLevel.MEDIUM ?? 0) + (stats.byRiskLevel.HIGH ?? 0);
  return (
    <>
      <div className="stat-tiles">
        <StatTile label={t("stats.total")} value={formatNumber(stats.total)} />
        <StatTile
          label={t("stats.flagged")}
          value={formatNumber(flagged)}
          note={t("stats.flaggedShare", { percent: percent(flagged, stats.total) })}
        />
        <StatTile
          label={t("stats.byType")}
          value={`${formatNumber(stats.byType.URL ?? 0)} / ${formatNumber(stats.byType.EMAIL ?? 0)}`}
        />
        <StatTile label={t("stats.firstScan")} value={formatDateTime(stats.firstScan)} small />
        <StatTile label={t("stats.lastScan")} value={formatDateTime(stats.lastScan)} small />
      </div>

      <div className="stats-grid">
        <section className="panel">
          <h2>{t("stats.byRisk")}</h2>
          <ul className="bar-list">
            {RISK_LEVELS.map((level) => {
              const count = stats.byRiskLevel[level] ?? 0;
              const label = t(`stats.level.${level}`);
              return (
                <li key={level} className="bar-row" title={t("stats.levelCount", { level: label, count: formatNumber(count) })}>
                  <Link className="bar-label" to={`/history?risk=${level}`}>
                    {label}
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
          <h2>{t("stats.topDomains")}</h2>
          {stats.topFlaggedDomains.length === 0 ? (
            <p className="muted">{t("stats.noFlaggedDomains")}</p>
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
  const { t } = useI18n();
  const max = Math.max(...domains.map((item) => item.count), 1);
  return (
    <ol className="bar-list">
      {domains.map((item) => (
        <li key={item.domain} className="bar-row" title={t("stats.domainCount", { domain: item.domain, count: formatNumber(item.count) })}>
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
