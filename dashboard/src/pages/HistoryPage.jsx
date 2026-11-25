import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { defaultClient, RISK_LEVELS } from "../api/client.js";
import Pagination, { pageCount } from "../components/Pagination.jsx";
import RiskBadge from "../components/RiskBadge.jsx";
import { formatAgeDays, formatDateTime, formatNumber } from "../format.js";
import { useI18n } from "../i18n/index.js";

const PAGE_SIZE = 20;
const SEARCH_DELAY_MS = 300;

export default function HistoryPage() {
  const { t } = useI18n();
  // Filters live in the address bar, so a filtered view can be bookmarked or shared.
  const [searchParams, setSearchParams] = useSearchParams();
  const target = searchParams.get("target") ?? "";
  const risk = searchParams.get("risk") ?? "";
  const type = searchParams.get("type") ?? "";
  const page = Math.max(1, Number.parseInt(searchParams.get("page") ?? "1", 10) || 1);

  const [targetInput, setTargetInput] = useState(target);
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  /** Applies filter changes; any change other than the page itself starts again from page 1. */
  function updateParams(changes) {
    const next = new URLSearchParams(searchParams);
    if (!("page" in changes)) {
      next.delete("page");
    }
    for (const [key, value] of Object.entries(changes)) {
      if (value) {
        next.set(key, value);
      } else {
        next.delete(key);
      }
    }
    setSearchParams(next, { replace: true });
  }

  // Search as the user types, once they pause.
  useEffect(() => {
    if (targetInput.trim() === target) {
      return undefined;
    }
    const timer = setTimeout(() => updateParams({ target: targetInput.trim() }), SEARCH_DELAY_MS);
    return () => clearTimeout(timer);
  }, [targetInput]);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    defaultClient()
      .history({ limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE, target, risk, type })
      .then((body) => {
        if (!cancelled) {
          setData(body);
          setError(null);
        }
      })
      .catch((e) => {
        if (!cancelled) {
          setError(e.message);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [target, risk, type, page]);

  // A page past the end (e.g. after scans were removed, or a stale bookmark): go to the last one.
  useEffect(() => {
    if (data && data.total > 0 && data.scans.length === 0 && page > pageCount(data.total, PAGE_SIZE)) {
      updateParams({ page: String(pageCount(data.total, PAGE_SIZE)) });
    }
  }, [data, page]);

  function goToPage(next) {
    updateParams({ page: next > 1 ? String(next) : "" });
    window.scrollTo?.({ top: 0 });
  }

  const filtered = Boolean(target || risk || type);

  function clearFilters() {
    setTargetInput("");
    setSearchParams(new URLSearchParams(), { replace: true });
  }

  return (
    <section>
      <h1>{t("history.title")}</h1>
      <p className="muted">{t("history.intro")}</p>

      <form className="filters" role="search" onSubmit={(event) => {
        event.preventDefault();
        updateParams({ target: targetInput.trim() });
      }}>
        <label className="filter">
          <span>{t("history.search")}</span>
          <input
            type="search"
            placeholder={t("history.searchPlaceholder")}
            value={targetInput}
            onChange={(event) => setTargetInput(event.target.value)}
          />
        </label>
        <label className="filter">
          <span>{t("history.risk")}</span>
          <select value={risk} onChange={(event) => updateParams({ risk: event.target.value })}>
            <option value="">{t("history.allLevels")}</option>
            {RISK_LEVELS.map((level) => (
              <option key={level} value={level}>
                {t(`risk.${level}`)}
              </option>
            ))}
          </select>
        </label>
        <label className="filter">
          <span>{t("history.type")}</span>
          <select value={type} onChange={(event) => updateParams({ type: event.target.value })}>
            <option value="">{t("history.allTypes")}</option>
            <option value="URL">{t("history.typeUrl")}</option>
            <option value="EMAIL">{t("history.typeEmail")}</option>
          </select>
        </label>
        {filtered ? (
          <button type="button" className="link-button" onClick={clearFilters}>
            {t("history.clearFilters")}
          </button>
        ) : null}
      </form>

      {error ? (
        <p className="error" role="alert">
          {error}
        </p>
      ) : null}

      {data ? (
        <>
          <p className="muted">
            {t(filtered ? "history.matching" : "history.recorded", { total: formatNumber(data.total) })}
          </p>
          <HistoryTable scans={data.scans} loading={loading} filtered={filtered} />
          <Pagination page={page} pageSize={PAGE_SIZE} total={data.total} onPageChange={goToPage} disabled={loading} />
        </>
      ) : loading ? (
        <p className="muted">{t("common.loading")}</p>
      ) : null}
    </section>
  );
}

function HistoryTable({ scans, loading, filtered }) {
  const { t } = useI18n();
  if (scans.length === 0) {
    return <p className="empty">{t(filtered ? "history.noMatches" : "history.empty")}</p>;
  }
  return (
    <div className="table-wrap" aria-busy={loading}>
      <table className="data-table">
        <thead>
          <tr>
            <th scope="col">{t("history.column.when")}</th>
            <th scope="col">{t("history.column.type")}</th>
            <th scope="col">{t("history.column.target")}</th>
            <th scope="col">{t("history.column.risk")}</th>
            <th scope="col" className="num">
              {t("history.column.score")}
            </th>
            <th scope="col">{t("history.column.domainAge")}</th>
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => (
            <tr key={scan.id}>
              <td className="nowrap">{formatDateTime(scan.timestamp)}</td>
              <td>{scan.type === "URL" || scan.type === "EMAIL" ? t(`type.${scan.type}`) : scan.type}</td>
              <td className="target-cell">
                <span title={scan.target}>{scan.target}</span>
                {scan.subject ? <span className="muted small">{scan.subject}</span> : null}
                {scan.reasons?.length ? (
                  <span className="muted small">{scan.reasons.map((reason) => reason.id).join(", ")}</span>
                ) : null}
              </td>
              <td>
                <RiskBadge level={scan.riskLevel} />
              </td>
              <td className="num">{scan.riskScore}</td>
              <td className="nowrap">{formatAgeDays(scan.domainAgeDays)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
