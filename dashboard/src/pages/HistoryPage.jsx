import { useEffect, useState } from "react";
import { defaultClient } from "../api/client.js";
import RiskBadge from "../components/RiskBadge.jsx";
import { formatAgeDays, formatDateTime, formatNumber } from "../format.js";

const PAGE_SIZE = 20;

export default function HistoryPage() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    defaultClient()
      .history({ limit: PAGE_SIZE })
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
  }, []);

  return (
    <section>
      <h1>History</h1>
      <p className="muted">Past scans recorded by the CLI and the API, newest first.</p>

      {error ? (
        <p className="error" role="alert">
          {error}
        </p>
      ) : null}

      {data ? (
        <>
          <p className="muted">{formatNumber(data.total)} scans recorded</p>
          <HistoryTable scans={data.scans} loading={loading} />
        </>
      ) : loading ? (
        <p className="muted">Loading...</p>
      ) : null}
    </section>
  );
}

function HistoryTable({ scans, loading }) {
  if (scans.length === 0) {
    return <p className="empty">No scans recorded yet. Scan something on the Scan page, or with the CLI.</p>;
  }
  return (
    <div className="table-wrap" aria-busy={loading}>
      <table className="data-table">
        <thead>
          <tr>
            <th scope="col">When</th>
            <th scope="col">Type</th>
            <th scope="col">Target</th>
            <th scope="col">Risk</th>
            <th scope="col" className="num">
              Score
            </th>
            <th scope="col">Domain age</th>
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => (
            <tr key={scan.id}>
              <td className="nowrap">{formatDateTime(scan.timestamp)}</td>
              <td>{scan.type}</td>
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
