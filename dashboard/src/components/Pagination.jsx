import { formatNumber } from "../format.js";

/** Number of pages needed for `total` items, at least 1. */
export function pageCount(total, pageSize) {
  return Math.max(1, Math.ceil((total ?? 0) / pageSize));
}

/** Previous/next controls with a "21–40 of 135" summary. `page` is 1-based. */
export default function Pagination({ page, pageSize, total, onPageChange, disabled }) {
  const pages = pageCount(total, pageSize);
  if (total <= pageSize && page === 1) {
    return null;
  }
  const first = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const last = Math.min(total, page * pageSize);
  return (
    <nav className="pagination" aria-label="Pages">
      <button type="button" onClick={() => onPageChange(1)} disabled={disabled || page <= 1}>
        « First
      </button>
      <button type="button" onClick={() => onPageChange(page - 1)} disabled={disabled || page <= 1}>
        ‹ Previous
      </button>
      <span className="pagination-status">
        {formatNumber(first)}–{formatNumber(last)} of {formatNumber(total)} · page {formatNumber(page)} of{" "}
        {formatNumber(pages)}
      </span>
      <button type="button" onClick={() => onPageChange(page + 1)} disabled={disabled || page >= pages}>
        Next ›
      </button>
      <button type="button" onClick={() => onPageChange(pages)} disabled={disabled || page >= pages}>
        Last »
      </button>
    </nav>
  );
}
