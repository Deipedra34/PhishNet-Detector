import { formatNumber } from "../format.js";
import { useI18n } from "../i18n/index.js";

/** Number of pages needed for `total` items, at least 1. */
export function pageCount(total, pageSize) {
  return Math.max(1, Math.ceil((total ?? 0) / pageSize));
}

/** Previous/next controls with a "21–40 of 135" summary. `page` is 1-based. */
export default function Pagination({ page, pageSize, total, onPageChange, disabled }) {
  const { t } = useI18n();
  const pages = pageCount(total, pageSize);
  if (total <= pageSize && page === 1) {
    return null;
  }
  const first = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const last = Math.min(total, page * pageSize);
  return (
    <nav className="pagination" aria-label={t("pagination.label")}>
      <button type="button" onClick={() => onPageChange(1)} disabled={disabled || page <= 1}>
        {t("pagination.first")}
      </button>
      <button type="button" onClick={() => onPageChange(page - 1)} disabled={disabled || page <= 1}>
        {t("pagination.previous")}
      </button>
      <span className="pagination-status">
        {t("pagination.status", {
          first: formatNumber(first),
          last: formatNumber(last),
          total: formatNumber(total),
          page: formatNumber(page),
          pages: formatNumber(pages),
        })}
      </span>
      <button type="button" onClick={() => onPageChange(page + 1)} disabled={disabled || page >= pages}>
        {t("pagination.next")}
      </button>
      <button type="button" onClick={() => onPageChange(pages)} disabled={disabled || page >= pages}>
        {t("pagination.last")}
      </button>
    </nav>
  );
}
