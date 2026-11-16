// Small display helpers shared by the dashboard's pages.

const DATE_TIME = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
const NUMBER = new Intl.NumberFormat();

/** An ISO-8601 timestamp in the viewer's locale and time zone; "—" when missing or unreadable. */
export function formatDateTime(iso) {
  if (!iso) {
    return "—";
  }
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? "—" : DATE_TIME.format(date);
}

/** "1,234". */
export function formatNumber(value) {
  return NUMBER.format(value ?? 0);
}

/** A domain age in days as "12 days", "5 months", "3 years"; "—" when unknown. */
export function formatAgeDays(days) {
  if (days === null || days === undefined) {
    return "—";
  }
  if (days < 60) {
    return plural(days, "day");
  }
  if (days < 730) {
    return plural(Math.floor(days / 30), "month");
  }
  return plural(Math.floor(days / 365), "year");
}

/** "45 seconds", "1 minute", "3 hours", "2 days": the largest whole unit (as `phishnet feeds status` shows it). */
export function formatDuration(seconds) {
  const s = Math.max(0, Math.floor(seconds ?? 0));
  if (s < 60) {
    return plural(s, "second");
  }
  if (s < 3600) {
    return plural(Math.floor(s / 60), "minute");
  }
  if (s < 86400) {
    return plural(Math.floor(s / 3600), "hour");
  }
  return plural(Math.floor(s / 86400), "day");
}

function plural(count, unit) {
  return `${count} ${unit}${count === 1 ? "" : "s"}`;
}
