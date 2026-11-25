// Small display helpers shared by the dashboard's pages.

import { getLanguage, supportedLanguage, translate } from "./i18n/index.js";

const formatters = new Map();

/**
 * The locale for Intl formatting: the browser's own (with its regional conventions)
 * when the dashboard is shown in the browser's language, otherwise the chosen language.
 */
function localeFor(language) {
  return supportedLanguage(globalThis.navigator?.language) === language ? undefined : language;
}

function formatter(kind, language) {
  const cacheKey = `${kind}:${language}`;
  if (!formatters.has(cacheKey)) {
    const locale = localeFor(language);
    formatters.set(cacheKey, kind === "date"
      ? new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeStyle: "short" })
      : new Intl.NumberFormat(locale));
  }
  return formatters.get(cacheKey);
}

/** An ISO-8601 timestamp in the viewer's language and time zone; "—" when missing or unreadable. */
export function formatDateTime(iso, language = getLanguage()) {
  if (!iso) {
    return "—";
  }
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? "—" : formatter("date", language).format(date);
}

/** "1,234". */
export function formatNumber(value, language = getLanguage()) {
  return formatter("number", language).format(value ?? 0);
}

/** A domain age in days as "12 days", "5 months", "3 years"; "—" when unknown. */
export function formatAgeDays(days, language = getLanguage()) {
  if (days === null || days === undefined) {
    return "—";
  }
  if (days < 60) {
    return plural(days, "day", language);
  }
  if (days < 730) {
    return plural(Math.floor(days / 30), "month", language);
  }
  return plural(Math.floor(days / 365), "year", language);
}

/** "45 seconds", "1 minute", "3 hours", "2 days": the largest whole unit (as `phishnet feeds status` shows it). */
export function formatDuration(seconds, language = getLanguage()) {
  const s = Math.max(0, Math.floor(seconds ?? 0));
  if (s < 60) {
    return plural(s, "second", language);
  }
  if (s < 3600) {
    return plural(Math.floor(s / 60), "minute", language);
  }
  if (s < 86400) {
    return plural(Math.floor(s / 3600), "hour", language);
  }
  return plural(Math.floor(s / 86400), "day", language);
}

function plural(count, unit, language) {
  return translate(`duration.${unit}`, { count }, language);
}
