// Translations for the popup and the settings page, from _locales/<lang>/messages.json.
//
// browser.i18n / chrome.i18n always follow the browser's UI language, so the
// language picked in Settings is applied by reading that language's messages.json
// directly (same file format, same placeholder rules). Until it has loaded, and for
// anything it lacks, the browser's own i18n API answers. Text from the API itself
// (scan results, error messages) is requested in the same language.

const ext = globalThis.browser ?? globalThis.chrome;

/** Storage key for the language picked in Settings: "en", "tr", or absent for automatic. */
export const LANGUAGE_KEY = "language";

/** Value of the "automatic" choice: follow the browser's UI language. */
export const AUTO_LANGUAGE = "auto";

/** Languages with a _locales folder; the first is the default. */
export const LANGUAGES = ["en", "tr"];

/** Each language's name in that language, for the picker. */
export const LANGUAGE_NAMES = { en: "English", tr: "Türkçe" };

let active = null;

/** The supported language for a tag such as "tr-TR" or "tr_TR", or null. */
export function supportedLanguage(tag) {
  const language = String(tag ?? "").trim().toLowerCase().split(/[-_]/)[0];
  return LANGUAGES.includes(language) ? language : null;
}

/** The browser's UI language if it's supported, else English. */
export function browserLanguage() {
  return supportedLanguage(ext?.i18n?.getUILanguage?.() ?? globalThis.navigator?.language) ?? LANGUAGES[0];
}

/** "en", "tr", or AUTO_LANGUAGE. */
export async function getLanguageSetting() {
  const stored = await ext.storage.local.get(LANGUAGE_KEY);
  return supportedLanguage(stored[LANGUAGE_KEY]) ?? AUTO_LANGUAGE;
}

export async function setLanguageSetting(value) {
  const language = supportedLanguage(value);
  if (language) {
    await ext.storage.local.set({ [LANGUAGE_KEY]: language });
  } else {
    await ext.storage.local.remove(LANGUAGE_KEY);
  }
}

async function fetchMessages(language) {
  const response = await fetch(ext.runtime.getURL(`_locales/${language}/messages.json`));
  return response.json();
}

/**
 * Loads the messages for the language in effect (the setting, else the browser's
 * language) and resolves to that language. Never rejects: if the files can't be
 * read, the browser's own i18n API is used instead.
 */
export async function initI18n() {
  let language = browserLanguage();
  try {
    const setting = await getLanguageSetting();
    language = setting === AUTO_LANGUAGE ? browserLanguage() : setting;
    const [messages, fallback] = await Promise.all([
      fetchMessages(language),
      language === LANGUAGES[0] ? null : fetchMessages(LANGUAGES[0]),
    ]);
    active = { language, messages, fallback: fallback ?? messages };
  } catch {
    active = null;
  }
  if (globalThis.document?.documentElement) {
    globalThis.document.documentElement.lang = language;
  }
  return language;
}

/** The language the extension is shown in. */
export function currentLanguage() {
  return active?.language ?? browserLanguage();
}

/** Fills in a messages.json entry like browser.i18n.getMessage does: $NAME$ placeholders, $1-$9, and $$. */
function format(entry, substitutions) {
  const withPlaceholders = entry.message.replace(/\$([A-Za-z0-9_@]+)\$/g, (match, name) => {
    const placeholder = entry.placeholders?.[name.toLowerCase()];
    return placeholder ? placeholder.content : match;
  });
  return withPlaceholders.replace(/\$\$|\$([1-9])/g, (match, index) =>
    index === undefined ? "$" : (substitutions[index - 1] ?? ""),
  );
}

/** The message `key` in the current language, with `substitutions` for $1, $2, ... */
export function t(key, ...substitutions) {
  const values = substitutions.map((value) => String(value));
  if (active) {
    const entry = active.messages[key] ?? active.fallback[key];
    if (entry?.message !== undefined) {
      return format(entry, values);
    }
  }
  return ext?.i18n?.getMessage?.(key, values) || key;
}

/** Sets an element's text; parts between `backticks` become <code> elements. */
export function setRichText(element, text) {
  element.replaceChildren(...text.split("`").map((part, index) => {
    if (index % 2 === 0) {
      return part;
    }
    const code = document.createElement("code");
    code.textContent = part;
    return code;
  }));
}

/**
 * Translates the page's static text: elements with data-i18n (their text),
 * data-i18n-placeholder, and data-i18n-title.
 */
export function applyTranslations(root = document) {
  for (const element of root.querySelectorAll("[data-i18n]")) {
    setRichText(element, t(element.dataset.i18n));
  }
  for (const element of root.querySelectorAll("[data-i18n-placeholder]")) {
    element.placeholder = t(element.dataset.i18nPlaceholder);
  }
  for (const element of root.querySelectorAll("[data-i18n-title]")) {
    element.title = t(element.dataset.i18nTitle);
  }
}
