// Lightweight translations for the dashboard's own text (no library needed).
//
// Each language is a flat JSON dictionary in this folder; a key missing from one
// falls back to English, and a key missing from English shows the key itself.
// Placeholders look like {name}. A key with ".one"/".other" variants is picked by
// the `count` parameter. Text that comes from the API (scan results, error
// messages) is shown as the server sends it - the client asks the server for the
// same language with an Accept-Language header.

import { Fragment, createElement, useSyncExternalStore } from "react";
import en from "./en.json";

/** localStorage key holding the language picked in the header, next to the API settings. */
export const LANGUAGE_STORAGE_KEY = "phishnet.language";

/** Window event fired when the language changes. */
export const LANGUAGE_CHANGED_EVENT = "phishnet:language-changed";

export const DEFAULT_LANGUAGE = "en";

const DICTIONARIES = { en };

/** Supported languages, as ISO 639 codes. */
export const LANGUAGES = Object.keys(DICTIONARIES);

/** Each language's name in that language, for the switcher. */
export const LANGUAGE_NAMES = { en: "English" };

/** The supported language for a tag such as "tr-TR", or null. */
export function supportedLanguage(tag) {
  const language = String(tag ?? "").trim().toLowerCase().split(/[-_]/)[0];
  return Object.hasOwn(DICTIONARIES, language) ? language : null;
}

function readStoredLanguage() {
  try {
    return supportedLanguage(globalThis.localStorage?.getItem(LANGUAGE_STORAGE_KEY));
  } catch {
    return null;
  }
}

/** The language picked earlier in this browser, else the browser's own preference, else English. */
export function detectLanguage() {
  const stored = readStoredLanguage();
  if (stored) {
    return stored;
  }
  const nav = globalThis.navigator;
  const preferred = nav?.languages?.length ? nav.languages : [nav?.language];
  for (const tag of preferred) {
    const language = supportedLanguage(tag);
    if (language) {
      return language;
    }
  }
  return DEFAULT_LANGUAGE;
}

let current = null;

export function getLanguage() {
  if (current === null) {
    current = detectLanguage();
  }
  return current;
}

/** Switches the dashboard's language and remembers it in this browser. */
export function setLanguage(language) {
  const next = supportedLanguage(language) ?? DEFAULT_LANGUAGE;
  current = next;
  try {
    globalThis.localStorage?.setItem(LANGUAGE_STORAGE_KEY, next);
  } catch {
    // Storage unavailable: the choice lasts until the page is reloaded.
  }
  if (globalThis.document?.documentElement) {
    globalThis.document.documentElement.lang = next;
  }
  globalThis.dispatchEvent?.(new Event(LANGUAGE_CHANGED_EVENT));
}

/** Forgets the in-memory choice so the next read detects it again (for tests). */
export function resetLanguage() {
  current = null;
}

function lookup(language, key) {
  return DICTIONARIES[language]?.[key] ?? DICTIONARIES[DEFAULT_LANGUAGE][key];
}

function template(language, key, params) {
  if (typeof params?.count === "number") {
    const category = new Intl.PluralRules(language).select(params.count);
    const plural = lookup(language, `${key}.${category}`) ?? lookup(language, `${key}.other`);
    if (plural !== undefined) {
      return plural;
    }
  }
  return lookup(language, key) ?? key;
}

/** The text for `key` in `language` (default: the current one), with {placeholders} filled in. */
export function translate(key, params, language = getLanguage()) {
  return template(language, key, params).replace(/\{(\w+)\}/g, (match, name) =>
    params && Object.hasOwn(params, name) ? String(params[name]) : match,
  );
}

/** Like translate(), but placeholders may be React elements (links, <code>); returns React children. */
export function translateRich(key, parts, language = getLanguage()) {
  return template(language, key, parts)
    .split(/\{(\w+)\}/)
    .map((piece, index) => {
      const value = index % 2 === 1 ? (parts && Object.hasOwn(parts, piece) ? parts[piece] : `{${piece}}`) : piece;
      return createElement(Fragment, { key: index }, value);
    });
}

function subscribe(onChange) {
  globalThis.addEventListener?.(LANGUAGE_CHANGED_EVENT, onChange);
  return () => globalThis.removeEventListener?.(LANGUAGE_CHANGED_EVENT, onChange);
}

/**
 * The current language and its translate functions; the component re-renders when
 * the language changes. Works without any provider component.
 */
export function useI18n() {
  const language = useSyncExternalStore(subscribe, getLanguage, () => DEFAULT_LANGUAGE);
  return {
    language,
    setLanguage,
    t: (key, params) => translate(key, params, language),
    rich: (key, parts) => translateRich(key, parts, language),
  };
}
