// Settings page: the address of the PhishNet API the popup calls, and its API key.

import {
  ApiError,
  DEFAULT_API_URL,
  checkConnection,
  getApiBaseUrl,
  getApiKey,
  normalizeApiBaseUrl,
  normalizeApiKey,
  requestHostPermission,
  resetApiBaseUrl,
  setApiBaseUrl,
  setApiKey,
} from "./lib/api.js";
import {
  AUTO_LANGUAGE,
  applyTranslations,
  getLanguageSetting,
  initI18n,
  setLanguageSetting,
  t,
} from "./lib/i18n.js";

const input = document.getElementById("api-url");
const keyInput = document.getElementById("api-key");
const status = document.getElementById("status");
const languageSelect = document.getElementById("language");

document.getElementById("show-key").addEventListener("change", (event) => {
  keyInput.type = event.target.checked ? "text" : "password";
});

/** The normalized API key, or null after showing why it's invalid. */
function readKey() {
  try {
    return normalizeApiKey(keyInput.value);
  } catch (error) {
    showStatus("error", error.message);
    keyInput.focus();
    return null;
  }
}

function showStatus(kind, message) {
  status.className = `notice ${kind}`;
  status.textContent = message;
  status.hidden = false;
}

/** The normalized input, or null after showing why it's invalid. */
function readInput() {
  try {
    return normalizeApiBaseUrl(input.value);
  } catch (error) {
    showStatus("error", error.message);
    input.focus();
    return null;
  }
}

document.getElementById("settings-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const url = readInput();
  const key = url === null ? null : readKey();
  if (url === null || key === null) {
    return;
  }
  // Started before any await: the permission prompt has to come from the click itself.
  requestHostPermission(url).then(async (granted) => {
    await setApiBaseUrl(url);
    await setApiKey(key);
    input.value = url;
    keyInput.value = key;
    const saved = t(key ? "optionsSavedWithKey" : "optionsSavedWithoutKey", url);
    showStatus("ok", granted ? saved : `${saved} ${t("optionsNoPermission")}`);
  }).catch((error) => showStatus("error", t("optionsSaveFailed", error.message)));
});

document.getElementById("test").addEventListener("click", () => {
  const url = readInput();
  const key = url === null ? null : readKey();
  if (url === null || key === null) {
    return;
  }
  showStatus("", t("optionsConnecting", url));
  requestHostPermission(url)
    .then(() => checkConnection(url, key))
    .then(({ keyChecked }) => showStatus("ok", keyChecked
      ? t(key ? "optionsConnectedWithKey" : "optionsConnectedWithoutKey", url)
      : t("optionsConnectedOldServer", url)))
    .catch((error) => showStatus("error", error instanceof ApiError && error.kind === "auth"
      ? `${error.message} ${t("optionsKeyHint")}`
      : error.message));
});

document.getElementById("reset").addEventListener("click", async () => {
  try {
    await resetApiBaseUrl();
    input.value = DEFAULT_API_URL;
    showStatus("ok", t("optionsResetDone", DEFAULT_API_URL));
  } catch (error) {
    showStatus("error", t("optionsResetFailed", error.message));
  }
});

// Applied as soon as it's picked; the popup reads it each time it opens.
languageSelect.addEventListener("change", async () => {
  try {
    await setLanguageSetting(languageSelect.value);
    await initI18n();
    applyTranslations();
    showStatus("ok", t("optionsLanguageSaved"));
  } catch (error) {
    showStatus("error", t("optionsSaveFailed", error.message));
  }
});

initI18n()
  .then(() => {
    applyTranslations();
    return Promise.all([getApiBaseUrl(), getApiKey(), getLanguageSetting().catch(() => AUTO_LANGUAGE)]);
  })
  .then(([url, key, language]) => {
    input.value = url;
    keyInput.value = key;
    languageSelect.value = language;
  })
  .catch((error) => showStatus("error", t("optionsLoadFailed", error.message)));
