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

const input = document.getElementById("api-url");
const keyInput = document.getElementById("api-key");
const status = document.getElementById("status");

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

const NO_PERMISSION_NOTE = " Permission to access that host wasn't granted, so the server has to allow "
  + "extension requests itself (PhishNet 2.4.0 and newer do).";

const KEY_HINT = " Paste the API key that \"phishnet serve\" printed when it first started "
  + "(stored in ~/.phishnet/api-key on the server), or make a new one with: phishnet serve --regenerate-key";

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
    const keyNote = key ? " with the API key" : " without an API key";
    showStatus("ok", `Saved. The popup will use ${url}${keyNote}.${granted ? "" : NO_PERMISSION_NOTE}`);
  }).catch((error) => showStatus("error", `Couldn't save the settings: ${error.message}`));
});

document.getElementById("test").addEventListener("click", () => {
  const url = readInput();
  const key = url === null ? null : readKey();
  if (url === null || key === null) {
    return;
  }
  showStatus("", `Connecting to ${url}…`);
  requestHostPermission(url)
    .then(() => checkConnection(url, key))
    .then(({ keyChecked }) => showStatus("ok", keyChecked
      ? `Connected: PhishNet API is running at ${url}, and it accepts ${key ? "the API key" : "requests without a key"}.`
      : `Connected: PhishNet API is running at ${url}. It's older than 2.9.0, so it doesn't check API keys.`))
    .catch((error) => showStatus("error", error.message
      + (error instanceof ApiError && error.kind === "auth" ? KEY_HINT : "")));
});

document.getElementById("reset").addEventListener("click", async () => {
  try {
    await resetApiBaseUrl();
    input.value = DEFAULT_API_URL;
    showStatus("ok", `Reset to the default, ${DEFAULT_API_URL}.`);
  } catch (error) {
    showStatus("error", `Couldn't reset the setting: ${error.message}`);
  }
});

Promise.all([getApiBaseUrl(), getApiKey()])
  .then(([url, key]) => {
    input.value = url;
    keyInput.value = key;
  })
  .catch((error) => showStatus("error", `Couldn't load the saved settings: ${error.message}`));
