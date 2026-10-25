// Settings page: the address of the PhishNet API the popup calls.

import {
  DEFAULT_API_URL,
  checkHealth,
  getApiBaseUrl,
  normalizeApiBaseUrl,
  requestHostPermission,
  resetApiBaseUrl,
  setApiBaseUrl,
} from "./lib/api.js";

const input = document.getElementById("api-url");
const status = document.getElementById("status");

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

document.getElementById("settings-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const url = readInput();
  if (!url) {
    return;
  }
  // Started before any await: the permission prompt has to come from the click itself.
  requestHostPermission(url).then(async (granted) => {
    await setApiBaseUrl(url);
    input.value = url;
    showStatus("ok", `Saved. The popup will use ${url}.${granted ? "" : NO_PERMISSION_NOTE}`);
  }).catch((error) => showStatus("error", `Couldn't save the setting: ${error.message}`));
});

document.getElementById("test").addEventListener("click", () => {
  const url = readInput();
  if (!url) {
    return;
  }
  showStatus("", `Connecting to ${url}…`);
  requestHostPermission(url)
    .then(() => checkHealth(url))
    .then(() => showStatus("ok", `Connected: PhishNet API is running at ${url}.`))
    .catch((error) => showStatus("error", error.message));
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

getApiBaseUrl()
  .then((url) => {
    input.value = url;
  })
  .catch((error) => showStatus("error", `Couldn't load the saved setting: ${error.message}`));
