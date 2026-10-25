// Toolbar popup: scans the active tab's URL once, when the popup is opened.
// Nothing runs in the background and no page is scanned unless you click the icon.

import { ApiError, ext, getApiBaseUrl, isScannablePageUrl, scanUrl } from "./lib/api.js";

/** How many signals to list before collapsing the rest into "+N more". */
const MAX_SIGNALS = 5;

const $ = (id) => document.getElementById(id);
const STATES = ["loading", "result", "error", "unsupported"];

function show(state) {
  for (const id of STATES) {
    $(id).hidden = id !== state;
  }
}

function showUnsupported(message) {
  $("unsupported-message").textContent = message;
  show("unsupported");
}

function showError(error) {
  const isApiError = error instanceof ApiError;
  $("error-message").textContent = isApiError ? error.message : `Something went wrong: ${error?.message ?? error}`;
  const hints = {
    unreachable: "Start it with \"phishnet serve\" (or the Docker image), or set the right address in Settings. "
      + "A server on another machine needs PhishNet 2.4.0 or newer.",
    timeout: "Something is listening at that address but didn't reply. Check that it's a PhishNet API, "
      + "or try again.",
  };
  const hint = (isApiError && hints[error.kind]) || "";
  $("error-hint").textContent = hint;
  $("error-hint").hidden = !hint;
  show("error");
}

function describeDomainAge(domainAge) {
  if (!domainAge || domainAge.status === "SKIPPED") {
    return "";
  }
  if (domainAge.status === "KNOWN") {
    const age = domainAge.age ?? `${domainAge.ageDays} days`;
    return domainAge.creationDate ? `Domain age: ${age} (registered ${domainAge.creationDate})` : `Domain age: ${age}`;
  }
  return "Domain age: unknown";
}

function showResult(result) {
  const level = result.level.toLowerCase();
  $("result").className = `state level-${level}`;
  $("level").textContent = `${result.level} RISK`;
  $("score").textContent = String(result.score);
  $("meter-fill").style.width = `${Math.max(0, Math.min(100, result.score))}%`;
  $("recommendation").textContent = result.recommendation ?? "";

  const age = describeDomainAge(result.domainAge);
  $("domain-age").textContent = age;
  $("domain-age").hidden = !age;

  const list = $("signals");
  list.replaceChildren();
  for (const signal of result.signals.slice(0, MAX_SIGNALS)) {
    const item = document.createElement("li");
    item.append(signal.description ?? signal.id);
    const id = document.createElement("span");
    id.className = "signal-id";
    id.textContent = signal.evidence ? `${signal.id} · ${signal.evidence}` : signal.id;
    item.append(id);
    list.append(item);
  }
  const hasSignals = result.signals.length > 0;
  $("signals-heading").hidden = !hasSignals;
  list.hidden = !hasSignals;
  $("no-signals").hidden = hasSignals;
  const more = result.signals.length - MAX_SIGNALS;
  $("more-signals").textContent = more > 0 ? `+${more} more` : "";
  $("more-signals").hidden = more <= 0;

  show("result");
}

async function runScan(apiBaseUrl, pageUrl) {
  show("loading");
  try {
    showResult(await scanUrl(apiBaseUrl, pageUrl));
  } catch (error) {
    showError(error);
  }
}

async function main() {
  $("open-settings").addEventListener("click", (event) => {
    event.preventDefault();
    ext.runtime.openOptionsPage();
    window.close();
  });

  show("loading");
  const apiBaseUrl = await getApiBaseUrl();
  $("api-url").textContent = apiBaseUrl;

  // activeTab: clicking the toolbar icon grants access to this one tab's URL.
  const [tab] = await ext.tabs.query({ active: true, currentWindow: true });
  const pageUrl = tab?.url;
  if (!pageUrl) {
    showUnsupported("PhishNet couldn't read this tab's address. Click the toolbar icon while on the page you want to check.");
    return;
  }
  $("target").textContent = pageUrl;
  $("target").title = pageUrl;
  if (!isScannablePageUrl(pageUrl)) {
    showUnsupported("Only regular web pages (http:// and https://) can be checked.");
    return;
  }

  $("retry").addEventListener("click", () => runScan(apiBaseUrl, pageUrl));
  await runScan(apiBaseUrl, pageUrl);
}

main().catch(showError);
