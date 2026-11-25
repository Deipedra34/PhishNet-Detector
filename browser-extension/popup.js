// Toolbar popup: scans the active tab's URL once, when the popup is opened.
// Nothing runs in the background and no page is scanned unless you click the icon.

import { ApiError, ext, getApiBaseUrl, getApiKey, isScannablePageUrl, scanUrl } from "./lib/api.js";
import { applyTranslations, initI18n, t } from "./lib/i18n.js";

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
  $("error-message").textContent = isApiError ? error.message : t("popupSomethingWrong", error?.message ?? error);
  const hints = {
    unreachable: "hintUnreachable",
    timeout: "hintTimeout",
    auth: "hintAuth",
    rate: "hintRate",
  };
  const hint = isApiError && hints[error.kind] ? t(hints[error.kind]) : "";
  $("error-hint").textContent = hint;
  $("error-hint").hidden = !hint;
  show("error");
}

function describeDomainAge(domainAge) {
  if (!domainAge || domainAge.status === "SKIPPED") {
    return "";
  }
  if (domainAge.status === "KNOWN") {
    const age = domainAge.age ?? t("popupDomainAgeDays", domainAge.ageDays);
    return domainAge.creationDate ? t("popupDomainAgeRegistered", age, domainAge.creationDate) : t("popupDomainAge", age);
  }
  return t("popupDomainAgeUnknown");
}

function showResult(result) {
  const level = result.level.toLowerCase();
  $("result").className = `state level-${level}`;
  $("level").textContent = t(`popupLevel_${result.level}`);
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
  $("more-signals").textContent = more > 0 ? t("popupMoreSignals", more) : "";
  $("more-signals").hidden = more <= 0;

  show("result");
}

async function runScan(apiBaseUrl, apiKey, pageUrl) {
  show("loading");
  try {
    showResult(await scanUrl(apiBaseUrl, pageUrl, apiKey));
  } catch (error) {
    showError(error);
  }
}

async function main() {
  await initI18n();
  applyTranslations();
  $("open-settings").addEventListener("click", (event) => {
    event.preventDefault();
    ext.runtime.openOptionsPage();
    window.close();
  });

  show("loading");
  const apiBaseUrl = await getApiBaseUrl();
  const apiKey = await getApiKey();
  $("api-url").textContent = apiBaseUrl;

  // activeTab: clicking the toolbar icon grants access to this one tab's URL.
  const [tab] = await ext.tabs.query({ active: true, currentWindow: true });
  const pageUrl = tab?.url;
  if (!pageUrl) {
    showUnsupported(t("popupNoAddress"));
    return;
  }
  $("target").textContent = pageUrl;
  $("target").title = pageUrl;
  if (!isScannablePageUrl(pageUrl)) {
    showUnsupported(t("popupUnsupportedPage"));
    return;
  }

  $("retry").addEventListener("click", () => runScan(apiBaseUrl, apiKey, pageUrl));
  await runScan(apiBaseUrl, apiKey, pageUrl);
}

main().catch(showError);
