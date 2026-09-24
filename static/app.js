"use strict";

import {
  shouldDeferLiveReplacement,
  summarizeReportSessions,
  isDirtyLiveControl,
  roundedCostCents,
} from "./report-helpers.mjs";
import { initializePasskeyFlows } from "./passkeys.mjs";


initializePasskeyFlows();

const oneTimeConfirmation = document.querySelector("[data-one-time-confirmation]");

if (oneTimeConfirmation instanceof HTMLElement) {
  const redirectAfter = Number(oneTimeConfirmation.dataset.expireAfterMs);
  const redirectTarget = oneTimeConfirmation.dataset.expireRedirect;
  if (Number.isFinite(redirectAfter) && redirectAfter > 0 && redirectTarget) {
    const redirectUrl = new URL(redirectTarget, window.location.origin);
    if (redirectUrl.origin === window.location.origin) {
      const leaveConfirmation = () => window.location.replace(redirectUrl.href);
      const countdown = oneTimeConfirmation.querySelector(
        "[data-confirmation-countdown]",
      );
      const expiresAt = Date.now() + redirectAfter;
      const updateCountdown = () => {
        const remainingSeconds = Math.max(
          0,
          Math.ceil((expiresAt - Date.now()) / 1000),
        );
        if (countdown) {
          const minutes = Math.floor(remainingSeconds / 60);
          const seconds = String(remainingSeconds % 60).padStart(2, "0");
          countdown.textContent = `${minutes}:${seconds}`;
        }
      };
      updateCountdown();
      window.setInterval(updateCountdown, 1000);
      window.setTimeout(leaveConfirmation, redirectAfter);
      window.addEventListener("pageshow", (event) => {
        if (event.persisted) {
          leaveConfirmation();
        }
      });
    }
  }
}

const totpSetup = document.querySelector("[data-totp-setup]");

if (totpSetup instanceof HTMLElement) {
  const expiresAt = Number(totpSetup.dataset.expireAtMs);
  const redirectTarget = totpSetup.dataset.expireRedirect;
  const countdown = totpSetup.querySelector("[data-totp-setup-countdown]");
  if (Number.isFinite(expiresAt) && redirectTarget && countdown) {
    const redirectUrl = new URL(redirectTarget, window.location.origin);
    if (redirectUrl.origin === window.location.origin) {
      let countdownInterval;
      const updateCountdown = () => {
        const remainingSeconds = Math.max(
          0,
          Math.ceil((expiresAt - Date.now()) / 1000),
        );
        const minutes = Math.floor(remainingSeconds / 60);
        const seconds = String(remainingSeconds % 60).padStart(2, "0");
        countdown.textContent = `${minutes}:${seconds}`;
        if (remainingSeconds === 0) {
          window.clearInterval(countdownInterval);
          window.location.replace(redirectUrl.href);
        }
      };
      updateCountdown();
      countdownInterval = window.setInterval(updateCountdown, 1000);
      window.addEventListener("pageshow", (event) => {
        if (event.persisted) {
          window.location.replace(redirectUrl.href);
        }
      });
    }
  }
}

const moneyFormatter = new Intl.NumberFormat("en-US", {
  style: "currency",
  currency: "USD",
});

function formatDuration(totalSeconds) {
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  return `${hours}:${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
}

function formatDailyDuration(totalSeconds) {
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  return `${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
}

function roundedSessionCostCents(seconds, hourlyRateCents) {
  const numerator = seconds * hourlyRateCents;
  if (!Number.isSafeInteger(numerator)) {
    return null;
  }
  return roundedCostCents(seconds, hourlyRateCents);
}

function localDateKey(timeZone) {
  try {
    const values = new Intl.DateTimeFormat("en-US", {
      timeZone,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
    }).formatToParts(new Date()).reduce((result, part) => {
      result[part.type] = part.value;
      return result;
    }, {});
    return `${values.year}-${values.month}-${values.day}`;
  } catch {
    return "";
  }
}

function updatePendingSessionSummary() {
  const summary = document.querySelector("[data-pending-live-summary]");
  if (!(summary instanceof HTMLElement) || summary.dataset.runningBaseSeconds === undefined) {
    return;
  }
  const snapshotAt = Date.parse(summary.dataset.snapshotAt || "");
  const baseTotalSeconds = Number(summary.dataset.baseTotalSeconds);
  const baseTotalCostCents = Number(summary.dataset.baseTotalCostCents);
  const runningBaseSeconds = Number(summary.dataset.runningBaseSeconds);
  const runningRateCents = Number(summary.dataset.runningRateCents);
  if (!Number.isFinite(snapshotAt) || ![baseTotalSeconds, baseTotalCostCents, runningBaseSeconds, runningRateCents].every(Number.isSafeInteger)) {
    return;
  }
  const delta = Math.max(0, Math.floor((Date.now() - snapshotAt) / 1000));
  const runningCost = roundedSessionCostCents(runningBaseSeconds + delta, runningRateCents);
  const baseRunningCost = roundedSessionCostCents(runningBaseSeconds, runningRateCents);
  const duration = summary.querySelector("[data-pending-total-duration]");
  const cost = summary.querySelector("[data-pending-total-cost]");
  if (duration) {
    duration.textContent = formatDuration(baseTotalSeconds + delta);
  }
  if (cost && runningCost !== null && baseRunningCost !== null) {
    cost.textContent = moneyFormatter.format(
      (baseTotalCostCents + runningCost - baseRunningCost) / 100,
    );
  }

  const daily = document.querySelector("[data-pending-live-daily]");
  if (!(daily instanceof HTMLElement)) {
    return;
  }
  const today = localDateKey(daily.dataset.pendingTimezone || "");
  if (today && daily.dataset.snapshotDay && today !== daily.dataset.snapshotDay) {
    const rollover = `${daily.dataset.snapshotDay}->${today}`;
    try {
      const key = "pending-daily-rollover";
      if (window.sessionStorage.getItem(key) !== rollover) {
        window.sessionStorage.setItem(key, rollover);
        window.location.reload();
        return;
      }
    } catch {
      // Keep the page usable if browser storage is unavailable.
    }
  }
  const row = Array.from(daily.querySelectorAll("[data-pending-day]"))
    .find((candidate) => candidate.dataset.pendingDay === today);
  const dayDuration = row?.querySelector("[data-pending-day-duration]");
  const baseDaySeconds = Number(dayDuration?.dataset.baseSeconds);
  if (dayDuration && Number.isSafeInteger(baseDaySeconds)) {
    dayDuration.textContent = formatDailyDuration(baseDaySeconds + delta);
  }
  const dayCost = row?.querySelector("[data-pending-day-cost]");
  const baseDayCostCents = Number(dayCost?.dataset.baseCostCents);
  if (dayCost && Number.isSafeInteger(baseDayCostCents) && runningCost !== null && baseRunningCost !== null) {
    dayCost.textContent = moneyFormatter.format(
      (baseDayCostCents + runningCost - baseRunningCost) / 100,
    );
  }
}

function updateRunningTimers() {
  document.querySelectorAll("[data-timer-start]").forEach((timer) => {
    const startedAt = Date.parse(timer.dataset.timerStart || "");
    if (Number.isNaN(startedAt)) {
      return;
    }
    const elapsed = Math.max(0, Math.floor((Date.now() - startedAt) / 1000));
    timer.textContent = formatDuration(elapsed);
  });
  document.querySelectorAll("[data-session-start]").forEach((duration) => {
    const startedAt = Date.parse(duration.dataset.sessionStart || "");
    if (Number.isNaN(startedAt)) {
      return;
    }
    const elapsed = Math.max(0, Math.floor((Date.now() - startedAt) / 1000));
    duration.textContent = formatDuration(elapsed);
    const cost = duration.closest("tr")?.querySelector("[data-session-cost-rate-cents]");
    if (cost instanceof HTMLElement) {
      const rateCents = Number(cost.dataset.sessionCostRateCents);
      const cents = Number.isSafeInteger(rateCents)
        ? roundedSessionCostCents(elapsed, rateCents)
        : null;
      if (cents !== null) {
        cost.textContent = moneyFormatter.format(cents / 100);
      }
    }
  });
  updatePendingSessionSummary();
}

updateRunningTimers();
window.setInterval(updateRunningTimers, 1000);

const reportPageSizes = Object.freeze({ summary: 10, sessions: 25 });

function reportPaginationKey(container) {
  const section = container.closest("[data-report-contract-section]");
  return `${section?.dataset.contractId || "client"}:${container.dataset.reportPagination || "table"}`;
}

function createReportPaginationControls(container) {
  const controls = document.createElement("nav");
  controls.className = "report-pagination";
  controls.setAttribute("aria-label", `${container.dataset.reportPagination} table pages`);

  const previous = document.createElement("button");
  previous.className = "button button-secondary button-compact";
  previous.type = "button";
  previous.textContent = "Previous";
  previous.dataset.reportPagePrevious = "";

  const label = document.createElement("span");
  label.dataset.reportPageLabel = "";

  const next = document.createElement("button");
  next.className = "button button-secondary button-compact";
  next.type = "button";
  next.textContent = "Next";
  next.dataset.reportPageNext = "";

  previous.addEventListener("click", () => {
    updateReportPagination(container, Number(container.dataset.reportPage) - 1);
  });
  next.addEventListener("click", () => {
    updateReportPagination(container, Number(container.dataset.reportPage) + 1);
  });
  controls.append(previous, label, next);
  container.append(controls);
  return controls;
}

function updateReportPagination(container, requestedPage = 1) {
  const rows = Array.from(container.querySelectorAll("tbody > tr"));
  const pageSize = reportPageSizes[container.dataset.reportPagination];
  if (!pageSize) {
    return;
  }
  const pageCount = Math.max(1, Math.ceil(rows.length / pageSize));
  const currentPage = Math.min(pageCount, Math.max(1, requestedPage || 1));
  container.dataset.reportPage = String(currentPage);
  rows.forEach((row, index) => {
    row.hidden = index < (currentPage - 1) * pageSize || index >= currentPage * pageSize;
  });

  let controls = container.querySelector(":scope > .report-pagination");
  if (pageCount === 1) {
    controls?.remove();
    return;
  }
  controls ||= createReportPaginationControls(container);
  const previous = controls.querySelector("[data-report-page-previous]");
  const next = controls.querySelector("[data-report-page-next]");
  const label = controls.querySelector("[data-report-page-label]");
  previous.disabled = currentPage === 1;
  next.disabled = currentPage === pageCount;
  label.textContent = `Page ${currentPage} of ${pageCount}`;
}

function reportPaginationState(root) {
  return new Map(
    Array.from(root.querySelectorAll("[data-report-pagination]")).map((container) => [
      reportPaginationKey(container),
      Number(container.dataset.reportPage) || 1,
    ]),
  );
}

function initializeReportPagination(root, pages = new Map()) {
  root.querySelectorAll("[data-report-pagination]").forEach((container) => {
    updateReportPagination(container, pages.get(reportPaginationKey(container)) || 1);
  });
}

function updateLiveReportSection(section) {
  const hourlyRateCents = Number(section.dataset.hourlyRateCents);
  if (!Number.isSafeInteger(hourlyRateCents)) {
    return { seconds: 0, costCents: 0 };
  }
  const snapshotAt = Date.parse(
    section.closest("[data-live-report]")?.dataset.reportSnapshotAt || "",
  );
  const activeDelta = Number.isFinite(snapshotAt)
    ? Math.max(0, Math.floor((Date.now() - snapshotAt) / 1000))
    : 0;
  const groups = Array.from(section.querySelectorAll("tr[data-report-group]:not([data-report-session])")).map((row) => ({
    label: row.dataset.reportGroup || "",
    row,
    sessions: [],
    seconds: 0,
    costCents: 0,
  }));
  const groupsByLabel = new Map(groups.map((group) => [group.label, group]));
  section.querySelectorAll("tr[data-report-session]").forEach((row) => {
    const baseSeconds = Number(row.dataset.baseSeconds);
    const seconds = Math.max(0, baseSeconds + (row.dataset.active === "true" ? activeDelta : 0));
    const session = { row, seconds };
    groupsByLabel.get(row.dataset.reportGroup || "")?.sessions.push(session);
    const duration = row.querySelector("[data-report-session-duration]");
    if (duration) {
      duration.textContent = formatDuration(seconds);
    }
  });
  groups.forEach((group) => {
    const summary = summarizeReportSessions(group.sessions, hourlyRateCents);
    group.seconds = summary.seconds;
    group.costCents = summary.costCents;
    summary.rows.forEach((session) => {
      const cost = session.row.querySelector("[data-report-session-cost]");
      if (cost) {
        cost.textContent = moneyFormatter.format(
          session.costCents / 100,
        );
      }
    });
    const duration = group.row.querySelector("[data-report-group-duration]");
    const cost = group.row.querySelector("[data-report-group-cost]");
    if (duration) {
      duration.textContent = formatDuration(group.seconds);
    }
    if (cost) {
      cost.textContent = moneyFormatter.format(group.costCents / 100);
    }
  });
  const totalSeconds = groups.reduce((total, group) => total + group.seconds, 0);
  const totalCostCents = groups.reduce((total, group) => total + group.costCents, 0);
  const sectionDuration = section.querySelector("[data-report-contract-total-duration]");
  const sectionCost = section.querySelector("[data-report-contract-total-cost]");
  if (sectionDuration) {
    sectionDuration.textContent = formatDuration(totalSeconds);
  }
  if (sectionCost) {
    sectionCost.textContent = moneyFormatter.format(totalCostCents / 100);
  }
  return { seconds: totalSeconds, costCents: totalCostCents };
}

function updateLiveReportCounters() {
  const article = document.querySelector("[data-live-report]");
  if (!article || reportReconciliationStopped) {
    return;
  }
  const totals = Array.from(article.querySelectorAll("[data-report-contract-section]"))
    .map(updateLiveReportSection)
    .reduce(
      (total, section) => ({
        seconds: total.seconds + section.seconds,
        costCents: total.costCents + section.costCents,
      }),
      { seconds: 0, costCents: 0 },
    );
  const totalDuration = article.querySelector("[data-report-total-duration]");
  const totalCost = article.querySelector("[data-report-total-cost]");
  if (totalDuration) {
    totalDuration.textContent = formatDuration(totals.seconds);
  }
  if (totalCost) {
    totalCost.textContent = moneyFormatter.format(totals.costCents / 100);
  }
}

function setLiveReportStatus(label, state) {
  const status = document.querySelector("[data-live-status]");
  if (status) {
    status.dataset.state = state;
    const statusLabel = status.querySelector("[data-live-status-label]");
    if (statusLabel) {
      statusLabel.textContent = label;
    }
  }
}

let reportRequestActive = false;
let reportReconciliationStopped = false;

async function reconcileLiveReport() {
  const article = document.querySelector("[data-live-report]");
  if (!article || reportRequestActive || reportReconciliationStopped || document.hidden) {
    return;
  }
  reportRequestActive = true;
  try {
    const response = await window.fetch(article.dataset.liveUrl || "", {
      credentials: "same-origin",
      headers: { "If-None-Match": `"${article.dataset.liveEtag || ""}"` },
    });
    if (response.status === 304) {
      setLiveReportStatus("Live", "live");
      return;
    }
    if (response.redirected) {
      reportReconciliationStopped = true;
      const redirectUrl = new URL(response.url, window.location.origin);
      if (redirectUrl.origin === window.location.origin && redirectUrl.pathname === "/login") {
        redirectUrl.searchParams.set("next", window.location.pathname + window.location.search);
      }
      window.location.replace(redirectUrl.href);
      return;
    }
    if (response.status === 404) {
      reportReconciliationStopped = true;
      const reportUrl = new URL(article.dataset.liveUrl || "", window.location.origin);
      reportUrl.pathname = reportUrl.pathname.replace(/\/live$/, "");
      window.location.replace(reportUrl.href);
      return;
    }
    if ([401, 403].includes(response.status)) {
      reportReconciliationStopped = true;
      setLiveReportStatus("Access ended", "ended");
      return;
    }
    if (!response.ok) {
      setLiveReportStatus("Reconnecting", "reconnecting");
      return;
    }
    const documentFragment = new DOMParser().parseFromString(await response.text(), "text/html");
    const replacement = documentFragment.querySelector("[data-live-report]");
    if (!replacement) {
      setLiveReportStatus("Reconnecting", "reconnecting");
      return;
    }
    const currentViewport = article.querySelector(".report-viewport");
    const scrollTop = currentViewport instanceof HTMLElement ? currentViewport.scrollTop : 0;
    const paginationState = reportPaginationState(article);
    article.replaceWith(replacement);
    const replacementViewport = replacement.querySelector(".report-viewport");
    if (replacementViewport instanceof HTMLElement) {
      replacementViewport.scrollTop = scrollTop;
    }
    initializeReportPagination(replacement, paginationState);
    updateLiveReportCounters();
    setLiveReportStatus("Live", "live");
  } catch {
    setLiveReportStatus("Reconnecting", "reconnecting");
  } finally {
    reportRequestActive = false;
  }
}

const liveReport = document.querySelector("[data-live-report]");
if (liveReport) {
  initializeReportPagination(liveReport);
  updateLiveReportCounters();
  window.setInterval(updateLiveReportCounters, 1000);
  window.setInterval(
    reconcileLiveReport,
    Number(liveReport.dataset.liveIntervalMs) || 3000,
  );
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) {
      updateLiveReportCounters();
      reconcileLiveReport();
    }
  });
}

function replaceLiveRegions(page, replacement) {
  const currentRegions = Array.from(page.querySelectorAll("[data-live-region]"));
  const replacementRegions = Array.from(replacement.querySelectorAll("[data-live-region]"));
  const deferred = currentRegions.some((region) => {
    const active = region.contains(document.activeElement);
    const dirty = Array.from(region.querySelectorAll("input, textarea, select"))
      .some(isDirtyLiveControl);
    const openDisclosure = region.querySelector("details[open]") !== null;
    return shouldDeferLiveReplacement({ dirty, focused: active, openDisclosure });
  });
  if (deferred) {
    return false;
  }
  let replaced = false;

  currentRegions.forEach((region) => {
    const name = region.dataset.liveRegion;
    const replacementRegion = replacementRegions.find((candidate) => candidate.dataset.liveRegion === name);
    if (replacementRegion) {
      region.replaceWith(replacementRegion);
      replaced = true;
    }
  });

  return replaced;
}

let livePageRequestActive = false;
let livePageEtag = "";

async function reconcileLivePage() {
  const page = document.querySelector("[data-live-page]");
  if (document.hidden || !page || page.querySelector("[data-one-time-confirmation], [data-totp-setup]") || livePageRequestActive) {
    return;
  }
  livePageRequestActive = true;
  try {
    const response = await window.fetch(window.location.href, {
      credentials: "same-origin",
      headers: {
        "If-None-Match": livePageEtag,
        "X-Grayhaven-Live-Refresh": "1",
      },
    });
    if (response.status === 304) {
      return;
    }
    if (response.redirected) {
      window.location.replace(response.url);
      return;
    }
    if (!response.ok) {
      return;
    }
    const documentFragment = new DOMParser().parseFromString(await response.text(), "text/html");
    const replacement = documentFragment.querySelector("[data-live-page]");
    if (!replacement) {
      return;
    }
    if (!replaceLiveRegions(page, replacement)) {
      return;
    }
    livePageEtag = response.headers.get("ETag") || "";
    updateRunningTimers();
  } catch {
    // The next scheduled conditional refresh will retry without disrupting work.
  } finally {
    livePageRequestActive = false;
  }
}

const livePage = document.querySelector("[data-live-page]");
if (livePage) {
  livePageEtag = livePage.dataset.liveEtag || "";
  window.setInterval(
    reconcileLivePage,
    Number(livePage.dataset.liveIntervalMs) || 3000,
  );
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) {
      reconcileLivePage();
    }
  });
}

document.addEventListener("click", (event) => {
  document.querySelectorAll("details.rename-control[open]").forEach((details) => {
    if (!details.contains(event.target)) {
      details.removeAttribute("open");
    }
  });
});

document.querySelectorAll("[data-role-create-form]").forEach((form) => {
  const role = form.querySelector("[name=role]");
  const submit = form.querySelector("[data-role-create-submit]");
  const icon = form.querySelector("[data-role-create-icon]");
  const label = form.querySelector("[data-role-create-label]");
  if (!(role instanceof HTMLSelectElement) || !(submit instanceof HTMLButtonElement)
    || !(icon instanceof HTMLElement) || !(label instanceof HTMLElement)) {
    return;
  }
  const update = () => {
    const administrator = role.value === "admin";
    submit.classList.toggle("button-primary", !administrator);
    submit.classList.toggle("button-stop", administrator);
    icon.className = `fa-solid ${administrator ? "fa-user-gear" : "fa-user-plus"}`;
    label.textContent = administrator ? "Create Administrator" : "Create User";
  };
  role.addEventListener("change", update);
  update();
});

const staleNoticeUrl = new URL(window.location.href);
if (staleNoticeUrl.searchParams.has("stale")) {
  staleNoticeUrl.searchParams.delete("stale");
  window.history.replaceState({}, "", staleNoticeUrl.href);
}

function datetimeLocalNow(timeZone) {
  const values = new Intl.DateTimeFormat("en-CA", {
    timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  }).formatToParts(new Date()).reduce((result, part) => {
    result[part.type] = part.value;
    return result;
  }, {});
  return `${values.year}-${values.month}-${values.day}T${values.hour}:${values.minute}:${values.second}`;
}

document.querySelectorAll("[data-set-now-for]").forEach((button) => {
  button.addEventListener("click", () => {
    const input = document.querySelector(button.dataset.setNowFor || "");
    if (input instanceof HTMLInputElement) {
      input.value = datetimeLocalNow(input.dataset.timezone || Intl.DateTimeFormat().resolvedOptions().timeZone);
      input.dispatchEvent(new Event("change", { bubbles: true }));
    }
  });
});

document.querySelectorAll("[data-session-editor]").forEach((form) => {
  const clientSelect = form.querySelector("select[name=client_id]");
  const contractSelect = form.querySelector("select[name=contract_id]");
  const assignmentSelect = form.querySelector("select[name=assignment]");
  if (!(clientSelect instanceof HTMLSelectElement) || !(contractSelect instanceof HTMLSelectElement) || !(assignmentSelect instanceof HTMLSelectElement)) {
    return;
  }
  const endpoint = (template, identifier) => (template || "").replace("/0/", `/${identifier}/`);
  const setOptions = (select, options, selected) => {
    select.replaceChildren(...options.map(({ value, label }) => {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = label;
      option.selected = String(value) === String(selected);
      return option;
    }));
  };
  const loadAssignments = async (contractId, selected = "") => {
    if (!contractId) {
      setOptions(assignmentSelect, [], "");
      return;
    }
    const response = await window.fetch(endpoint(form.dataset.assignmentsUrlTemplate, contractId), { credentials: "same-origin" });
    if (!response.ok) throw new Error("Unable to load assignments");
    const tasks = await response.json();
    const options = tasks.flatMap((task) => [
      { value: String(task.id), label: task.name },
      ...task.subtasks.map((subtask) => ({ value: `${task.id}:${subtask.id}`, label: `${task.name} → ${subtask.name}` })),
    ]);
    setOptions(assignmentSelect, options, selected || options[0]?.value);
  };
  const loadContracts = async (clientId, selected = "", assignment = "") => {
    const response = await window.fetch(endpoint(form.dataset.contractsUrlTemplate, clientId), { credentials: "same-origin" });
    if (!response.ok) throw new Error("Unable to load contracts");
    const contracts = await response.json();
    const options = contracts.map((contract) => ({ value: String(contract.id), label: contract.name }));
    setOptions(contractSelect, options, selected || options[0]?.value);
    await loadAssignments(contractSelect.value, assignment);
  };
  clientSelect.addEventListener("change", () => {
    loadContracts(clientSelect.value, "", "").catch(() => {});
  });
  contractSelect.addEventListener("change", () => {
    loadAssignments(contractSelect.value).catch(() => {});
  });
  loadContracts(clientSelect.value, contractSelect.value, assignmentSelect.value).catch(() => {});
});

document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") {
    return;
  }
  document.querySelectorAll("details.rename-control[open]").forEach((details) => {
    details.removeAttribute("open");
  });
});

document.querySelectorAll("[data-invoice-range-form]").forEach((form) => {
  const client = form.querySelector("[data-invoice-client]");
  const project = form.querySelector("[data-invoice-project]");
  const mode = form.querySelector("[data-invoice-mode]");
  const customRange = form.querySelector("[data-invoice-custom-range]");
  if (!(client instanceof HTMLSelectElement) || !(project instanceof HTMLSelectElement)
    || !(mode instanceof HTMLSelectElement) || !(customRange instanceof HTMLElement)) {
    return;
  }
  const rangeInputs = Array.from(customRange.querySelectorAll("input"));
  const updateProjects = () => {
    const clientId = client.value;
    let selectedIsVisible = false;
    project.querySelectorAll("option[data-client-id]").forEach((option) => {
      const visible = !clientId || option.dataset.clientId === clientId;
      option.hidden = !visible;
      option.disabled = !visible;
      if (visible && option.selected) {
        selectedIsVisible = true;
      }
    });
    if (!selectedIsVisible && project.value) {
      project.value = "";
    }
  };
  const updateRange = () => {
    const custom = mode.value === "custom";
    customRange.hidden = !custom;
    rangeInputs.forEach((input) => {
      input.disabled = !custom;
      input.required = custom;
    });
  };
  client.addEventListener("change", updateProjects);
  mode.addEventListener("change", updateRange);
  updateProjects();
  updateRange();
});
