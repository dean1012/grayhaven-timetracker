"use strict";

document.addEventListener("submit", (event) => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement)) {
    return;
  }
  const message = form.dataset.confirm;
  if (message && !window.confirm(message)) {
    event.preventDefault();
  }
});

async function copyText(value) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }
  const fallback = document.createElement("textarea");
  fallback.value = value;
  fallback.setAttribute("readonly", "true");
  fallback.className = "clipboard-fallback";
  document.body.append(fallback);
  fallback.select();
  const copied = document.execCommand("copy");
  fallback.remove();
  if (!copied) {
    throw new Error("Clipboard copy was rejected");
  }
}

document.addEventListener("click", async (event) => {
  if (!(event.target instanceof Element)) {
    return;
  }
  const button = event.target.closest("[data-copy-target]");
  if (!(button instanceof HTMLButtonElement)) {
    return;
  }
  const target = document.querySelector(button.dataset.copyTarget || "");
  const value = target?.dataset.copyValue || target?.textContent?.trim() || "";
  if (!value) {
    return;
  }
  try {
    await copyText(value);
    const original = button.innerHTML;
    const originalLabel = button.getAttribute("aria-label");
    const originalTitle = button.getAttribute("title");
    button.innerHTML = '<i class="fa-solid fa-check" aria-hidden="true"></i><span class="visually-hidden">Copied</span>';
    button.setAttribute("aria-label", "Copied");
    button.setAttribute("title", "Copied");
    window.setTimeout(() => {
      button.innerHTML = original;
      if (originalLabel === null) {
        button.removeAttribute("aria-label");
      } else {
        button.setAttribute("aria-label", originalLabel);
      }
      if (originalTitle === null) {
        button.removeAttribute("title");
      } else {
        button.setAttribute("title", originalTitle);
      }
    }, 1800);
  } catch {
    window.prompt("Copy this password", value);
  }
});

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

function formatDuration(totalSeconds) {
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  return `${hours}:${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
}

const runningTimers = Array.from(document.querySelectorAll("[data-timer-start]"));

function updateRunningTimers() {
  runningTimers.forEach((timer) => {
    const startedAt = Date.parse(timer.dataset.timerStart || "");
    if (Number.isNaN(startedAt)) {
      return;
    }
    const elapsed = Math.max(0, Math.floor((Date.now() - startedAt) / 1000));
    timer.textContent = formatDuration(elapsed);
  });
}

if (runningTimers.length > 0) {
  updateRunningTimers();
  window.setInterval(updateRunningTimers, 1000);
}

const moneyFormatter = new Intl.NumberFormat("en-US", {
  style: "currency",
  currency: "USD",
});
const reportReceivedAt = new WeakMap();
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
  previous.className = "button button-secondary table-button";
  previous.type = "button";
  previous.textContent = "Previous";
  previous.dataset.reportPagePrevious = "";

  const label = document.createElement("span");
  label.dataset.reportPageLabel = "";

  const next = document.createElement("button");
  next.className = "button button-secondary table-button";
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

function roundedCostCents(seconds, hourlyRateCents) {
  const numerator = BigInt(seconds) * BigInt(hourlyRateCents);
  return Number((numerator + 1800n) / 3600n);
}

function allocateReportSessionCosts(sessions, hourlyRateCents) {
  const allocations = sessions.map((session, index) => {
    const numerator = BigInt(session.seconds) * BigInt(hourlyRateCents);
    return {
      index,
      cents: Number(numerator / 3600n),
      remainder: Number(numerator % 3600n),
    };
  });
  const target = roundedCostCents(
    sessions.reduce((total, session) => total + session.seconds, 0),
    hourlyRateCents,
  );
  let remaining = target - allocations.reduce((total, item) => total + item.cents, 0);
  allocations
    .slice()
    .sort((left, right) => right.remainder - left.remainder || left.index - right.index)
    .forEach((item) => {
      if (remaining > 0) {
        allocations[item.index].cents += 1;
        remaining -= 1;
      }
    });
  return allocations.map((item) => item.cents);
}

function reportPiePath(startAngle, endAngle) {
  const center = 100;
  const radius = 86;
  const point = (angle) => [
    center + radius * Math.cos(angle),
    center + radius * Math.sin(angle),
  ];
  const [startX, startY] = point(startAngle);
  const [endX, endY] = point(endAngle);
  if (endAngle - startAngle >= 2 * Math.PI - 1e-9) {
    const [middleX, middleY] = point(startAngle + Math.PI);
    return `M ${center.toFixed(3)} ${center.toFixed(3)} L ${startX.toFixed(3)} ${startY.toFixed(3)} A ${radius.toFixed(3)} ${radius.toFixed(3)} 0 1 1 ${middleX.toFixed(3)} ${middleY.toFixed(3)} A ${radius.toFixed(3)} ${radius.toFixed(3)} 0 1 1 ${startX.toFixed(3)} ${startY.toFixed(3)} Z`;
  }
  const largeArc = endAngle - startAngle > Math.PI ? 1 : 0;
  return `M ${center.toFixed(3)} ${center.toFixed(3)} L ${startX.toFixed(3)} ${startY.toFixed(3)} A ${radius.toFixed(3)} ${radius.toFixed(3)} 0 ${largeArc} 1 ${endX.toFixed(3)} ${endY.toFixed(3)} Z`;
}

function updateReportPie(section, groups) {
  const totalSeconds = groups.reduce((total, group) => total + group.seconds, 0);
  let angle = -Math.PI / 2;
  groups.forEach((group, index) => {
    const nextAngle = index < groups.length - 1
      ? angle + 2 * Math.PI * group.seconds / Math.max(totalSeconds, 1)
      : 3 * Math.PI / 2;
    const path = Array.from(section.querySelectorAll("[data-report-pie]")).find(
      (item) => item.dataset.reportPie === group.label,
    );
    if (path) {
      path.setAttribute("d", totalSeconds > 0 ? reportPiePath(angle, nextAngle) : "");
      const title = path.querySelector("title");
      if (title) {
        title.textContent = `${group.label}: ${formatDuration(group.seconds)} (${moneyFormatter.format(group.costCents / 100)})`;
      }
    }
    const legend = Array.from(section.querySelectorAll("[data-report-legend]")).find(
      (item) => item.dataset.reportLegend === group.label,
    );
    const legendValue = legend?.querySelector("[data-report-legend-value]");
    if (legendValue) {
      legendValue.textContent = `${formatDuration(group.seconds)} · ${moneyFormatter.format(group.costCents / 100)}`;
    }
    angle = nextAngle;
  });
}

function updateLiveReportSection(section) {
  const hourlyRateCents = Number(section.dataset.hourlyRateCents);
  if (!Number.isSafeInteger(hourlyRateCents)) {
    return { seconds: 0, costCents: 0 };
  }
  const receivedAt = reportReceivedAt.get(section) || Date.now();
  reportReceivedAt.set(section, receivedAt);
  const activeDelta = Math.max(0, Math.floor((Date.now() - receivedAt) / 1000));
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
    group.seconds = group.sessions.reduce((total, session) => total + session.seconds, 0);
    group.costCents = roundedCostCents(group.seconds, hourlyRateCents);
    const allocations = allocateReportSessionCosts(group.sessions, hourlyRateCents);
    group.sessions.forEach((session, index) => {
      const cost = session.row.querySelector("[data-report-session-cost]");
      if (cost) {
        cost.textContent = moneyFormatter.format(allocations[index] / 100);
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
  updateReportPie(section, groups);
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
    if (response.redirected || [401, 403, 404].includes(response.status)) {
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

document.addEventListener("click", (event) => {
  document.querySelectorAll("details.rename-control[open]").forEach((details) => {
    if (!details.contains(event.target)) {
      details.removeAttribute("open");
    }
  });
});

document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") {
    return;
  }
  document.querySelectorAll("details.rename-control[open]").forEach((details) => {
    details.removeAttribute("open");
  });
});

document.querySelectorAll("[data-totp-bubbles]").forEach((group) => {
  const inputs = Array.from(group.querySelectorAll("input[name='totp_digit']"));

  function distributeDigits(value) {
    const digits = value.replace(/\D/g, "").slice(0, inputs.length);
    inputs.forEach((input, index) => {
      input.value = digits[index] || "";
    });
    const focusIndex = Math.min(digits.length, inputs.length - 1);
    inputs[focusIndex].focus();
    inputs[focusIndex].select();
  }

  group.addEventListener("paste", (event) => {
    const digits = event.clipboardData?.getData("text").replace(/\D/g, "") || "";
    if (digits.length === inputs.length) {
      event.preventDefault();
      distributeDigits(digits);
    }
  });

  inputs.forEach((input, index) => {
    input.addEventListener("input", () => {
      const digits = input.value.replace(/\D/g, "");
      if (digits.length > 1) {
        distributeDigits(digits);
        return;
      }
      input.value = digits;
      if (digits && index < inputs.length - 1) {
        inputs[index + 1].focus();
        inputs[index + 1].select();
      }
    });

    input.addEventListener("focus", () => input.select());
    input.addEventListener("keydown", (event) => {
      if (event.key === "Backspace" && !input.value && index > 0) {
        event.preventDefault();
        inputs[index - 1].value = "";
        inputs[index - 1].focus();
      } else if (event.key === "ArrowLeft" && index > 0) {
        event.preventDefault();
        inputs[index - 1].focus();
      } else if (event.key === "ArrowRight" && index < inputs.length - 1) {
        event.preventDefault();
        inputs[index + 1].focus();
      }
    });
  });
});
