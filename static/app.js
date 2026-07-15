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

function updateReportPie(article, groups) {
  const totalSeconds = groups.reduce((total, group) => total + group.seconds, 0);
  let angle = -Math.PI / 2;
  groups.forEach((group, index) => {
    const nextAngle = index < groups.length - 1
      ? angle + 2 * Math.PI * group.seconds / Math.max(totalSeconds, 1)
      : 3 * Math.PI / 2;
    const path = Array.from(article.querySelectorAll("[data-report-pie]")).find(
      (item) => item.dataset.reportPie === group.label,
    );
    if (path) {
      path.setAttribute("d", totalSeconds > 0 ? reportPiePath(angle, nextAngle) : "");
      const title = path.querySelector("title");
      if (title) {
        title.textContent = `${group.label}: ${formatDuration(group.seconds)} (${moneyFormatter.format(group.costCents / 100)})`;
      }
    }
    const legend = Array.from(article.querySelectorAll("[data-report-legend]")).find(
      (item) => item.dataset.reportLegend === group.label,
    );
    const legendValue = legend?.querySelector("[data-report-legend-value]");
    if (legendValue) {
      legendValue.textContent = `${formatDuration(group.seconds)} · ${moneyFormatter.format(group.costCents / 100)}`;
    }
    angle = nextAngle;
  });
}

function updateLiveReportCounters() {
  const article = document.querySelector("[data-live-report]");
  if (!article || reportReconciliationStopped) {
    return;
  }
  const hourlyRateCents = Number(article.dataset.hourlyRateCents);
  if (!Number.isSafeInteger(hourlyRateCents)) {
    return;
  }
  if (!reportReceivedAt.has(article)) {
    reportReceivedAt.set(article, Date.now());
  }
  const activeDelta = Math.max(
    0,
    Math.floor((Date.now() - (reportReceivedAt.get(article) || Date.now())) / 1000),
  );
  const groups = Array.from(article.querySelectorAll("tr[data-report-group]:not([data-report-session])")).map((row) => ({
    label: row.dataset.reportGroup || "",
    row,
    sessions: [],
    seconds: 0,
    costCents: 0,
  }));
  const groupsByLabel = new Map(groups.map((group) => [group.label, group]));

  article.querySelectorAll("tr[data-report-session]").forEach((row) => {
    const baseSeconds = Number(row.dataset.baseSeconds);
    const seconds = Math.max(
      0,
      baseSeconds + (row.dataset.active === "true" ? activeDelta : 0),
    );
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
  const totalDuration = article.querySelector("[data-report-total-duration]");
  const totalCost = article.querySelector("[data-report-total-cost]");
  if (totalDuration) {
    totalDuration.textContent = formatDuration(totalSeconds);
  }
  if (totalCost) {
    totalCost.textContent = moneyFormatter.format(totalCostCents / 100);
  }
  updateReportPie(article, groups);
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
    article.replaceWith(replacement);
    const replacementViewport = replacement.querySelector(".report-viewport");
    if (replacementViewport instanceof HTMLElement) {
      replacementViewport.scrollTop = scrollTop;
    }
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
