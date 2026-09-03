"use strict";

function decodeBase64Url(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  return Uint8Array.from(window.atob(padded), (character) =>
    character.charCodeAt(0),
  );
}

function encodeBase64Url(value) {
  if (value === null) {
    return null;
  }
  const bytes = new Uint8Array(value);
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return window
    .btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function preparePublicKeyOptions(options, flow) {
  const prepared = { ...options, challenge: decodeBase64Url(options.challenge) };
  if (flow === "registration") {
    prepared.user = { ...options.user, id: decodeBase64Url(options.user.id) };
    prepared.excludeCredentials = (options.excludeCredentials || []).map(
      (credential) => ({ ...credential, id: decodeBase64Url(credential.id) }),
    );
  } else {
    prepared.allowCredentials = (options.allowCredentials || []).map(
      (credential) => ({ ...credential, id: decodeBase64Url(credential.id) }),
    );
  }
  return prepared;
}

function serializePasskeyCredential(credential, flow) {
  const common = {
    id: credential.id,
    rawId: encodeBase64Url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults(),
  };
  if (flow === "registration") {
    return {
      ...common,
      response: {
        attestationObject: encodeBase64Url(credential.response.attestationObject),
        clientDataJSON: encodeBase64Url(credential.response.clientDataJSON),
        transports: credential.response.getTransports?.() || [],
      },
    };
  }
  return {
    ...common,
    response: {
      authenticatorData: encodeBase64Url(credential.response.authenticatorData),
      clientDataJSON: encodeBase64Url(credential.response.clientDataJSON),
      signature: encodeBase64Url(credential.response.signature),
      userHandle: encodeBase64Url(credential.response.userHandle),
    },
  };
}

async function passkeyPost(url, payload, csrfToken) {
  const response = await window.fetch(url, {
    method: "POST",
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      "X-CSRFToken": csrfToken,
    },
    body: JSON.stringify(payload),
  });
  const mediaType = (response.headers.get("Content-Type") || "")
    .split(";", 1)[0]
    .trim()
    .toLowerCase();
  const isJson = mediaType === "application/json" || mediaType.endsWith("+json");
  let body;
  if (isJson) {
    try {
      body = await response.json();
    } catch {
      body = undefined;
    }
  }
  const isObject = body !== null && typeof body === "object" && !Array.isArray(body);
  if (!response.ok) {
    const serverError =
      isObject && typeof body.error === "string" && body.error.trim()
        ? body.error
        : undefined;
    const fallback =
      response.status === 429
        ? "Too many passkey attempts. Wait a moment and try again."
        : "The passkey request was not accepted.";
    throw new Error(serverError || fallback);
  }
  if (!isObject) {
    throw new Error("The passkey response was not accepted.");
  }
  return body;
}

function requiredPasskeyResponseValue(body, field) {
  const value = body[field];
  if (typeof value !== "string" || !value) {
    throw new Error("The passkey response was not accepted.");
  }
  const validChallenge =
    field !== "challengeId" || (value.length >= 32 && value.length <= 64);
  const validRedirect =
    field !== "redirect" ||
    (value.startsWith("/") && !value.startsWith("//") && !value.includes("\\"));
  if (!validChallenge || !validRedirect) {
    throw new Error("The passkey response was not accepted.");
  }
  return value;
}

let conditionalPasskeyController = null;
let conditionalPasskeyPending = Promise.resolve();

async function settleConditionalPasskeyLogin() {
  conditionalPasskeyController?.abort();
  await conditionalPasskeyPending;
}

async function startConditionalPasskeyLogin(container) {
  const conditionalAvailable =
    typeof window.PublicKeyCredential?.isConditionalMediationAvailable ===
    "function";
  if (!conditionalAvailable || !navigator.credentials) {
    return;
  }
  const controller =
    typeof AbortController === "function" ? new AbortController() : null;
  conditionalPasskeyController = controller;
  let status;
  const pending = (async () => {
    try {
      if (!(await window.PublicKeyCredential.isConditionalMediationAvailable())) {
        return;
      }
      const optionsUrl = container.dataset.optionsUrl;
      const verifyUrl = container.dataset.verifyUrl;
      const csrfToken = container.querySelector('input[name="csrf_token"]')?.value;
      status = container.querySelector("[data-conditional-passkey-status]");
      if (!optionsUrl || !verifyUrl || !csrfToken || controller?.signal.aborted) {
        return;
      }

      let challengeId;
      let credential;
      try {
        const options = await passkeyPost(optionsUrl, {}, csrfToken);
        challengeId = requiredPasskeyResponseValue(options, "challengeId");
        delete options.challengeId;
        const request = {
          publicKey: preparePublicKeyOptions(options, "authentication"),
          mediation: "conditional",
        };
        if (controller) {
          request.signal = controller.signal;
        }
        credential = await navigator.credentials.get(request);
        if (!(credential instanceof window.PublicKeyCredential)) {
          return;
        }
      } catch {
        return;
      }
      const result = await passkeyPost(
        verifyUrl,
        {
          challengeId,
          credential: serializePasskeyCredential(credential, "authentication"),
        },
        csrfToken,
      );
      window.location.assign(requiredPasskeyResponseValue(result, "redirect"));
    } catch (error) {
      if (status) {
        status.hidden = false;
        status.textContent = error?.message || "The passkey was not accepted.";
      }
    }
  })();
  conditionalPasskeyPending = pending.finally(() => {
    if (conditionalPasskeyController === controller) {
      conditionalPasskeyController = null;
      conditionalPasskeyPending = Promise.resolve();
    }
  });
  return conditionalPasskeyPending;
}

async function startExplicitPasskey(container) {
  const button = container.querySelector("[data-passkey-start]");
  const alternative = container.querySelector("[data-passkey-alternative]");
  const status = container.querySelector("[data-passkey-status]");
  if (
    !(button instanceof HTMLButtonElement) ||
    !(status instanceof HTMLElement)
  ) {
    return;
  }
  if (!window.PublicKeyCredential || !navigator.credentials) {
    container.dataset.passkeyState = "fallback";
    if (alternative && alternative !== status) alternative.hidden = true;
    button.hidden = true;
    status.hidden = false;
    status.textContent =
      "Passkeys are unavailable in this browser. Use the password and authenticator instead.";
    return;
  }
  const optionsUrl = container.dataset.optionsUrl;
  const verifyUrl = container.dataset.verifyUrl;
  const csrfToken =
    container.querySelector('input[name="csrf_token"]')?.value ||
    document.querySelector('input[name="csrf_token"]')?.value;
  if (!optionsUrl || !verifyUrl || !csrfToken) {
    container.dataset.passkeyState = "fallback";
    if (alternative && alternative !== status) alternative.hidden = true;
    button.hidden = true;
    button.disabled = true;
    status.hidden = false;
    status.textContent = "The passkey request could not be started.";
    return;
  }
  container.dataset.passkeyState = "ready";
  if (alternative && alternative !== status) alternative.hidden = false;
  button.hidden = false;
  button.addEventListener("click", async () => {
    button.disabled = true;
    status.hidden = false;
    status.textContent = "Waiting for your passkey…";
    try {
      await settleConditionalPasskeyLogin();
      const options = await passkeyPost(optionsUrl, {}, csrfToken);
      const challengeId = requiredPasskeyResponseValue(options, "challengeId");
      delete options.challengeId;
      const credential = await navigator.credentials.get({
        publicKey: preparePublicKeyOptions(options, "authentication"),
      });
      if (!(credential instanceof window.PublicKeyCredential)) {
        throw new Error("The browser did not return a passkey response.");
      }
      const result = await passkeyPost(
        verifyUrl,
        {
          challengeId,
          credential: serializePasskeyCredential(credential, "authentication"),
        },
        csrfToken,
      );
      window.location.assign(requiredPasskeyResponseValue(result, "redirect"));
    } catch (error) {
      status.textContent =
        error?.name === "NotAllowedError" || error?.name === "AbortError"
          ? "Passkey canceled. Use the password and authenticator option whenever you prefer."
          : error?.message || "The passkey was not accepted.";
    } finally {
      button.disabled = false;
    }
  });
}

document.querySelectorAll("[data-passkey-flow]").forEach((container) => {
  const startButton = container.querySelector("[data-passkey-start]");
  const cancelButton = container.querySelector("[data-passkey-cancel]");
  const status = container.querySelector("[data-passkey-status]");
  const nameInput = container.querySelector("[data-passkey-name]");
  if (
    !(startButton instanceof HTMLButtonElement) ||
    !(cancelButton instanceof HTMLButtonElement) ||
    !(status instanceof HTMLElement) ||
    !window.PublicKeyCredential ||
    !navigator.credentials
  ) {
    if (status instanceof HTMLElement) {
      status.textContent = "Passkeys are unavailable in this browser. Use your password and authenticator instead.";
    }
    return;
  }
  startButton.hidden = false;
  let controller;
  cancelButton.addEventListener("click", () => controller?.abort());
  startButton.addEventListener("click", async () => {
    const flow = container.dataset.passkeyFlow;
    const optionsUrl = container.dataset.optionsUrl;
    const verifyUrl = container.dataset.verifyUrl;
    const csrfToken =
      container.querySelector('input[name="csrf_token"]')?.value ||
      document.querySelector('input[name="csrf_token"]')?.value;
    const name = nameInput?.value.trim();
    if (!flow || !optionsUrl || !verifyUrl || !csrfToken) {
      status.textContent = "The passkey request could not be started.";
      return;
    }
    if (flow === "registration" && !name) {
      status.textContent = "Enter a name for this passkey.";
      nameInput?.focus();
      return;
    }
    controller = new AbortController();
    startButton.disabled = true;
    cancelButton.hidden = false;
    status.textContent = "Waiting for your passkey…";
    try {
      const options = await passkeyPost(optionsUrl, {}, csrfToken);
      const challengeId = requiredPasskeyResponseValue(options, "challengeId");
      delete options.challengeId;
      const publicKey = preparePublicKeyOptions(options, flow);
      const credential =
        flow === "registration"
          ? await navigator.credentials.create({ publicKey, signal: controller.signal })
          : await navigator.credentials.get({ publicKey, signal: controller.signal });
      if (!(credential instanceof PublicKeyCredential)) {
        throw new Error("The browser did not return a passkey response.");
      }
      const result = await passkeyPost(
        verifyUrl,
        {
          challengeId,
          credential: serializePasskeyCredential(credential, flow),
          ...(flow === "registration" ? { name } : {}),
        },
        csrfToken,
      );
      window.location.assign(requiredPasskeyResponseValue(result, "redirect"));
    } catch (error) {
      status.textContent =
        error?.name === "AbortError"
          ? "Passkey canceled. Use the password and authenticator option whenever you prefer."
          : error?.message || "The passkey was not accepted.";
    } finally {
      controller = undefined;
      startButton.disabled = false;
      cancelButton.hidden = true;
    }
  });
});

document
  .querySelectorAll("[data-conditional-passkey-login]")
  .forEach((container) => void startConditionalPasskeyLogin(container));

document
  .querySelectorAll("[data-explicit-passkey-login], [data-explicit-passkey-authentication]")
  .forEach((container) => void startExplicitPasskey(container));

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

function formatDuration(totalSeconds) {
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  return `${hours}:${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
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
  });
}

updateRunningTimers();
window.setInterval(updateRunningTimers, 1000);

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
      window.location.replace(response.url);
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
  if (!page || page.querySelector("[data-one-time-confirmation], [data-totp-setup]") || livePageRequestActive) {
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

document.querySelectorAll("[data-payment-status-form]").forEach((form) => {
  const status = form.querySelector("select[name='billing_status']");
  const reasonField = form.querySelector("[data-correction-reason-field]");
  const reasonInput = reasonField?.querySelector("textarea[name='correction_reason']");
  if (
    !(status instanceof HTMLSelectElement) ||
    !(reasonField instanceof HTMLElement) ||
    !(reasonInput instanceof HTMLTextAreaElement)
  ) {
    return;
  }
  const statusOrder = ["pending_invoice", "invoiced", "client_paid", "disbursed"];
  const financialInputs = Array.from(form.querySelectorAll("[data-original-value]"));
  const updateCorrectionReason = () => {
    const movingBackward =
      statusOrder.indexOf(status.value) <
      statusOrder.indexOf(form.dataset.currentPaymentStatus || "");
    const existingDataChanged = financialInputs.some(
      (input) =>
        input.dataset.originalValue !== "" &&
        input.value !== input.dataset.originalValue,
    );
    const required = movingBackward || existingDataChanged;
    reasonField.hidden = !required;
    reasonInput.disabled = !required;
    reasonInput.required = required;
  };
  const updateFields = () => {
    form.querySelectorAll("[data-payment-statuses]").forEach((field) => {
      const visible = (field.dataset.paymentStatuses || "")
        .split(" ")
        .includes(status.value);
      field.hidden = !visible;
      field.querySelectorAll("input").forEach((input) => {
        input.disabled = !visible;
        input.required = visible && input.hasAttribute("data-payment-status-required");
      });
    });
    updateCorrectionReason();
  };
  status.addEventListener("change", updateFields);
  financialInputs.forEach((input) => {
    input.addEventListener("input", updateCorrectionReason);
  });
  updateFields();
});
