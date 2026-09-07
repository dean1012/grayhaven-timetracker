export function requiredPasskeyResponseValue(body, field) {
  const value = body[field];
  if (
    typeof value !== "string" ||
    !value ||
    (field === "challengeId" && (value.length < 32 || value.length > 64)) ||
    (field === "redirect" &&
      (!value.startsWith("/") ||
        value.startsWith("//") ||
        value.includes("\\")))
  ) {
    throw new Error("The passkey response was not accepted.");
  }
  return value;
}

export function decodeBase64Url(value, atob = globalThis.atob) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(
    atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=")),
    (character) => character.charCodeAt(0),
  );
}

export function encodeBase64Url(value, btoa = globalThis.btoa) {
  if (value === null) return null;
  let binary = "";
  new Uint8Array(value).forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

export function preparePublicKeyOptions(options, flow, atob = globalThis.atob) {
  const prepared = {
    ...options,
    challenge: decodeBase64Url(options.challenge, atob),
  };
  const key =
    flow === "registration" ? "excludeCredentials" : "allowCredentials";
  if (flow === "registration")
    prepared.user = {
      ...options.user,
      id: decodeBase64Url(options.user.id, atob),
    };
  prepared[key] = (options[key] || []).map((credential) => ({
    ...credential,
    id: decodeBase64Url(credential.id, atob),
  }));
  return prepared;
}

export function serializePasskeyCredential(
  credential,
  flow,
  btoa = globalThis.btoa,
) {
  const common = {
    id: credential.id,
    rawId: encodeBase64Url(credential.rawId, btoa),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults(),
  };
  const response =
    flow === "registration"
      ? {
          attestationObject: encodeBase64Url(
            credential.response.attestationObject,
            btoa,
          ),
          clientDataJSON: encodeBase64Url(
            credential.response.clientDataJSON,
            btoa,
          ),
          transports: credential.response.getTransports?.() || [],
        }
      : {
          authenticatorData: encodeBase64Url(
            credential.response.authenticatorData,
            btoa,
          ),
          clientDataJSON: encodeBase64Url(
            credential.response.clientDataJSON,
            btoa,
          ),
          signature: encodeBase64Url(credential.response.signature, btoa),
          userHandle: encodeBase64Url(credential.response.userHandle, btoa),
        };
  return { ...common, response };
}

export function createPasskeyFlows(environment = globalThis) {
  const browserWindow = () => environment.window || globalThis.window;
  const browserDocument = () => environment.document || globalThis.document;
  const browserNavigator = () => environment.navigator || globalThis.navigator;
  const BrowserAbortController = () =>
    environment.AbortController || globalThis.AbortController;
  const HTMLElement = () => environment.HTMLElement || globalThis.HTMLElement;
  const HTMLButtonElement = () =>
    environment.HTMLButtonElement || globalThis.HTMLButtonElement;
  let conditionalController = null;
  let conditionalPending = Promise.resolve();

  async function passkeyPost(url, payload, csrfToken) {
    const response = await browserWindow().fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
      body: JSON.stringify(payload),
    });
    const mediaType = (response.headers.get("Content-Type") || "")
      .split(";", 1)[0]
      .trim()
      .toLowerCase();
    let body;
    if (mediaType === "application/json" || mediaType.endsWith("+json")) {
      try {
        body = await response.json();
      } catch {
        body = undefined;
      }
    }
    const isObject =
      body !== null && typeof body === "object" && !Array.isArray(body);
    if (!response.ok)
      throw new Error(
        isObject && typeof body.error === "string" && body.error.trim()
          ? body.error
          : response.status === 429
            ? "Too many passkey attempts. Wait a moment and try again."
            : "The passkey request was not accepted.",
      );
    if (!isObject) throw new Error("The passkey response was not accepted.");
    return body;
  }
  async function settleConditionalPasskeyLogin() {
    conditionalController?.abort();
    await conditionalPending;
  }
  async function startConditionalPasskeyLogin(container) {
    const win = browserWindow();
    const nav = browserNavigator();
    const Credential = win.PublicKeyCredential;
    if (
      typeof Credential?.isConditionalMediationAvailable !== "function" ||
      !nav.credentials
    )
      return;
    const AbortController = BrowserAbortController();
    const controller =
      typeof AbortController === "function" ? new AbortController() : null;
    conditionalController = controller;
    let status;
    const pending = (async () => {
      try {
        if (!(await Credential.isConditionalMediationAvailable())) return;
        const optionsUrl = container.dataset.optionsUrl;
        const verifyUrl = container.dataset.verifyUrl;
        const csrfToken = container.querySelector(
          'input[name="csrf_token"]',
        )?.value;
        status = container.querySelector("[data-conditional-passkey-status]");
        if (
          !optionsUrl ||
          !verifyUrl ||
          !csrfToken ||
          controller?.signal.aborted
        )
          return;
        let challengeId;
        let credential;
        try {
          const options = await passkeyPost(optionsUrl, {}, csrfToken);
          challengeId = requiredPasskeyResponseValue(options, "challengeId");
          delete options.challengeId;
          const request = {
            publicKey: preparePublicKeyOptions(
              options,
              "authentication",
              win.atob,
            ),
            mediation: "conditional",
          };
          if (controller) request.signal = controller.signal;
          credential = await nav.credentials.get(request);
          if (!(credential instanceof Credential)) return;
        } catch {
          return;
        }
        const result = await passkeyPost(
          verifyUrl,
          {
            challengeId,
            credential: serializePasskeyCredential(
              credential,
              "authentication",
              win.btoa,
            ),
          },
          csrfToken,
        );
        win.location.assign(requiredPasskeyResponseValue(result, "redirect"));
      } catch (error) {
        if (status) {
          status.hidden = false;
          status.textContent =
            error?.message || "The passkey was not accepted.";
        }
      }
    })();
    conditionalPending = pending.finally(() => {
      if (conditionalController === controller) {
        conditionalController = null;
        conditionalPending = Promise.resolve();
      }
    });
    return conditionalPending;
  }
  async function startExplicitPasskey(container) {
    const win = browserWindow();
    const doc = browserDocument();
    const nav = browserNavigator();
    const button = container.querySelector("[data-passkey-start]");
    const alternative = container.querySelector("[data-passkey-alternative]");
    const status = container.querySelector("[data-passkey-status]");
    if (
      !(button instanceof HTMLButtonElement()) ||
      !(status instanceof HTMLElement())
    )
      return;
    if (!win.PublicKeyCredential || !nav.credentials) {
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
      doc.querySelector('input[name="csrf_token"]')?.value;
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
        const challengeId = requiredPasskeyResponseValue(
          options,
          "challengeId",
        );
        delete options.challengeId;
        const credential = await nav.credentials.get({
          publicKey: preparePublicKeyOptions(
            options,
            "authentication",
            win.atob,
          ),
        });
        if (!(credential instanceof win.PublicKeyCredential))
          throw new Error("The browser did not return a passkey response.");
        const result = await passkeyPost(
          verifyUrl,
          {
            challengeId,
            credential: serializePasskeyCredential(
              credential,
              "authentication",
              win.btoa,
            ),
          },
          csrfToken,
        );
        win.location.assign(requiredPasskeyResponseValue(result, "redirect"));
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
  function initializePasskeyFlows() {
    const doc = browserDocument();
    const win = browserWindow();
    const nav = browserNavigator();
    doc.querySelectorAll("[data-passkey-flow]").forEach((container) => {
      const start = container.querySelector("[data-passkey-start]");
      const cancel = container.querySelector("[data-passkey-cancel]");
      const status = container.querySelector("[data-passkey-status]");
      const name = container.querySelector("[data-passkey-name]");
      if (
        !(start instanceof HTMLButtonElement()) ||
        !(cancel instanceof HTMLButtonElement()) ||
        !(status instanceof HTMLElement()) ||
        !win.PublicKeyCredential ||
        !nav.credentials
      ) {
        if (status instanceof HTMLElement())
          status.textContent =
            "Passkeys are unavailable in this browser. Use your password and authenticator instead.";
        return;
      }
      start.hidden = false;
      let controller;
      cancel.addEventListener("click", () => controller?.abort());
      start.addEventListener("click", async () => {
        const flow = container.dataset.passkeyFlow;
        const optionsUrl = container.dataset.optionsUrl;
        const verifyUrl = container.dataset.verifyUrl;
        const csrfToken =
          container.querySelector('input[name="csrf_token"]')?.value ||
          doc.querySelector('input[name="csrf_token"]')?.value;
        const label = name?.value.trim();
        if (!flow || !optionsUrl || !verifyUrl || !csrfToken) {
          status.textContent = "The passkey request could not be started.";
          return;
        }
        if (flow === "registration" && !label) {
          status.textContent = "Enter a name for this passkey.";
          name?.focus();
          return;
        }
        controller = new (BrowserAbortController())();
        start.disabled = true;
        cancel.hidden = false;
        status.textContent = "Waiting for your passkey…";
        try {
          const options = await passkeyPost(optionsUrl, {}, csrfToken);
          const challengeId = requiredPasskeyResponseValue(
            options,
            "challengeId",
          );
          delete options.challengeId;
          const publicKey = preparePublicKeyOptions(options, flow, win.atob);
          const credential =
            flow === "registration"
              ? await nav.credentials.create({
                  publicKey,
                  signal: controller.signal,
                })
              : await nav.credentials.get({
                  publicKey,
                  signal: controller.signal,
                });
          if (!(credential instanceof win.PublicKeyCredential))
            throw new Error("The browser did not return a passkey response.");
          const result = await passkeyPost(
            verifyUrl,
            {
              challengeId,
              credential: serializePasskeyCredential(
                credential,
                flow,
                win.btoa,
              ),
              ...(flow === "registration" ? { name: label } : {}),
            },
            csrfToken,
          );
          win.location.assign(requiredPasskeyResponseValue(result, "redirect"));
        } catch (error) {
          status.textContent =
            error?.name === "AbortError"
              ? "Passkey canceled. Use the password and authenticator option whenever you prefer."
              : error?.message || "The passkey was not accepted.";
        } finally {
          controller = undefined;
          start.disabled = false;
          cancel.hidden = true;
        }
      });
    });
    doc
      .querySelectorAll("[data-conditional-passkey-login]")
      .forEach((container) => void startConditionalPasskeyLogin(container));
    doc
      .querySelectorAll(
        "[data-explicit-passkey-login], [data-explicit-passkey-authentication]",
      )
      .forEach((container) => void startExplicitPasskey(container));
  }
  return {
    passkeyPost,
    settleConditionalPasskeyLogin,
    startConditionalPasskeyLogin,
    startExplicitPasskey,
    initializePasskeyFlows,
  };
}

export function initializePasskeyFlows() {
  return createPasskeyFlows().initializePasskeyFlows();
}
