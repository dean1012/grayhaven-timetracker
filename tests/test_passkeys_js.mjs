import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const source = readFileSync(new URL("../static/app.js", import.meta.url), "utf8");
const start = source.indexOf("function decodeBase64Url");
const end = source.indexOf('document.querySelectorAll("[data-passkey-flow]")');
assert.notEqual(start, -1);
assert.notEqual(end, -1);

const context = vm.createContext({ window: {} });
class TestHTMLElement {}
class TestHTMLButtonElement extends TestHTMLElement {}
context.HTMLElement = TestHTMLElement;
context.HTMLButtonElement = TestHTMLButtonElement;
vm.runInContext(source.slice(start, end), context);

function response({
  status = 200,
  contentType = "application/json",
  json = async () => ({}),
}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: {
      get: (name) => (name.toLowerCase() === "content-type" ? contentType : null),
    },
    json,
  };
}

function authenticationOptions() {
  return response({
    json: async () => ({
      challenge: "AQ",
      challengeId: "c".repeat(32),
      rpId: "localhost",
      timeout: 300000,
      userVerification: "required",
    }),
  });
}

function accountScopedAuthenticationOptions() {
  return response({
    json: async () => ({
      challenge: "AQ",
      challengeId: "a".repeat(32),
      rpId: "localhost",
      timeout: 300000,
      userVerification: "required",
      allowCredentials: [
        { id: "Ag", type: "public-key", transports: ["internal"] },
      ],
    }),
  });
}

function conditionalHarness({
  available = true,
  conditionalAvailability,
  getCredential,
  responses = [],
  localCsrf = true,
} = {}) {
  class TestPublicKeyCredential {}
  TestPublicKeyCredential.isConditionalMediationAvailable =
    conditionalAvailability || (async () => available);
  const credential = new TestPublicKeyCredential();
  Object.assign(credential, {
    id: "credential",
    rawId: Uint8Array.of(2).buffer,
    type: "public-key",
    authenticatorAttachment: "platform",
    getClientExtensionResults: () => ({}),
    response: {
      authenticatorData: Uint8Array.of(3).buffer,
      clientDataJSON: Uint8Array.of(4).buffer,
      signature: Uint8Array.of(5).buffer,
      userHandle: Uint8Array.of(6).buffer,
    },
  });
  const requests = [];
  const credentialRequests = [];
  const redirects = [];
  const documentQueries = [];
  const status = { hidden: true, textContent: "" };
  Object.setPrototypeOf(status, TestHTMLElement.prototype);
  const alternative = { hidden: true };
  const button = {
    hidden: false,
    disabled: false,
    clickHandler: null,
    addEventListener: (event, handler) => {
      if (event === "click") {
        button.clickHandler = handler;
      }
    },
  };
  Object.setPrototypeOf(button, TestHTMLButtonElement.prototype);
  const container = {
    dataset: {
      optionsUrl: "/login/passkey/options",
      verifyUrl: "/login/passkey/verify",
    },
    querySelector: (selector) => {
      if (selector === 'input[name="csrf_token"]') {
        return localCsrf ? { value: "csrf" } : null;
      }
      if (selector === "[data-passkey-start]") {
        return button;
      }
      if (selector === "[data-passkey-alternative]") {
        return alternative;
      }
      return status;
    },
  };
  context.window.PublicKeyCredential = TestPublicKeyCredential;
  context.window.atob = (value) => Buffer.from(value, "base64").toString("binary");
  context.window.btoa = (value) => Buffer.from(value, "binary").toString("base64");
  context.window.location = { assign: (value) => redirects.push(value) };
  context.document = {
    querySelector: (selector) => {
      documentQueries.push(selector);
      return selector === 'input[name="csrf_token"]' ? { value: "csrf" } : null;
    },
  };
  context.window.fetch = async (...request) => {
    requests.push(request);
    return responses.shift();
  };
  context.navigator = {
    credentials: {
      get: async (request) => {
        credentialRequests.push(request);
        return getCredential ? getCredential(credential, request) : credential;
      },
    },
  };
  return {
    container,
    credentialRequests,
    redirects,
    requests,
    status,
    alternative,
    documentQueries,
    button,
    click: async () => {
      assert.ok(button.clickHandler);
      await button.clickHandler();
    },
  };
}

function accountScopedHarness(options = {}) {
  const harness = conditionalHarness({ ...options, localCsrf: false });
  harness.container.dataset = {
    optionsUrl: "/reauthenticate/passkey/options",
    verifyUrl: "/reauthenticate/passkey/verify",
  };
  return harness;
}

async function postWith(serverResponse) {
  context.window.fetch = async () => serverResponse;
  return context.passkeyPost("/passkey", {}, "csrf");
}

test("passkeyPost uses a valid server JSON error", async () => {
  await assert.rejects(
    postWith(
      response({
        status: 409,
        json: async () => ({ error: "No passkeys are available." }),
      }),
    ),
    /No passkeys are available\./,
  );
});

test("passkeyPost safely handles HTML and malformed JSON errors", async () => {
  await assert.rejects(
    postWith(response({ status: 403, contentType: "text/html" })),
    /The passkey request was not accepted\./,
  );
  await assert.rejects(
    postWith(
      response({
        status: 500,
        json: async () => {
          throw new SyntaxError("invalid JSON");
        },
      }),
    ),
    /The passkey request was not accepted\./,
  );
});

test("passkeyPost gives non-JSON rate limits a stable retry message", async () => {
  await assert.rejects(
    postWith(response({ status: 429, contentType: "text/html" })),
    /Too many passkey attempts\. Wait a moment and try again\./,
  );
});

test("passkeyPost requires a JSON object on successful responses", async () => {
  await assert.rejects(
    postWith(response({ contentType: "text/html" })),
    /The passkey response was not accepted\./,
  );
  await assert.rejects(
    postWith(response({ json: async () => ["unexpected"] })),
    /The passkey response was not accepted\./,
  );
  assert.deepEqual(
    await postWith(response({ json: async () => ({ challengeId: "challenge" }) })),
    { challengeId: "challenge" },
  );
});

test("successful passkey fields must be nonempty strings", () => {
  assert.equal(
    context.requiredPasskeyResponseValue({ redirect: "/profile" }, "redirect"),
    "/profile",
  );
  assert.throws(
    () => context.requiredPasskeyResponseValue({}, "redirect"),
    /The passkey response was not accepted\./,
  );
  assert.throws(
    () => context.requiredPasskeyResponseValue({ challengeId: 42 }, "challengeId"),
    /The passkey response was not accepted\./,
  );
  assert.throws(
    () =>
      context.requiredPasskeyResponseValue(
        { challengeId: "short" },
        "challengeId",
      ),
    /The passkey response was not accepted\./,
  );
  assert.throws(
    () =>
      context.requiredPasskeyResponseValue(
        { redirect: "https://example.invalid" },
        "redirect",
      ),
    /The passkey response was not accepted\./,
  );
});

test("conditional login quietly skips unsupported browsers", async () => {
  const harness = conditionalHarness({ available: false });
  await context.startConditionalPasskeyLogin(harness.container);
  assert.equal(harness.requests.length, 0);
  assert.equal(harness.credentialRequests.length, 0);
  assert.equal(harness.status.hidden, true);

  delete context.window.PublicKeyCredential.isConditionalMediationAvailable;
  await context.startConditionalPasskeyLogin(harness.container);
  assert.equal(harness.requests.length, 0);
});

test("conditional login requests mediation and redirects after verification", async () => {
  const harness = conditionalHarness({
    responses: [
      authenticationOptions(),
      response({ json: async () => ({ redirect: "/profile" }) }),
    ],
  });
  await context.startConditionalPasskeyLogin(harness.container);

  assert.equal(harness.requests.length, 2);
  assert.equal(harness.requests[0][0], "/login/passkey/options");
  assert.equal(harness.requests[1][0], "/login/passkey/verify");
  assert.equal(harness.credentialRequests.length, 1);
  assert.equal(harness.credentialRequests[0].mediation, "conditional");
  assert.ok(ArrayBuffer.isView(harness.credentialRequests[0].publicKey.challenge));
  assert.deepEqual(harness.redirects, ["/profile"]);
  assert.equal(harness.status.hidden, true);
});

test("conditional login keeps option failures and cancellation quiet", async () => {
  const limited = conditionalHarness({
    responses: [response({ status: 429, contentType: "text/html" })],
  });
  await context.startConditionalPasskeyLogin(limited.container);
  assert.equal(limited.credentialRequests.length, 0);
  assert.equal(limited.status.hidden, true);
  assert.deepEqual(limited.redirects, []);

  const canceled = conditionalHarness({
    getCredential: () => {
      const error = new Error("canceled");
      error.name = "AbortError";
      throw error;
    },
    responses: [authenticationOptions()],
  });
  await context.startConditionalPasskeyLogin(canceled.container);
  assert.equal(canceled.status.hidden, true);
  assert.deepEqual(canceled.redirects, []);
});

test("conditional login shows bounded server verification errors", async () => {
  const harness = conditionalHarness({
    responses: [
      authenticationOptions(),
      response({
        status: 401,
        json: async () => ({ error: "The passkey was not accepted." }),
      }),
    ],
  });
  await context.startConditionalPasskeyLogin(harness.container);
  assert.equal(harness.status.hidden, false);
  assert.ok(harness.status.textContent);
  assert.deepEqual(harness.redirects, []);
});

test("explicit passkey authentication preserves allowCredentials and redirects", async () => {
  const harness = accountScopedHarness({
    responses: [
      accountScopedAuthenticationOptions(),
      response({ json: async () => ({ redirect: "/profile/password/change" }) }),
    ],
  });
  assert.equal(harness.alternative.hidden, true);
  await context.startExplicitPasskey(harness.container);
  assert.equal(harness.container.dataset.passkeyState, "ready");
  assert.equal(harness.alternative.hidden, false);
  await harness.click();

  assert.equal(harness.requests.length, 2);
  assert.deepEqual(harness.documentQueries, ['input[name="csrf_token"]']);
  assert.equal(harness.requests[0][0], "/reauthenticate/passkey/options");
  assert.equal(harness.requests[1][0], "/reauthenticate/passkey/verify");
  assert.equal(harness.credentialRequests.length, 1);
  assert.equal("mediation" in harness.credentialRequests[0], false);
  assert.deepEqual(
    Array.from(
      harness.credentialRequests[0].publicKey.allowCredentials[0].id,
    ),
    [2],
  );
  assert.equal(
    harness.credentialRequests[0].publicKey.allowCredentials[0].type,
    "public-key",
  );
  assert.deepEqual(harness.redirects, ["/profile/password/change"]);
  assert.equal(harness.status.hidden, false);
});

test("explicit passkey authentication settles an active conditional login", async () => {
  class TestAbortController {
    constructor() {
      this.signal = {
        aborted: false,
        listeners: [],
        addEventListener: (event, listener) => {
          if (event === "abort") this.signal.listeners.push(listener);
        },
      };
    }

    abort() {
      this.signal.aborted = true;
      for (const listener of this.signal.listeners) listener();
    }
  }
  context.AbortController = TestAbortController;
  let conditionalSettled = false;
  const harness = conditionalHarness({
    responses: [
      authenticationOptions(),
      accountScopedAuthenticationOptions(),
      response({ json: async () => ({ redirect: "/profile" }) }),
    ],
    getCredential: (credential, request) => {
      if (request.mediation === "conditional") {
        return new Promise((resolve, reject) => {
          request.signal.addEventListener("abort", () => {
            const error = new Error("conditional canceled");
            error.name = "AbortError";
            reject(error);
          });
        });
      }
      return credential;
    },
  });

  const conditional = context.startConditionalPasskeyLogin(harness.container);
  await new Promise((resolve) => setImmediate(resolve));
  await context.startExplicitPasskey(harness.container);
  await harness.click();
  await conditional;
  conditionalSettled = true;

  assert.equal(conditionalSettled, true);
  assert.equal(harness.credentialRequests[0].mediation, "conditional");
  assert.equal("mediation" in harness.credentialRequests[1], false);
  assert.deepEqual(harness.redirects, ["/profile"]);
});

test("explicit activation wins while conditional capability is still probing", async () => {
  let resolveCapability;
  const capability = new Promise((resolve) => {
    resolveCapability = resolve;
  });
  const harness = accountScopedHarness({
    conditionalAvailability: () => capability,
    responses: [
      accountScopedAuthenticationOptions(),
      response({ json: async () => ({ redirect: "/profile/password/change" }) }),
    ],
  });

  const conditional = context.startConditionalPasskeyLogin(harness.container);
  await context.startExplicitPasskey(harness.container);
  const explicit = harness.click();
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(harness.requests, []);

  resolveCapability(true);
  await conditional;
  await explicit;

  assert.deepEqual(
    harness.requests.map(([url]) => url),
    ["/reauthenticate/passkey/options", "/reauthenticate/passkey/verify"],
  );
  assert.equal(harness.credentialRequests.length, 1);
  assert.equal("mediation" in harness.credentialRequests[0], false);
  assert.deepEqual(harness.redirects, ["/profile/password/change"]);
});

test("explicit passkey authentication reports pre-verification failures", async () => {
  const unsupported = accountScopedHarness();
  delete context.window.PublicKeyCredential;
  await context.startExplicitPasskey(unsupported.container);
  assert.equal(unsupported.requests.length, 0);
  assert.equal(unsupported.button.hidden, true);
  assert.equal(unsupported.status.hidden, false);

  const missingCredentials = accountScopedHarness();
  delete context.navigator.credentials;
  await context.startExplicitPasskey(missingCredentials.container);
  assert.equal(missingCredentials.requests.length, 0);
  assert.equal(missingCredentials.button.hidden, true);
  assert.equal(missingCredentials.status.hidden, false);

  const missingConfiguration = accountScopedHarness();
  delete missingConfiguration.container.dataset.optionsUrl;
  await context.startExplicitPasskey(missingConfiguration.container);
  assert.equal(missingConfiguration.requests.length, 0);
  assert.equal(missingConfiguration.button.disabled, true);
  assert.equal(missingConfiguration.status.hidden, false);

  const optionsFailure = accountScopedHarness({
    responses: [response({ status: 409, json: async () => ({ error: "None" }) })],
  });
  await context.startExplicitPasskey(optionsFailure.container);
  await optionsFailure.click();
  assert.equal(optionsFailure.credentialRequests.length, 0);
  assert.equal(optionsFailure.status.hidden, false);

  for (const result of [null, "cancel"]) {
    const canceled = accountScopedHarness({
      getCredential: () => {
        if (result === null) {
          return null;
        }
        const error = new Error("canceled");
        error.name = "AbortError";
        throw error;
      },
      responses: [accountScopedAuthenticationOptions()],
    });
    await context.startExplicitPasskey(canceled.container);
    await canceled.click();
    assert.equal(canceled.requests.length, 1);
    assert.equal(canceled.status.hidden, false);
    assert.deepEqual(canceled.redirects, []);
  }

  const serializationFailure = accountScopedHarness({
    getCredential: (credential) => {
      credential.getClientExtensionResults = undefined;
      return credential;
    },
    responses: [accountScopedAuthenticationOptions()],
  });
  await context.startExplicitPasskey(serializationFailure.container);
  await serializationFailure.click();
  assert.equal(serializationFailure.requests.length, 1);
  assert.equal(serializationFailure.status.hidden, false);
});

test("explicit passkey authentication shows bounded verification errors", async () => {
  const harness = accountScopedHarness({
    responses: [
      accountScopedAuthenticationOptions(),
      response({
        status: 401,
        json: async () => ({ error: "The passkey was not accepted." }),
      }),
    ],
  });
  await context.startExplicitPasskey(harness.container);
  await harness.click();
  assert.equal(harness.status.hidden, false);
  assert.ok(harness.status.textContent);
  assert.deepEqual(harness.redirects, []);
});
