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
  getCredential,
  responses = [],
} = {}) {
  class TestPublicKeyCredential {}
  TestPublicKeyCredential.isConditionalMediationAvailable = async () => available;
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
  const status = { hidden: true, textContent: "" };
  const container = {
    dataset: {
      optionsUrl: "/login/passkey/options",
      verifyUrl: "/login/passkey/verify",
    },
    querySelector: (selector) =>
      selector === 'input[name="csrf_token"]' ? { value: "csrf" } : status,
  };
  context.window.PublicKeyCredential = TestPublicKeyCredential;
  context.window.atob = (value) => Buffer.from(value, "base64").toString("binary");
  context.window.btoa = (value) => Buffer.from(value, "binary").toString("base64");
  context.window.location = { assign: (value) => redirects.push(value) };
  context.window.fetch = async (...request) => {
    requests.push(request);
    return responses.shift();
  };
  context.navigator = {
    credentials: {
      get: async (request) => {
        credentialRequests.push(request);
        return getCredential ? getCredential(credential) : credential;
      },
    },
  };
  return {
    container,
    credentialRequests,
    redirects,
    requests,
    status,
  };
}

function accountScopedHarness(options = {}) {
  const harness = conditionalHarness(options);
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
  assert.equal(harness.status.textContent, "The passkey was not accepted.");
  assert.deepEqual(harness.redirects, []);
});

test("account-scoped authentication is wired to start automatically", () => {
  assert.match(
    source,
    /querySelectorAll\("\[data-account-scoped-passkey-authentication\]"\)[\s\S]*startAccountScopedPasskeyAuthentication/,
  );
});

test("account-scoped authentication preserves allowCredentials and redirects", async () => {
  const harness = accountScopedHarness({
    responses: [
      accountScopedAuthenticationOptions(),
      response({ json: async () => ({ redirect: "/profile/password/change" }) }),
    ],
  });
  await context.startAccountScopedPasskeyAuthentication(harness.container);

  assert.equal(harness.requests.length, 2);
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
  assert.equal(harness.status.hidden, true);
});

test("account-scoped authentication keeps pre-verification failures quiet", async () => {
  const unsupported = accountScopedHarness();
  delete context.window.PublicKeyCredential;
  await context.startAccountScopedPasskeyAuthentication(unsupported.container);
  assert.equal(unsupported.requests.length, 0);
  assert.equal(unsupported.status.hidden, true);

  const missingCredentials = accountScopedHarness();
  delete context.navigator.credentials;
  await context.startAccountScopedPasskeyAuthentication(
    missingCredentials.container,
  );
  assert.equal(missingCredentials.requests.length, 0);
  assert.equal(missingCredentials.status.hidden, true);

  const missingConfiguration = accountScopedHarness();
  delete missingConfiguration.container.dataset.optionsUrl;
  await context.startAccountScopedPasskeyAuthentication(
    missingConfiguration.container,
  );
  assert.equal(missingConfiguration.requests.length, 0);
  assert.equal(missingConfiguration.status.hidden, true);

  const optionsFailure = accountScopedHarness({
    responses: [response({ status: 409, json: async () => ({ error: "None" }) })],
  });
  await context.startAccountScopedPasskeyAuthentication(optionsFailure.container);
  assert.equal(optionsFailure.credentialRequests.length, 0);
  assert.equal(optionsFailure.status.hidden, true);

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
    await context.startAccountScopedPasskeyAuthentication(canceled.container);
    assert.equal(canceled.requests.length, 1);
    assert.equal(canceled.status.hidden, true);
    assert.deepEqual(canceled.redirects, []);
  }

  const serializationFailure = accountScopedHarness({
    getCredential: (credential) => {
      credential.getClientExtensionResults = undefined;
      return credential;
    },
    responses: [accountScopedAuthenticationOptions()],
  });
  await context.startAccountScopedPasskeyAuthentication(
    serializationFailure.container,
  );
  assert.equal(serializationFailure.requests.length, 1);
  assert.equal(serializationFailure.status.hidden, true);
});

test("account-scoped authentication shows bounded verification errors", async () => {
  const harness = accountScopedHarness({
    responses: [
      accountScopedAuthenticationOptions(),
      response({
        status: 401,
        json: async () => ({ error: "The passkey was not accepted." }),
      }),
    ],
  });
  await context.startAccountScopedPasskeyAuthentication(harness.container);
  assert.equal(harness.status.hidden, false);
  assert.equal(harness.status.textContent, "The passkey was not accepted.");
  assert.deepEqual(harness.redirects, []);
});
