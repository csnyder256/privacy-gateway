import assert from "node:assert/strict";
import test from "node:test";

import { PrivacyGatewayClient, PrivacyGatewayError } from "../src/index.js";

test("client emits the documented transform request and rejects redirects", async () => {
  let captured: { url: string; init?: RequestInit } | undefined;
  const fetcher: typeof fetch = async (input, init) => {
    captured = { url: String(input), init };
    return new Response(
      JSON.stringify({
        text: "safe",
        state: "protected",
        session_id: "session",
        policy_name: "balanced",
        policy_version: 1,
        detections: [],
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  };
  const client = new PrivacyGatewayClient({ baseUrl: "https://privacy.example/", fetch: fetcher });
  const result = await client.transform("secret", { preset: "strict", restoreKey: "key" });
  assert.equal(result.state, "protected");
  assert.equal(captured?.url, "https://privacy.example/v1/transform");
  assert.equal(captured?.init?.redirect, "error");
  assert.deepEqual(JSON.parse(String(captured?.init?.body)), {
    text: "secret",
    preset: "strict",
    restore_key: "key",
    scope: "text",
  });
});

test("client exposes structured gateway failures", async () => {
  const client = new PrivacyGatewayClient({
    fetch: async () =>
      new Response(JSON.stringify({ detail: "blocked" }), {
        status: 422,
        headers: { "content-type": "application/json" },
      }),
  });
  await assert.rejects(
    () => client.transform("value"),
    (error: unknown) => error instanceof PrivacyGatewayError && error.status === 422,
  );
});

test("client keeps a non-JSON gateway failure structured and keeps the status", async () => {
  // Starlette answers an unhandled exception with text/plain, a reverse proxy
  // answers with an HTML error page, and a 503 can carry no body at all. Every
  // one of those used to escape as `SyntaxError` from `response.json()`, with the
  // status thrown away, so the documented `error.status === 503` retry branch
  // never ran for the failures it exists to catch.
  const cases: Array<[number, string, string]> = [
    [500, "text/plain; charset=utf-8", "Internal Server Error"],
    [502, "text/html", "<html><body>502 Bad Gateway</body></html>"],
    [503, "", ""],
  ];
  for (const [status, contentType, text] of cases) {
    const client = new PrivacyGatewayClient({
      fetch: async () =>
        new Response(text, {
          status,
          headers: contentType ? { "content-type": contentType } : {},
        }),
    });
    await assert.rejects(
      () => client.transform("value"),
      (error: unknown) => {
        assert.ok(error instanceof PrivacyGatewayError, `${status}: ${String(error)}`);
        assert.equal(error.status, status);
        assert.ok(
          error.message.startsWith(`gateway returned ${status}: `),
          `${status}: ${error.message}`,
        );
        return true;
      },
    );
  }
});

test("client reports the raw body when a failure is not JSON", async () => {
  const client = new PrivacyGatewayClient({
    fetch: async () =>
      new Response("Internal Server Error", {
        status: 500,
        headers: { "content-type": "text/plain; charset=utf-8" },
      }),
  });
  await assert.rejects(
    () => client.transform("value"),
    (error: unknown) =>
      error instanceof PrivacyGatewayError &&
      error.message === "gateway returned 500: Internal Server Error",
  );
});

test("client serializes a validation detail list instead of flattening it", async () => {
  const client = new PrivacyGatewayClient({
    fetch: async () =>
      new Response(
        JSON.stringify({ detail: [{ loc: ["body", "text"], msg: "Field required" }] }),
        { status: 422, headers: { "content-type": "application/json" } },
      ),
  });
  await assert.rejects(
    () => client.transform("value"),
    (error: unknown) => {
      assert.ok(error instanceof PrivacyGatewayError);
      assert.equal(error.status, 422);
      assert.ok(error.message.includes("Field required"), error.message);
      assert.ok(!error.message.includes("[object Object]"), error.message);
      return true;
    },
  );
});

test("client refuses a 2xx body that is not the promised JSON", async () => {
  const client = new PrivacyGatewayClient({
    fetch: async () =>
      new Response("<html>not json</html>", {
        status: 200,
        headers: { "content-type": "text/html" },
      }),
  });
  await assert.rejects(
    () => client.transform("value"),
    (error: unknown) => {
      assert.ok(error instanceof PrivacyGatewayError, String(error));
      assert.equal(error.status, 200);
      assert.match(error.message, /response body was not JSON/u);
      return true;
    },
  );
});

test("client still returns the parsed JSON of a successful response", async () => {
  const client = new PrivacyGatewayClient({
    fetch: async () =>
      new Response(JSON.stringify({ text: "safe", state: "protected", detections: [] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
  });
  assert.deepEqual(await client.transform("secret"), {
    text: "safe",
    state: "protected",
    detections: [],
  });
});
