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
