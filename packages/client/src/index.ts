export type TransformState = "protected" | "blocked" | "bypassed";

export interface TransformResponse {
  text: string | null;
  state: TransformState;
  session_id: string;
  policy_name: string;
  policy_version: number;
  detections: Array<Record<string, unknown>>;
  capsule?: string | null;
  reason?: string | null;
}

export class PrivacyGatewayError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "PrivacyGatewayError";
  }
}

/**
 * Read a response body, or report that it was not the promised JSON.
 *
 * A gateway failure is not always JSON: Starlette answers an unhandled exception
 * with a `text/plain` "Internal Server Error", a reverse proxy answers with an
 * HTML error page, and a 503 can carry no body at all. The body is therefore read
 * once as text and parsed only when it parses; the caller decides what a
 * non-JSON body means. `privacy_gateway.client._raise` reads it the same way.
 */
function decodeBody(raw: string): { json: true; body: unknown } | { json: false } {
  if (raw === "") return { json: false };
  try {
    return { json: true, body: JSON.parse(raw) as unknown };
  } catch {
    return { json: false };
  }
}

/** The `detail` a JSON gateway error carries, as text, else `fallback`. */
function describeDetail(body: unknown, fallback: string): string {
  if (typeof body === "object" && body !== null && "detail" in body) {
    const { detail } = body as { detail: unknown };
    if (typeof detail === "string") return detail;
    // FastAPI answers a validation failure with a list of objects, which
    // `String()` would flatten to `[object Object]`.
    if (detail !== undefined && detail !== null) return JSON.stringify(detail);
  }
  return fallback;
}

export interface ClientOptions {
  baseUrl?: string;
  fetch?: typeof globalThis.fetch;
  headers?: Record<string, string>;
}

export class PrivacyGatewayClient {
  readonly baseUrl: string;
  readonly fetcher: typeof globalThis.fetch;
  readonly headers: Record<string, string>;

  constructor(options: ClientOptions = {}) {
    this.baseUrl = (options.baseUrl ?? "http://127.0.0.1:8787").replace(/\/$/u, "");
    this.fetcher = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.headers = { ...options.headers };
  }

  private async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const response = await this.fetcher(`${this.baseUrl}${path}`, {
      ...init,
      headers: {
        ...(init.body ? { "content-type": "application/json" } : {}),
        ...this.headers,
        ...(init.headers ?? {}),
      },
      redirect: "error",
    });
    // `response.json()` was called unconditionally, so any body that was not JSON
    // escaped as a bare `SyntaxError` with the status discarded: a caller's
    // documented `error instanceof PrivacyGatewayError && error.status === 503`
    // branch never ran for a 500, a proxy error page or an empty 503 — exactly the
    // failures it exists to tell apart. Read the body once and decide.
    const raw = await response.text();
    const decoded = decodeBody(raw);
    if (!response.ok) {
      throw new PrivacyGatewayError(
        `gateway returned ${response.status}: ${describeDetail(
          decoded.json ? decoded.body : undefined,
          raw.trim() || "request failed",
        )}`,
        response.status,
      );
    }
    if (!decoded.json) {
      // A 2xx that is not the promised JSON is a contract break, not a parse
      // accident: report it as a structured error rather than a `SyntaxError`.
      throw new PrivacyGatewayError(
        `gateway returned ${response.status}: response body was not JSON`,
        response.status,
      );
    }
    return decoded.body as T;
  }

  createSession(options: {
    preset?: string;
    policy?: Record<string, unknown>;
    metadata?: Record<string, unknown>;
  } = {}): Promise<{ session_id: string; policy: Record<string, unknown> }> {
    return this.request("/v1/sessions", {
      method: "POST",
      body: JSON.stringify({ preset: "balanced", metadata: {}, ...options }),
    });
  }

  transform(
    text: string,
    options: {
      preset?: string;
      sessionId?: string;
      restoreKey?: string;
      scope?: string;
    } = {},
  ): Promise<TransformResponse> {
    return this.request("/v1/transform", {
      method: "POST",
      body: JSON.stringify({
        text,
        preset: options.preset ?? "balanced",
        session_id: options.sessionId,
        restore_key: options.restoreKey,
        scope: options.scope ?? "text",
      }),
    });
  }

  restore(text: string, sessionId: string): Promise<{ text: string }> {
    return this.request("/v1/restore", {
      method: "POST",
      body: JSON.stringify({ text, session_id: sessionId }),
    });
  }

  restoreCapsule(
    text: string,
    capsule: string,
    restoreKey: string,
    sessionId: string,
  ): Promise<{ text: string }> {
    return this.request("/v1/restore/capsule", {
      method: "POST",
      body: JSON.stringify({
        text,
        capsule,
        restore_key: restoreKey,
        session_id: sessionId,
      }),
    });
  }

  summary(sessionId: string): Promise<Record<string, unknown>> {
    return this.request(`/v1/sessions/${encodeURIComponent(sessionId)}/summary`);
  }

  async deleteSession(sessionId: string): Promise<boolean> {
    const result = await this.request<{ deleted: boolean }>(
      `/v1/sessions/${encodeURIComponent(sessionId)}`,
      { method: "DELETE" },
    );
    return result.deleted;
  }
}
