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
    const body = (await response.json()) as Record<string, unknown>;
    if (!response.ok) {
      throw new PrivacyGatewayError(
        `gateway returned ${response.status}: ${String(body.detail ?? "request failed")}`,
        response.status,
      );
    }
    return body as T;
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
