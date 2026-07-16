import { randomBytes, timingSafeEqual } from "node:crypto";
import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";

import { BenchmarkInvariantFailure } from "@intentabi/benchmark-core";

const EXPECTED_TOOL_NAMES = Object.freeze(["update_plan"] as const);
const MAX_JSON_NODES = 100_000;
export const CODEX_GATEWAY_IMPLEMENTATION =
  "io.github.aantenore.intentabi/codex-gateway/one-shot-exact-schema-v3" as const;

export const LOCKED_CODEX_UPDATE_PLAN_TOOL = deepFreeze({
  type: "function",
  name: "update_plan",
  description:
    "Updates the task plan.\nProvide an optional explanation and a list of plan items, each with a step and status.\nAt most one step can be in_progress at a time.\n",
  strict: false,
  parameters: {
    type: "object",
    properties: {
      explanation: {
        type: "string",
        description: "Optional explanation for this plan update.",
      },
      plan: {
        type: "array",
        description: "The list of steps",
        items: {
          type: "object",
          properties: {
            status: {
              type: "string",
              description: "Step status.",
              enum: ["pending", "in_progress", "completed"],
            },
            step: { type: "string", description: "Task step text." },
          },
          required: ["step", "status"],
          additionalProperties: false,
        },
      },
    },
    required: ["plan"],
    additionalProperties: false,
  },
});

export interface BoundedResponsesGateway {
  readonly baseUrl: string;
  readonly proxyApiKey: string;
  assertConformant(): void;
  close(): Promise<void>;
}

export interface BoundedResponsesGatewayOptions {
  readonly upstreamBaseUrl: string;
  readonly upstreamApiKey: string;
  readonly expectedModel: string;
  readonly expectedInstructions: string;
  readonly expectedInput: string;
  readonly maxOutputTokens: number;
  readonly maxRequestBytes: number;
  readonly maxResponseBytes: number;
  readonly fetchImpl?: typeof fetch;
}

/**
 * A one-request loopback gateway that attests Codex's effective outgoing tool
 * surface before forwarding content. The real API key remains in this parent
 * process; the Codex child receives only a per-arm proxy credential.
 */
export async function createBoundedResponsesGateway(
  options: BoundedResponsesGatewayOptions,
): Promise<BoundedResponsesGateway> {
  validateOptions(options);
  const proxyApiKey = `intentabi-proxy-${randomBytes(24).toString("base64url")}`;
  const fetchImpl = options.fetchImpl ?? fetch;
  const controllers = new Set<AbortController>();
  let claimedRequests = 0;
  let forwardedRequests = 0;
  let violation: string | null = null;
  let closed = false;

  const recordViolation = (message: string): void => {
    violation ??= message;
    for (const controller of controllers) controller.abort();
  };

  const server = createServer(async (request, response) => {
    try {
      if (closed) return respondError(response, 503);
      const authenticated = constantTimeEqual(
        request.headers.authorization ?? "",
        `Bearer ${proxyApiKey}`,
      );
      if (
        request.method !== "POST" ||
        request.url !== "/v1/responses" ||
        !authenticated
      ) {
        recordViolation(
          `Unexpected gateway request envelope (${request.method ?? "missing"} ${request.url ?? "missing"}; authenticated=${String(authenticated)})`,
        );
        return respondError(response, 400);
      }
      if (violation !== null || claimedRequests !== 0) {
        recordViolation(
          "Provider request budget exceeded inside one benchmark arm",
        );
        return respondError(response, 409);
      }
      // Claim the only request slot before the first asynchronous body read.
      // Otherwise two concurrent requests can both observe a zero forward count.
      claimedRequests += 1;

      const source = await readBoundedBody(request, options.maxRequestBytes);
      const parsed = parseJsonBody(source);
      const body = attestAndProjectRequest(
        parsed,
        options.expectedModel,
        options.expectedInstructions,
        options.expectedInput,
        options.maxOutputTokens,
      );
      if (violation !== null) {
        throw new GatewayBoundaryError(
          "Gateway policy was invalidated before provider forwarding",
        );
      }
      forwardedRequests += 1;

      const controller = new AbortController();
      controllers.add(controller);
      response.once("close", () => {
        if (!response.writableEnded) controller.abort();
      });
      try {
        const upstream = await fetchImpl(
          new URL("responses", ensureTrailingSlash(options.upstreamBaseUrl)),
          {
            method: "POST",
            headers: {
              accept: "text/event-stream",
              authorization: `Bearer ${options.upstreamApiKey}`,
              "content-type": "application/json",
              "user-agent": "intentabi-codex-bench/0.1",
            },
            body: JSON.stringify(body),
            redirect: "error",
            signal: controller.signal,
          },
        );
        await forwardBoundedResponse(
          upstream,
          response,
          options.maxResponseBytes,
          () => {
            recordViolation(
              "Provider response exceeded the configured byte budget",
            );
          },
        );
      } finally {
        controllers.delete(controller);
      }
    } catch (error) {
      if (error instanceof GatewayBoundaryError) {
        recordViolation(error.message);
      }
      if (!response.headersSent) respondError(response, 502);
      else response.destroy();
    }
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (address === null || typeof address === "string") {
    server.close();
    throw new BenchmarkInvariantFailure("Loopback gateway did not bind TCP");
  }

  return Object.freeze({
    baseUrl: `http://127.0.0.1:${address.port}/v1`,
    proxyApiKey,
    assertConformant: () => {
      if (violation !== null || forwardedRequests !== 1) {
        throw new BenchmarkInvariantFailure(
          violation ?? "Codex did not use the attested loopback gateway",
        );
      }
    },
    close: async () => {
      if (closed) return;
      closed = true;
      for (const controller of controllers) controller.abort();
      await new Promise<void>((resolve, reject) => {
        server.close((error) =>
          error === undefined ? resolve() : reject(error),
        );
      });
    },
  });
}

function validateOptions(options: BoundedResponsesGatewayOptions): void {
  let upstream: URL;
  try {
    upstream = new URL(options.upstreamBaseUrl);
  } catch {
    throw new TypeError("Gateway upstream URL is invalid");
  }
  if (
    upstream.protocol !== "https:" ||
    upstream.username !== "" ||
    upstream.password !== "" ||
    upstream.search !== "" ||
    upstream.hash !== "" ||
    typeof options.upstreamApiKey !== "string" ||
    Buffer.byteLength(options.upstreamApiKey) < 16 ||
    typeof options.expectedModel !== "string" ||
    options.expectedModel.length === 0 ||
    typeof options.expectedInstructions !== "string" ||
    options.expectedInstructions.length === 0 ||
    typeof options.expectedInput !== "string" ||
    options.expectedInput.length === 0 ||
    !Number.isSafeInteger(options.maxOutputTokens) ||
    options.maxOutputTokens < 16 ||
    options.maxOutputTokens > 4_096 ||
    !Number.isSafeInteger(options.maxRequestBytes) ||
    options.maxRequestBytes < 1_024 ||
    !Number.isSafeInteger(options.maxResponseBytes) ||
    options.maxResponseBytes < 65_536
  ) {
    throw new TypeError("Gateway policy is invalid");
  }
}

function attestAndProjectRequest(
  value: unknown,
  expectedModel: string,
  expectedInstructions: string,
  expectedInput: string,
  maxOutputTokens: number,
): Record<string, unknown> {
  if (!isPlainRecord(value)) {
    throw new GatewayBoundaryError("Provider request is not a plain object");
  }
  if (
    value.model !== expectedModel ||
    value.instructions !== expectedInstructions ||
    value.stream !== true ||
    value.store !== false ||
    value.background === true ||
    value.conversation != null ||
    value.previous_response_id != null ||
    value.reasoning !== null ||
    !Array.isArray(value.include) ||
    value.include.length !== 0 ||
    !hasExpectedInput(value.input, expectedInput) ||
    !hasExpectedToolSurface(value.tools) ||
    containsImageInput(value.input)
  ) {
    throw new GatewayBoundaryError(
      "Effective provider request violated the locked Codex policy",
    );
  }
  return {
    background: false,
    include: [],
    input: [
      {
        type: "message",
        role: "user",
        content: [{ type: "input_text", text: expectedInput }],
      },
    ],
    instructions: expectedInstructions,
    max_output_tokens: maxOutputTokens,
    model: expectedModel,
    parallel_tool_calls: false,
    reasoning: null,
    store: false,
    stream: true,
    tool_choice: "none",
    tools: [LOCKED_CODEX_UPDATE_PLAN_TOOL],
  };
}

function hasExpectedInput(value: unknown, expectedInput: string): boolean {
  if (!Array.isArray(value) || value.length !== 1) return false;
  const message = value[0];
  if (
    !isPlainRecord(message) ||
    message.type !== "message" ||
    message.role !== "user" ||
    !Array.isArray(message.content) ||
    message.content.length !== 1
  ) {
    return false;
  }
  const content = message.content[0];
  return (
    isPlainRecord(content) &&
    content.type === "input_text" &&
    content.text === expectedInput
  );
}

function parseJsonBody(source: string): unknown {
  try {
    return JSON.parse(source) as unknown;
  } catch {
    throw new GatewayBoundaryError("Provider request body is not valid JSON");
  }
}

function hasExpectedToolSurface(value: unknown): boolean {
  if (!Array.isArray(value) || value.length !== EXPECTED_TOOL_NAMES.length) {
    return false;
  }
  return jsonStructurallyEqual(value[0], LOCKED_CODEX_UPDATE_PLAN_TOOL);
}

function jsonStructurallyEqual(actual: unknown, expected: unknown): boolean {
  if (Object.is(actual, expected)) return true;
  if (Array.isArray(expected)) {
    return (
      Array.isArray(actual) &&
      actual.length === expected.length &&
      expected.every((entry, index) =>
        jsonStructurallyEqual(actual[index], entry),
      )
    );
  }
  if (isPlainRecord(expected)) {
    if (!isPlainRecord(actual)) return false;
    const expectedKeys = Object.keys(expected).sort();
    const actualKeys = Object.keys(actual).sort();
    return (
      expectedKeys.length === actualKeys.length &&
      expectedKeys.every(
        (key, index) =>
          key === actualKeys[index] &&
          jsonStructurallyEqual(actual[key], expected[key]),
      )
    );
  }
  return false;
}

function containsImageInput(value: unknown): boolean {
  const pending: unknown[] = [value];
  let visited = 0;
  while (pending.length > 0) {
    visited += 1;
    if (visited > MAX_JSON_NODES) {
      throw new GatewayBoundaryError(
        "Provider request is too structurally large",
      );
    }
    const current = pending.pop();
    if (Array.isArray(current)) {
      pending.push(...current);
      continue;
    }
    if (!isPlainRecord(current)) continue;
    if (
      current.type === "input_image" ||
      current.type === "image_url" ||
      Object.hasOwn(current, "image_data") ||
      Object.hasOwn(current, "image_url")
    ) {
      return true;
    }
    pending.push(...Object.values(current));
  }
  return false;
}

async function readBoundedBody(
  request: IncomingMessage,
  maxBytes: number,
): Promise<string> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += buffer.byteLength;
    if (total > maxBytes) {
      throw new GatewayBoundaryError(
        "Provider request exceeded the configured byte budget",
      );
    }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function forwardBoundedResponse(
  upstream: Response,
  response: ServerResponse,
  maxBytes: number,
  markViolation: () => void,
): Promise<void> {
  const headers: Record<string, string> = {};
  const contentType = upstream.headers.get("content-type");
  const requestId = upstream.headers.get("x-request-id");
  if (contentType !== null) headers["content-type"] = contentType;
  if (requestId !== null) headers["x-request-id"] = requestId;
  response.writeHead(upstream.status, headers);
  if (upstream.body === null) {
    response.end();
    return;
  }
  let total = 0;
  for await (const chunk of upstream.body) {
    const buffer = Buffer.from(chunk);
    total += buffer.byteLength;
    if (total > maxBytes) {
      markViolation();
      await upstream.body.cancel().catch(() => undefined);
      response.destroy();
      return;
    }
    response.write(buffer);
  }
  response.end();
}

function respondError(response: ServerResponse, status: number): void {
  response.writeHead(status, { "content-type": "application/json" });
  response.end('{"error":{"message":"benchmark gateway rejected request"}}');
}

function constantTimeEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  return (
    leftBytes.byteLength === rightBytes.byteLength &&
    timingSafeEqual(leftBytes, rightBytes)
  );
}

function ensureTrailingSlash(value: string): URL {
  const url = new URL(value);
  if (!url.pathname.endsWith("/")) url.pathname += "/";
  return url;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

class GatewayBoundaryError extends Error {}
