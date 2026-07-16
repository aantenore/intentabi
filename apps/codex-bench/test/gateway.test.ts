import { BenchmarkInvariantFailure } from "@intentabi/benchmark-core";
import { describe, expect, it, vi } from "vitest";

import {
  createBoundedResponsesGateway,
  LOCKED_CODEX_UPDATE_PLAN_TOOL,
  type BoundedResponsesGateway,
} from "../src/gateway.js";

const UPSTREAM_BASE_URL = "https://api.openai.com/v1";
const UPSTREAM_API_KEY = "parent-only-openai-key-for-test";
const EXPECTED_MODEL = "gpt-codex-gateway-test";
const EXPECTED_INSTRUCTIONS = "Pinned benchmark instructions.";
const EXPECTED_INPUT = "PRIVATE BENCHMARK INPUT";
const MAX_RESPONSE_BYTES = 65_536;

describe("bounded Responses gateway", () => {
  it("forwards exactly one attested request with parent-only credentials and bounded policy", async () => {
    const upstreamFetch = vi.fn<typeof fetch>(async () => completedResponse());
    const gateway = await createGateway(upstreamFetch);
    try {
      const response = await sendToGateway(gateway, requestBody());

      expect(response.status).toBe(200);
      expect(await response.text()).toContain("response.completed");
      expect(upstreamFetch).toHaveBeenCalledTimes(1);
      const [target, init] = upstreamFetch.mock.calls[0]!;
      expect(String(target)).toBe("https://api.openai.com/v1/responses");
      expect(init?.method).toBe("POST");
      expect(init?.redirect).toBe("error");
      const headers = new Headers(init?.headers);
      expect(headers.get("authorization")).toBe(`Bearer ${UPSTREAM_API_KEY}`);
      expect(headers.get("authorization")).not.toContain(gateway.proxyApiKey);

      const forwarded = JSON.parse(String(init?.body)) as Record<
        string,
        unknown
      >;
      expect(forwarded).toMatchObject({
        model: EXPECTED_MODEL,
        stream: true,
        store: false,
        background: false,
        parallel_tool_calls: false,
        tool_choice: "none",
        max_output_tokens: 256,
      });
      expect(toolNames(forwarded.tools)).toEqual(["update_plan"]);
      expect(JSON.stringify(forwarded)).not.toContain(gateway.proxyApiKey);
      expect(JSON.stringify(forwarded)).not.toContain("MUST_NOT_FORWARD");
      expect(JSON.stringify(forwarded)).not.toContain("local-only");
      expect(forwarded).not.toHaveProperty("client_metadata");
      expect(forwarded).not.toHaveProperty("prompt_cache_key");
      expect(() => gateway.assertConformant()).not.toThrow();
    } finally {
      await gateway.close();
    }
  });

  it("rejects any request that is not authenticated with the proxy key", async () => {
    const upstreamFetch = vi.fn<typeof fetch>(async () => completedResponse());
    const gateway = await createGateway(upstreamFetch);
    try {
      const response = await sendToGateway(
        gateway,
        requestBody(),
        "wrong-proxy-key",
      );

      expect(response.status).toBe(400);
      expect(upstreamFetch).not.toHaveBeenCalled();
      expect(() => gateway.assertConformant()).toThrowError(
        BenchmarkInvariantFailure,
      );
      expect(() => gateway.assertConformant()).toThrow(
        /Unexpected gateway request envelope/u,
      );
    } finally {
      await gateway.close();
    }
  });

  it("rejects an extra tool before the provider boundary", async () => {
    const upstreamFetch = vi.fn<typeof fetch>(async () => completedResponse());
    const gateway = await createGateway(upstreamFetch);
    const body = requestBody();
    body.tools.push({
      type: "function",
      name: "view_image",
      description: "must never cross the boundary",
      parameters: { type: "object" },
      x_private: "MUST_NOT_FORWARD_EXTRA",
    });
    try {
      const response = await sendToGateway(gateway, body);

      expect(response.status).toBe(502);
      expect(upstreamFetch).not.toHaveBeenCalled();
      expect(() => gateway.assertConformant()).toThrow(
        /violated the locked Codex policy/u,
      );
    } finally {
      await gateway.close();
    }
  });

  it("rejects schema drift even when the expected tool name is preserved", async () => {
    const upstreamFetch = vi.fn<typeof fetch>(async () => completedResponse());
    const gateway = await createGateway(upstreamFetch);
    const body = requestBody();
    body.tools[0]!.description = "A drifted update_plan contract";
    try {
      const response = await sendToGateway(gateway, body);

      expect(response.status).toBe(502);
      expect(upstreamFetch).not.toHaveBeenCalled();
      expect(() => gateway.assertConformant()).toThrow(
        /violated the locked Codex policy/u,
      );
    } finally {
      await gateway.close();
    }
  });

  it("never forwards a second request in the same arm", async () => {
    const upstreamFetch = vi.fn<typeof fetch>(async () => completedResponse());
    const gateway = await createGateway(upstreamFetch);
    try {
      const first = await sendToGateway(gateway, requestBody());
      expect(first.status).toBe(200);
      await first.text();

      const second = await sendToGateway(gateway, requestBody());
      expect(second.status).toBe(409);
      expect(upstreamFetch).toHaveBeenCalledTimes(1);
      expect(() => gateway.assertConformant()).toThrow(
        /Provider request budget exceeded/u,
      );
    } finally {
      await gateway.close();
    }
  });

  it("terminates an upstream response that exceeds the byte budget", async () => {
    const upstreamFetch = vi.fn<typeof fetch>(async () => oversizedResponse());
    const gateway = await createGateway(upstreamFetch);
    try {
      await expect(
        sendToGateway(gateway, requestBody()).then((response) =>
          response.arrayBuffer(),
        ),
      ).rejects.toThrow();

      expect(upstreamFetch).toHaveBeenCalledTimes(1);
      expect(() => gateway.assertConformant()).toThrow(
        /response exceeded the configured byte budget/u,
      );
    } finally {
      await gateway.close();
    }
  });
});

async function createGateway(
  fetchImpl: typeof fetch,
): Promise<BoundedResponsesGateway> {
  return createBoundedResponsesGateway({
    upstreamBaseUrl: UPSTREAM_BASE_URL,
    upstreamApiKey: UPSTREAM_API_KEY,
    expectedModel: EXPECTED_MODEL,
    expectedInstructions: EXPECTED_INSTRUCTIONS,
    expectedInput: EXPECTED_INPUT,
    maxOutputTokens: 256,
    maxRequestBytes: 65_536,
    maxResponseBytes: MAX_RESPONSE_BYTES,
    fetchImpl,
  });
}

async function sendToGateway(
  gateway: BoundedResponsesGateway,
  body: ReturnType<typeof requestBody>,
  apiKey = gateway.proxyApiKey,
): Promise<Response> {
  return fetch(`${gateway.baseUrl}/responses`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${apiKey}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  });
}

function requestBody() {
  return {
    model: EXPECTED_MODEL,
    instructions: EXPECTED_INSTRUCTIONS,
    stream: true,
    store: false,
    background: false,
    input: [
      {
        type: "message",
        role: "user",
        content: [{ type: "input_text", text: EXPECTED_INPUT }],
        internal_chat_message_metadata_passthrough: { turn_id: "local-only" },
      },
    ],
    tools: [structuredClone(LOCKED_CODEX_UPDATE_PLAN_TOOL)],
    parallel_tool_calls: true,
    tool_choice: "auto",
    reasoning: null,
    include: [],
    prompt_cache_key: "local-only-cache-key",
    client_metadata: { thread_id: "local-only-thread" },
    x_private: "MUST_NOT_FORWARD",
    max_output_tokens: 4_096,
  };
}

function toolNames(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((tool) => {
    if (tool === null || typeof tool !== "object") return [];
    const name = (tool as Record<string, unknown>).name;
    return typeof name === "string" ? [name] : [];
  });
}

function completedResponse(): Response {
  return new Response(
    'event: response.completed\ndata: {"type":"response.completed"}\n\n',
    {
      status: 200,
      headers: { "content-type": "text/event-stream" },
    },
  );
}

function oversizedResponse(): Response {
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array(40_000));
      controller.enqueue(new Uint8Array(40_000));
      controller.close();
    },
  });
  return new Response(body, {
    status: 200,
    headers: { "content-type": "text/event-stream" },
  });
}
