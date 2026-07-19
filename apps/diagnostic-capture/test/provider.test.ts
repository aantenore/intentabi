import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { parseDiagnosticCaptureConfig } from "../src/config.js";
import {
  createOpenAICompatibleDiagnosticRunner,
  DiagnosticProviderError,
} from "../src/provider.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

describe("OpenAI-compatible diagnostic provider", () => {
  it("captures structured output, usage, and separate reasoning without retaining protocol metadata", async () => {
    const requests: unknown[] = [];
    const runner = createOpenAICompatibleDiagnosticRunner(
      exampleConfig(),
      {},
      (async (input: RequestInfo | URL, init?: RequestInit) => {
        const request = new Request(input, init);
        requests.push(JSON.parse(await request.text()));
        return providerResponse({
          content: '{"operation":"read-project-status","status":"available"}',
          reasoning: "private chain that must never be stored raw",
          finishReason: "stop",
        });
      }) as typeof fetch,
    );

    const observation = await runner.run("Show project status");

    expect(requests).toHaveLength(1);
    expect(requests[0]).toMatchObject({
      model: "qwen3:4b",
      reasoning_effort: "none",
      temperature: 0,
      max_tokens: 512,
    });
    expect(observation).toEqual({
      output: { operation: "read-project-status", status: "available" },
      rawText: '{"operation":"read-project-status","status":"available"}',
      reasoningText: "private chain that must never be stored raw",
      warningCount: 0,
      usage: {
        inputTokens: 17,
        outputTokens: 9,
        totalTokens: 26,
        reasoningOutputTokens: 3,
      },
    });
  });

  it("normalizes trailing provider slashes with a linear scan", async () => {
    const base = exampleConfig();
    const config = parseDiagnosticCaptureConfig({
      ...base,
      provider: {
        ...base.provider,
        baseUrl: `${base.provider.baseUrl}////`,
      },
    });
    let requestedUrl = "";
    const runner = createOpenAICompatibleDiagnosticRunner(config, {}, (async (
      input: RequestInfo | URL,
      init?: RequestInit,
    ) => {
      requestedUrl = new Request(input, init).url;
      return providerResponse({
        content: '{"operation":"read-project-status"}',
        reasoning: "",
        finishReason: "stop",
      });
    }) as typeof fetch);

    await runner.run("Show project status");

    expect(requestedUrl).toBe(`${base.provider.baseUrl}/chat/completions`);
  });

  it("distinguishes a reasoning budget exhaustion from semantic failure", async () => {
    const runner = createOpenAICompatibleDiagnosticRunner(
      exampleConfig(),
      {},
      (async () =>
        providerResponse({
          content: "",
          reasoning: "reasoning consumed the entire output allowance",
          finishReason: "length",
        })) as typeof fetch,
    );

    const error = await runner
      .run("Show project status")
      .catch((value) => value);
    expect(error).toBeInstanceOf(DiagnosticProviderError);
    expect(error).toMatchObject({
      code: "OUTPUT_BUDGET_EXHAUSTED_WITH_REASONING",
    });
  });

  it.each([
    [
      "omitted details",
      { prompt_tokens: 17, completion_tokens: 9, total_tokens: 26 },
    ],
    [
      "null details",
      {
        prompt_tokens: 17,
        completion_tokens: 9,
        total_tokens: 26,
        completion_tokens_details: null,
      },
    ],
    [
      "empty details",
      {
        prompt_tokens: 17,
        completion_tokens: 9,
        total_tokens: 26,
        completion_tokens_details: {},
      },
    ],
    [
      "null reasoning counter",
      {
        prompt_tokens: 17,
        completion_tokens: 9,
        total_tokens: 26,
        completion_tokens_details: { reasoning_tokens: null },
      },
    ],
  ])("preserves %s as absent wire reasoning usage", async (_label, usage) => {
    const runner = createOpenAICompatibleDiagnosticRunner(
      exampleConfig(),
      {},
      (async () =>
        providerResponse({
          content: '{"operation":"read-project-status"}',
          reasoning: "",
          finishReason: "stop",
          usage,
        })) as typeof fetch,
    );

    const observation = await runner.run("Show project status");

    expect(observation.usage).toEqual({
      inputTokens: 17,
      outputTokens: 9,
      totalTokens: 26,
      reasoningOutputTokens: null,
    });
  });

  it("keeps raw usage isolated between concurrent runs", async () => {
    const runner = createOpenAICompatibleDiagnosticRunner(
      exampleConfig(),
      {},
      (async (input: RequestInfo | URL, init?: RequestInit) => {
        const request = new Request(input, init);
        const requestBody = await request.text();
        if (requestBody.includes("wire-usage-absent")) {
          await new Promise<void>((resolvePromise) =>
            setTimeout(resolvePromise, 10),
          );
          return providerResponse({
            content: '{"operation":"absent"}',
            reasoning: "",
            finishReason: "stop",
            usage: {
              prompt_tokens: 11,
              completion_tokens: 5,
              total_tokens: 16,
            },
          });
        }
        return providerResponse({
          content: '{"operation":"present"}',
          reasoning: "",
          finishReason: "stop",
          usage: {
            prompt_tokens: 23,
            completion_tokens: 7,
            total_tokens: 30,
            completion_tokens_details: { reasoning_tokens: 4 },
          },
        });
      }) as typeof fetch,
    );

    const [absent, present] = await Promise.all([
      runner.run("wire-usage-absent"),
      runner.run("wire-usage-present"),
    ]);

    expect(absent.usage).toEqual({
      inputTokens: 11,
      outputTokens: 5,
      totalTokens: 16,
      reasoningOutputTokens: null,
    });
    expect(present.usage).toEqual({
      inputTokens: 23,
      outputTokens: 7,
      totalTokens: 30,
      reasoningOutputTokens: 4,
    });
  });

  it.each([
    ["absent", { omitUsage: true }],
    ["empty", { usage: {} }],
    ["partial", { usage: { prompt_tokens: 17, completion_tokens: 9 } }],
    [
      "incoherent total",
      {
        usage: {
          prompt_tokens: 17,
          completion_tokens: 9,
          total_tokens: 27,
        },
      },
    ],
    [
      "negative counter",
      {
        usage: {
          prompt_tokens: -1,
          completion_tokens: 9,
          total_tokens: 8,
        },
      },
    ],
    [
      "non-integer counter",
      {
        usage: {
          prompt_tokens: 17.5,
          completion_tokens: 9,
          total_tokens: 26.5,
        },
      },
    ],
    [
      "incoherent reasoning",
      {
        usage: {
          prompt_tokens: 17,
          completion_tokens: 9,
          total_tokens: 26,
          completion_tokens_details: { reasoning_tokens: 10 },
        },
      },
    ],
    [
      "invalid reasoning details",
      {
        usage: {
          prompt_tokens: 17,
          completion_tokens: 9,
          total_tokens: 26,
          completion_tokens_details: [],
        },
      },
    ],
    [
      "invalid reasoning counter",
      {
        usage: {
          prompt_tokens: 17,
          completion_tokens: 9,
          total_tokens: 26,
          completion_tokens_details: { reasoning_tokens: "3" },
        },
      },
    ],
  ])("rejects %s raw provider usage", async (_label, responseOptions) => {
    const runner = createOpenAICompatibleDiagnosticRunner(
      exampleConfig(),
      {},
      (async () =>
        providerResponse({
          content: '{"operation":"read-project-status"}',
          reasoning: "",
          finishReason: "stop",
          ...responseOptions,
        })) as typeof fetch,
    );

    const error = await runner
      .run("Show project status")
      .catch((value) => value);
    expect(error).toBeInstanceOf(DiagnosticProviderError);
    expect(error).toMatchObject({ code: "USAGE_UNAVAILABLE" });
  });
});

function exampleConfig() {
  return parseDiagnosticCaptureConfig(
    JSON.parse(
      readFileSync(
        resolve(root, "config/diagnostic-capture.ollama.example.json"),
        "utf8",
      ),
    ),
  );
}

function providerResponse(input: {
  readonly content: string;
  readonly reasoning: string;
  readonly finishReason: "stop" | "length";
  readonly omitUsage?: boolean;
  readonly usage?: unknown;
}): Response {
  const defaultUsage = {
    prompt_tokens: 17,
    completion_tokens: 9,
    total_tokens: 26,
    completion_tokens_details: { reasoning_tokens: 3 },
  };
  return new Response(
    JSON.stringify({
      id: "chatcmpl-local-test",
      object: "chat.completion",
      created: 1_782_000_000,
      model: "qwen3:4b",
      choices: [
        {
          index: 0,
          message: {
            role: "assistant",
            content: input.content,
            reasoning: input.reasoning,
          },
          finish_reason: input.finishReason,
        },
      ],
      ...(input.omitUsage ? {} : { usage: input.usage ?? defaultUsage }),
    }),
    { status: 200, headers: { "content-type": "application/json" } },
  );
}
