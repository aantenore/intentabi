import { createOpenAICompatible } from "@ai-sdk/openai-compatible";
import { generateText, Output } from "ai";

import {
  normalizeProviderBaseUrl,
  parseStrictJsonValue,
  type DiagnosticCaptureConfig,
  type StrictJson,
} from "./config.js";

export interface DiagnosticProviderUsage {
  readonly inputTokens: number;
  readonly outputTokens: number;
  readonly totalTokens: number;
  readonly reasoningOutputTokens: number | null;
}

export interface DiagnosticProviderObservation {
  readonly output: StrictJson;
  readonly rawText: string;
  readonly reasoningText: string | null;
  readonly warningCount: number;
  readonly usage: DiagnosticProviderUsage;
}

export interface DiagnosticProviderRunner {
  run(source: string): Promise<DiagnosticProviderObservation>;
}

export type DiagnosticProviderFailureCode =
  | "TRANSPORT_FAILURE"
  | "OUTPUT_BUDGET_EXHAUSTED"
  | "OUTPUT_BUDGET_EXHAUSTED_WITH_REASONING"
  | "REASONING_ONLY_OUTPUT"
  | "OUTPUT_INVALID_JSON"
  | "UNEXPECTED_TOOL_OUTPUT"
  | "USAGE_UNAVAILABLE";

export class DiagnosticProviderError extends Error {
  constructor(readonly code: DiagnosticProviderFailureCode) {
    super(code);
    this.name = "DiagnosticProviderError";
  }
}

export function createOpenAICompatibleDiagnosticRunner(
  config: DiagnosticCaptureConfig,
  environment: Readonly<Record<string, string | undefined>>,
  fetchImplementation: typeof fetch = fetch,
): DiagnosticProviderRunner {
  try {
    const apiKey = readApiKey(config, environment);
    const baseUrl = normalizeProviderBaseUrl(config.provider.baseUrl);
    const endpoint = `${baseUrl}/chat/completions`;

    return Object.freeze({
      run: async (source: string): Promise<DiagnosticProviderObservation> => {
        let rawUsage: DiagnosticProviderUsage | null = null;
        try {
          const boundedFetch = createBoundedFetch({
            endpoint,
            timeoutMs: config.provider.requestTimeoutMs,
            maxRequestBytes: config.provider.maxRequestBytes,
            maxResponseBytes: config.provider.maxResponseBytes,
            fetchImplementation,
            captureUsage: (usage) => {
              if (rawUsage !== null) {
                throw new DiagnosticProviderError("USAGE_UNAVAILABLE");
              }
              rawUsage = usage;
            },
          });
          const provider = createOpenAICompatible({
            name: config.provider.name,
            baseURL: baseUrl,
            supportsStructuredOutputs: true,
            ...(apiKey === undefined ? {} : { apiKey }),
            fetch: boundedFetch,
          });
          const responseFormat = Output.json({
            name: "diagnostic_route_output",
            description:
              "Return only the JSON value produced by the observed application route.",
          });
          const result = await generateText({
            model: provider.chatModel(config.provider.model),
            instructions: config.provider.instructions,
            prompt: source,
            output: {
              name: responseFormat.name,
              responseFormat: responseFormat.responseFormat,
              parseCompleteOutput: async ({ text }) => text,
              parsePartialOutput: async () => undefined,
              createElementStreamTransform: () => undefined,
            },
            temperature: config.provider.temperature,
            maxOutputTokens: config.provider.maxOutputTokens,
            maxRetries: 0,
            telemetry: {
              isEnabled: false,
              recordInputs: false,
              recordOutputs: false,
            },
            ...(config.provider.reasoningEffort === undefined
              ? {}
              : {
                  providerOptions: {
                    openaiCompatible: {
                      reasoningEffort: config.provider.reasoningEffort,
                    },
                  },
                }),
          });
          const reasoningText = result.reasoningText?.trim();
          const reasoningPresent =
            reasoningText !== undefined && reasoningText.length > 0;
          if (result.finishReason === "length") {
            throw new DiagnosticProviderError(
              reasoningPresent
                ? "OUTPUT_BUDGET_EXHAUSTED_WITH_REASONING"
                : "OUTPUT_BUDGET_EXHAUSTED",
            );
          }
          if (
            result.finishReason !== "stop" ||
            result.toolCalls.length !== 0 ||
            result.files.length !== 0 ||
            result.sources.length !== 0
          ) {
            throw new DiagnosticProviderError("UNEXPECTED_TOOL_OUTPUT");
          }
          if (result.text.trim().length === 0) {
            throw new DiagnosticProviderError(
              reasoningPresent
                ? "REASONING_ONLY_OUTPUT"
                : "OUTPUT_INVALID_JSON",
            );
          }
          let output: StrictJson;
          try {
            output = parseStrictJsonValue(JSON.parse(result.text));
          } catch {
            throw new DiagnosticProviderError("OUTPUT_INVALID_JSON");
          }
          const usage = projectUsage(result.usage, rawUsage);
          return Object.freeze({
            output,
            rawText: result.text,
            reasoningText: reasoningPresent ? reasoningText : null,
            warningCount: result.warnings?.length ?? 0,
            usage,
          });
        } catch (error) {
          const providerError = findDiagnosticProviderError(error);
          if (providerError !== null) throw providerError;
          throw new DiagnosticProviderError("TRANSPORT_FAILURE");
        }
      },
    });
  } catch (error) {
    if (error instanceof DiagnosticProviderError) throw error;
    throw new DiagnosticProviderError("TRANSPORT_FAILURE");
  }
}

function readApiKey(
  config: DiagnosticCaptureConfig,
  environment: Readonly<Record<string, string | undefined>>,
): string | undefined {
  if (config.provider.authentication.kind === "none") return undefined;
  const value = environment[config.provider.authentication.apiKeyEnv];
  if (value === undefined || Buffer.byteLength(value, "utf8") < 1) {
    throw new DiagnosticProviderError("TRANSPORT_FAILURE");
  }
  return value;
}

function projectUsage(
  value: {
    readonly inputTokens: number | undefined;
    readonly outputTokens: number | undefined;
    readonly totalTokens: number | undefined;
  },
  rawUsage: DiagnosticProviderUsage | null,
): DiagnosticProviderUsage {
  const counters = [value.inputTokens, value.outputTokens, value.totalTokens];
  if (
    !counters.every(
      (entry) =>
        typeof entry === "number" && Number.isSafeInteger(entry) && entry >= 0,
    ) ||
    value.totalTokens! !== value.inputTokens! + value.outputTokens! ||
    rawUsage === null ||
    rawUsage.inputTokens !== value.inputTokens ||
    rawUsage.outputTokens !== value.outputTokens ||
    rawUsage.totalTokens !== value.totalTokens
  ) {
    throw new DiagnosticProviderError("USAGE_UNAVAILABLE");
  }
  // The SDK may normalize an absent reasoning counter to zero. Preserve the
  // provider's wire-level presence semantics instead of that synthetic value.
  return rawUsage;
}

function createBoundedFetch(options: {
  readonly endpoint: string;
  readonly timeoutMs: number;
  readonly maxRequestBytes: number;
  readonly maxResponseBytes: number;
  readonly fetchImplementation: typeof fetch;
  readonly captureUsage: (usage: DiagnosticProviderUsage) => void;
}): typeof fetch {
  const endpoint = new URL(options.endpoint);
  return async (input, init) => {
    let request: Request;
    try {
      request = new Request(input, init);
    } catch {
      throw new DiagnosticProviderError("TRANSPORT_FAILURE");
    }
    if (request.method !== "POST" || request.url !== endpoint.href) {
      throw new DiagnosticProviderError("TRANSPORT_FAILURE");
    }
    const requestBytes = request.body
      ? Buffer.byteLength(await request.clone().text(), "utf8")
      : 0;
    if (requestBytes === 0 || requestBytes > options.maxRequestBytes) {
      throw new DiagnosticProviderError("TRANSPORT_FAILURE");
    }

    const timeout = AbortSignal.timeout(options.timeoutMs);
    const signal = request.signal.aborted
      ? request.signal
      : AbortSignal.any([request.signal, timeout]);
    let response: Response;
    try {
      response = await options.fetchImplementation(request, {
        redirect: "error",
        signal,
      });
    } catch {
      throw new DiagnosticProviderError("TRANSPORT_FAILURE");
    }
    const declaredLength = response.headers.get("content-length");
    if (
      declaredLength !== null &&
      (!/^\d+$/u.test(declaredLength) ||
        Number(declaredLength) > options.maxResponseBytes)
    ) {
      await response.body?.cancel().catch(() => undefined);
      throw new DiagnosticProviderError("TRANSPORT_FAILURE");
    }
    const body = await readBoundedBody(
      response,
      options.maxResponseBytes,
      signal,
    );
    if (response.ok) {
      options.captureUsage(validateOpenAICompatibleUsage(body));
    }
    return new Response(body, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    });
  };
}

async function readBoundedBody(
  response: Response,
  maximumBytes: number,
  signal: AbortSignal,
): Promise<Uint8Array> {
  if (response.body === null) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      if (signal.aborted) {
        throw new DiagnosticProviderError("TRANSPORT_FAILURE");
      }
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maximumBytes) {
        throw new DiagnosticProviderError("TRANSPORT_FAILURE");
      }
      chunks.push(value);
    }
  } catch {
    await reader.cancel().catch(() => undefined);
    throw new DiagnosticProviderError("TRANSPORT_FAILURE");
  } finally {
    reader.releaseLock();
  }
  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}

function validateOpenAICompatibleUsage(
  body: Uint8Array,
): DiagnosticProviderUsage {
  let payload: unknown;
  try {
    payload = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(body),
    );
  } catch {
    throw new DiagnosticProviderError("TRANSPORT_FAILURE");
  }
  if (!isRecord(payload) || !isRecord(payload.usage)) {
    throw new DiagnosticProviderError("USAGE_UNAVAILABLE");
  }

  const promptTokens = readWireTokenCount(payload.usage.prompt_tokens);
  const completionTokens = readWireTokenCount(payload.usage.completion_tokens);
  const totalTokens = readWireTokenCount(payload.usage.total_tokens);
  const expectedTotal = promptTokens + completionTokens;
  if (!Number.isSafeInteger(expectedTotal) || totalTokens !== expectedTotal) {
    throw new DiagnosticProviderError("USAGE_UNAVAILABLE");
  }

  let reasoningOutputTokens: number | null = null;
  const details = payload.usage.completion_tokens_details;
  if (details !== undefined && details !== null) {
    if (!isRecord(details)) {
      throw new DiagnosticProviderError("USAGE_UNAVAILABLE");
    }
    if (Object.hasOwn(details, "reasoning_tokens")) {
      const rawReasoningTokens = details.reasoning_tokens;
      if (rawReasoningTokens !== null) {
        const reasoningTokens = readWireTokenCount(rawReasoningTokens);
        if (reasoningTokens > completionTokens) {
          throw new DiagnosticProviderError("USAGE_UNAVAILABLE");
        }
        reasoningOutputTokens = reasoningTokens;
      }
    }
  }
  return Object.freeze({
    inputTokens: promptTokens,
    outputTokens: completionTokens,
    totalTokens,
    reasoningOutputTokens,
  });
}

function readWireTokenCount(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new DiagnosticProviderError("USAGE_UNAVAILABLE");
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function findDiagnosticProviderError(
  value: unknown,
): DiagnosticProviderError | null {
  let current = value;
  const seen = new Set<unknown>();
  for (let depth = 0; depth < 8; depth += 1) {
    if (current instanceof DiagnosticProviderError) return current;
    if (!isRecord(current) || seen.has(current)) return null;
    seen.add(current);
    current = current.cause;
  }
  return null;
}
