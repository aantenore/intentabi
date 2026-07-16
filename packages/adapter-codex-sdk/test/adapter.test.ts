import type {
  Input,
  RunResult,
  ThreadOptions,
  TurnOptions,
} from "@openai/codex-sdk";
import { describe, expect, it, vi } from "vitest";

import {
  createCodexSdkTurnTransport,
  normalizeCodexUsage,
  VERIFIED_CODEX_SDK_VERSION,
} from "../src/index.js";

const digest = (character: string) => `sha256:${character.repeat(64)}` as const;
const contracts = {
  runtimeRevisionDigest: digest("1"),
  promptContractDigest: digest("2"),
  toolContractDigest: digest("3"),
  agentsDigest: digest("4"),
};

describe("CodexSdkTurnTransport", () => {
  it("creates the thread and binding from the same frozen options snapshot", () => {
    const requested: ThreadOptions = {
      model: "gpt-codex-test",
      sandboxMode: "read-only",
      workingDirectory: "/private/workspace",
      skipGitRepoCheck: false,
      modelReasoningEffort: "high",
      networkAccessEnabled: false,
      webSearchMode: "disabled",
      webSearchEnabled: false,
      approvalPolicy: "never",
      additionalDirectories: ["/private/shared"],
    };
    let received: ThreadOptions | undefined;
    const client = {
      startThread: vi.fn((options?: ThreadOptions) => {
        received = options;
        return { run: vi.fn(async () => turn("done")) };
      }),
    };

    const transport = createCodexSdkTurnTransport(client, requested, contracts);
    requested.model = "mutated-model";
    requested.additionalDirectories?.push("/private/mutated");

    expect(received).toEqual({
      model: "gpt-codex-test",
      sandboxMode: "read-only",
      workingDirectory: "/private/workspace",
      skipGitRepoCheck: false,
      modelReasoningEffort: "high",
      networkAccessEnabled: false,
      webSearchMode: "disabled",
      webSearchEnabled: false,
      approvalPolicy: "never",
      additionalDirectories: ["/private/shared"],
    });
    expect(Object.isFrozen(received)).toBe(true);
    expect(Object.isFrozen(received?.additionalDirectories)).toBe(true);
    expect(Object.isFrozen(transport)).toBe(true);
    expect(transport.executionBinding).toMatchObject({
      provenance: "adapter-thread-factory",
      sdkVersion: VERIFIED_CODEX_SDK_VERSION,
      externalClientConfiguration: "unavailable:external-client",
      thread: {
        model: "gpt-codex-test",
        workingDirectory: "/private/workspace",
        additionalDirectories: 1,
      },
      contracts: { provenance: "host-declared-unverified" },
    });
    expect(transport.executionBinding.threadOptionsDigest).toMatch(
      /^sha256:[a-f0-9]{64}$/u,
    );
  });

  it("preserves exact input, turn options identity, and official output", async () => {
    const options: TurnOptions = { outputSchema: { type: "object" } };
    const output = turn("done");
    const run = vi.fn(async () => output);
    const transport = createCodexSdkTurnTransport(
      { startThread: vi.fn(() => ({ run })) },
      {},
      contracts,
    );
    const input: Input = "exact prompt";

    const result = await transport.runExact(input, options);

    expect(run).toHaveBeenCalledOnce();
    expect(run).toHaveBeenCalledWith(input, options);
    expect(result).toBe(output);
  });

  it("does not synthesize an undefined turn options argument", async () => {
    const run = vi.fn(async () => turn("done"));
    const transport = createCodexSdkTurnTransport(
      { startThread: vi.fn(() => ({ run })) },
      {},
      contracts,
    );

    await transport.runExact("exact prompt");

    expect(run).toHaveBeenCalledWith("exact prompt");
  });

  it("rejects accessor thread configuration before creating a thread", () => {
    let getterCalls = 0;
    const requested = Object.defineProperty({}, "model", {
      enumerable: true,
      get() {
        getterCalls += 1;
        return "gpt-codex-test";
      },
    }) as ThreadOptions;
    const startThread = vi.fn(() => ({ run: vi.fn(async () => turn("done")) }));

    expect(() =>
      createCodexSdkTurnTransport({ startThread }, requested, contracts),
    ).toThrow(/data fields/u);
    expect(getterCalls).toBe(0);
    expect(startThread).not.toHaveBeenCalled();
  });
});

describe("normalizeCodexUsage", () => {
  it("maps provider counters without inventing totals or savings", () => {
    expect(
      normalizeCodexUsage({
        input_tokens: 100,
        cached_input_tokens: 60,
        output_tokens: 40,
        reasoning_output_tokens: 10,
      }),
    ).toEqual({
      provenance: "caller-supplied-sdk-shaped",
      input: { total: 100, cached: 60 },
      output: { total: 40, reasoning: 10 },
    });
    expect(normalizeCodexUsage(null)).toBeNull();
  });

  it("fails closed on invalid provider counters", () => {
    expect(() =>
      normalizeCodexUsage({
        input_tokens: -1,
        cached_input_tokens: 0,
        output_tokens: 0,
        reasoning_output_tokens: 0,
      }),
    ).toThrow(/usage counters/u);
  });
});

function turn(finalResponse: string): RunResult {
  return { items: [], finalResponse, usage: null };
}
