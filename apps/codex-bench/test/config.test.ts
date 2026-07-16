import { describe, expect, it } from "vitest";

import {
  assertCodexBenchDatasetBudget,
  createBenchmarkPlan,
  parseCodexBenchConfig,
  parseCodexBenchDataset,
  resolveCodexBenchConfig,
} from "../src/index.js";

const config = {
  schema: "io.github.aantenore.intentabi/codex-bench-config/v1alpha1",
  classification: "research-conformance",
  codex: {
    codexPathOverride: "vendor/codex",
    expectedCliVersion: "0.144.4",
    expectedExecutableDigest: `sha256:${"a".repeat(64)}`,
    authentication: { apiKeyEnv: "INTENTABI_CODEX_API_KEY" },
    thread: {
      model: "gpt-codex-test",
      sandboxMode: "read-only",
      skipGitRepoCheck: false,
      modelReasoningEffort: "medium",
      networkAccessEnabled: false,
      webSearchMode: "disabled",
      webSearchEnabled: false,
      approvalPolicy: "never",
    },
    turnTimeoutMs: 10_000,
  },
  benchmark: {
    seed: "test-v1",
    maxCases: 8,
    maxProviderCalls: 16,
    maxInputBytes: 1_024,
    maxDatasetBytes: 4_096,
    maxOutputTokensPerCall: 256,
    maxTotalOutputTokens: 512,
    maxRunDurationMs: 20_000,
    maxGatewayResponseBytes: 1_048_576,
  },
  evidence: {
    hmacSecretEnv: "INTENTABI_BENCH_HMAC_SECRET",
    keyId: "test-v1",
  },
} as const;

const dataset = {
  schema: "io.github.aantenore.intentabi/codex-bench-dataset/v1alpha1",
  classification: "research-conformance",
  id: "test-v1",
  split: "conformance",
  cases: [
    {
      id: "case-1",
      stratum: "simple",
      cacheRegime: "cold",
      original: "PRIVATE ORIGINAL",
      candidate: "PRIVATE CANDIDATE",
    },
  ],
} as const;

describe("Codex benchmark config", () => {
  it("accepts only the pinned, read-only research composition", () => {
    const parsedConfig = parseCodexBenchConfig(config);
    const parsedDataset = parseCodexBenchDataset(dataset);
    expect(parsedConfig).toEqual(config);
    expect(parsedDataset).toEqual(dataset);
    expect(() =>
      assertCodexBenchDatasetBudget(parsedConfig, parsedDataset),
    ).not.toThrow();
  });

  it("rejects unknown config, unsafe execution, held-out claims, and duplicates", () => {
    expect(() => parseCodexBenchConfig({ ...config, active: true })).toThrow();
    expect(() =>
      parseCodexBenchConfig({
        ...config,
        codex: {
          ...config.codex,
          expectedExecutableDigest: `sha256:${"0".repeat(63)}`,
        },
      }),
    ).toThrow();
    expect(() =>
      parseCodexBenchConfig({
        ...config,
        codex: {
          ...config.codex,
          authentication: {
            apiKeyEnv: config.evidence.hmacSecretEnv,
          },
        },
      }),
    ).toThrow(/distinct/u);
    expect(() =>
      parseCodexBenchConfig({
        ...config,
        evidence: { ...config.evidence, hmacSecretEnv: "SYSTEMROOT" },
      }),
    ).toThrow(/platform variable/u);
    expect(() =>
      parseCodexBenchConfig({
        ...config,
        benchmark: { ...config.benchmark, maxTotalOutputTokens: 200 },
      }),
    ).toThrow(/feasible/u);
    expect(() =>
      parseCodexBenchConfig({
        ...config,
        codex: {
          ...config.codex,
          thread: { ...config.codex.thread, model: "gpt-codex-test\nimage" },
        },
      }),
    ).toThrow();
    expect(() =>
      parseCodexBenchConfig({
        ...config,
        codex: {
          ...config.codex,
          thread: { ...config.codex.thread, workingDirectory: "/host/repo" },
        },
      }),
    ).toThrow();
    expect(() =>
      parseCodexBenchConfig({
        ...config,
        codex: {
          ...config.codex,
          thread: { ...config.codex.thread, sandboxMode: "workspace-write" },
        },
      }),
    ).toThrow();
    expect(() =>
      parseCodexBenchDataset({ ...dataset, split: "held-out" }),
    ).toThrow();
    expect(() =>
      parseCodexBenchDataset({
        ...dataset,
        cases: [dataset.cases[0], dataset.cases[0]],
      }),
    ).toThrow();
    expect(() =>
      parseCodexBenchDataset({
        ...dataset,
        cases: [
          {
            ...dataset.cases[0],
            original: "PRIVATE\uD800ORIGINAL",
          },
        ],
      }),
    ).toThrow(/Unicode scalar/u);
    expect(() =>
      assertCodexBenchDatasetBudget(
        parseCodexBenchConfig({
          ...config,
          benchmark: {
            ...config.benchmark,
            maxProviderCalls: 2,
            maxInputBytes: 8,
            maxDatasetBytes: 16,
          },
        }),
        parseCodexBenchDataset(dataset),
      ),
    ).toThrow(/byte budget/u);
  });

  it("changes every content binding when the public evidence key lineage rotates", () => {
    const parsedDataset = parseCodexBenchDataset(dataset);
    const materialize = (keyId: string) =>
      createBenchmarkPlan({
        config: resolveCodexBenchConfig(
          parseCodexBenchConfig({
            ...config,
            evidence: { ...config.evidence, keyId },
          }),
          "/configured",
        ),
        dataset: parsedDataset,
        secret: "x".repeat(32),
      });

    const first = materialize("test-v1");
    const rotated = materialize("test-v2");
    expect(first.plan.keyId).toBe("test-v1");
    expect(rotated.plan.keyId).toBe("test-v2");
    expect(rotated.plan.datasetDigest).not.toBe(first.plan.datasetDigest);
    expect(rotated.plan.protocolDigest).not.toBe(first.plan.protocolDigest);
    expect(rotated.cases[0]?.caseRef).not.toBe(first.cases[0]?.caseRef);
  });
});
