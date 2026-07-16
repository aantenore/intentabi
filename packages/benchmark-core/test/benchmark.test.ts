import { describe, expect, it, vi } from "vitest";

import {
  BenchmarkInvariantFailure,
  createCounterbalancedPlan,
  runPairedBenchmark,
  type BenchmarkArmRunner,
  type BenchmarkCase,
} from "../src/index.js";

const hmac = (character: string) =>
  `hmac-sha256:evidence:${character.repeat(64)}` as const;
const digest = (character: string) => `sha256:${character.repeat(64)}` as const;
const keyId = "benchmark-evidence-v1";
const authenticateReceipt = () => hmac("9");

const cases: readonly BenchmarkCase[] = [
  {
    caseRef: hmac("a"),
    stratum: "simple",
    cacheRegime: "cold",
    original: "PRIVATE ORIGINAL A",
    candidate: "PRIVATE CANDIDATE A",
  },
  {
    caseRef: hmac("b"),
    stratum: "simple",
    cacheRegime: "cold",
    original: "PRIVATE ORIGINAL B",
    candidate: "PRIVATE CANDIDATE B",
  },
];

describe("paired benchmark", () => {
  it("creates a deterministic balanced AB/BA plan without content", () => {
    const first = createCounterbalancedPlan({
      cases,
      seed: "stable-seed",
      keyId,
      datasetDigest: hmac("c"),
      protocolDigest: digest("d"),
    });
    const second = createCounterbalancedPlan({
      cases,
      seed: "stable-seed",
      keyId,
      datasetDigest: hmac("c"),
      protocolDigest: digest("d"),
    });

    expect(second).toEqual(first);
    expect(new Set(first.cases.map((entry) => entry.order.join("/")))).toEqual(
      new Set(["baseline/candidate", "candidate/baseline"]),
    );
    expect(JSON.stringify(first)).not.toContain("PRIVATE");
    expect(first).toMatchObject({
      classification: "research-conformance",
      promotionEligible: false,
      keyId,
    });
  });

  it("counterbalances independently inside every stratum/cache block", () => {
    const blockedCases: readonly BenchmarkCase[] = [
      ...cases,
      {
        ...cases[0]!,
        caseRef: hmac("f"),
        cacheRegime: "warm",
      },
      {
        ...cases[1]!,
        caseRef: hmac("1"),
        cacheRegime: "warm",
      },
    ];
    const plan = createCounterbalancedPlan({
      cases: blockedCases,
      seed: "stable-seed",
      keyId,
      datasetDigest: hmac("c"),
      protocolDigest: digest("d"),
    });

    for (const cacheRegime of ["cold", "warm"] as const) {
      expect(
        new Set(
          plan.cases
            .filter((entry) => entry.cacheRegime === cacheRegime)
            .map((entry) => entry.order.join("/")),
        ),
      ).toEqual(new Set(["baseline/candidate", "candidate/baseline"]));
    }
  });

  it("runs each arm and emits only content-free diagnostic accounting", async () => {
    const submitted: string[] = [];
    const runner: BenchmarkArmRunner = {
      run: vi.fn(async (content) => {
        submitted.push(content);
        return {
          usage: {
            provenance: "host-observed-codex-sdk-run-result",
            inputTokens: content.includes("CANDIDATE") ? 60 : 100,
            cachedInputTokens: 10,
            outputTokens: 20,
            reasoningOutputTokens: 5,
          },
          latencyMicros: 1_000,
        };
      }),
    };
    const plan = createCounterbalancedPlan({
      cases,
      seed: "stable-seed",
      keyId,
      datasetDigest: hmac("c"),
      protocolDigest: digest("d"),
    });

    const receipt = await runPairedBenchmark({
      plan,
      cases,
      runner,
      runId: "00000000-0000-4000-8000-000000000001",
      executionMode: "injected-test-boundary",
      keyId,
      executableDigest: digest("e"),
      sdkVersion: "0.144.4",
      cliVersion: "0.144.4",
      authenticateReceipt,
    });

    expect(submitted).toHaveLength(4);
    expect(receipt.summary).toMatchObject({
      completePairs: 2,
      baselineInputTokens: "200",
      candidateInputTokens: "120",
      observedInputTokenDelta: "80",
    });
    expect(receipt).toMatchObject({
      classification: "research-conformance",
      promotionEligible: false,
      promotionManifest: "not-produced",
      executionMode: "injected-test-boundary",
      keyId,
      receiptMac: hmac("9"),
    });
    const serialized = JSON.stringify(receipt);
    expect(serialized).not.toContain("PRIVATE ORIGINAL");
    expect(serialized).not.toContain("PRIVATE CANDIDATE");
  });

  it("marks missing or invalid usage as accounting incomplete", async () => {
    const runner: BenchmarkArmRunner = {
      run: vi
        .fn()
        .mockResolvedValueOnce({ usage: null, latencyMicros: 5 })
        .mockResolvedValue({
          usage: {
            provenance: "host-observed-codex-sdk-run-result",
            inputTokens: 10,
            cachedInputTokens: 11,
            outputTokens: 2,
            reasoningOutputTokens: 0,
          },
          latencyMicros: 5,
        }),
    };
    const oneCase = cases.slice(0, 1);
    const plan = createCounterbalancedPlan({
      cases: oneCase,
      seed: "stable-seed",
      keyId,
      datasetDigest: hmac("c"),
      protocolDigest: digest("d"),
    });

    const receipt = await runPairedBenchmark({
      plan,
      cases: oneCase,
      runner,
      runId: "00000000-0000-4000-8000-000000000001",
      executionMode: "injected-test-boundary",
      keyId,
      executableDigest: digest("e"),
      sdkVersion: "0.144.4",
      cliVersion: "0.144.4",
      authenticateReceipt,
    });

    expect(receipt.summary.accountingIncompletePairs).toBe(1);
    expect(receipt.summary.completePairs).toBe(0);
  });

  it("projects runner usage to an exact content-free record", async () => {
    let getterCalls = 0;
    const hostileUsage = Object.create({
      inheritedSecret: "PRIVATE INHERITED",
    }) as Record<string, unknown>;
    Object.defineProperties(hostileUsage, {
      provenance: {
        value: "host-observed-codex-sdk-run-result",
        enumerable: true,
      },
      inputTokens: { value: 10, enumerable: true },
      cachedInputTokens: { value: 2, enumerable: true },
      outputTokens: { value: 3, enumerable: true },
      reasoningOutputTokens: { value: 1, enumerable: true },
      secret: {
        enumerable: true,
        get: () => {
          getterCalls += 1;
          return "PRIVATE EXTRA";
        },
      },
      toJSON: {
        enumerable: true,
        value: () => {
          throw new Error("source usage must not be serialized");
        },
      },
    });
    const oneCase = cases.slice(0, 1);
    const plan = createCounterbalancedPlan({
      cases: oneCase,
      seed: "stable-seed",
      keyId,
      datasetDigest: hmac("c"),
      protocolDigest: digest("d"),
    });

    const receipt = await runPairedBenchmark({
      plan,
      cases: oneCase,
      runner: {
        run: vi.fn(async () => ({
          usage: hostileUsage as never,
          latencyMicros: 1,
        })),
      },
      runId: "00000000-0000-4000-8000-000000000001",
      executionMode: "injected-test-boundary",
      keyId,
      executableDigest: digest("e"),
      sdkVersion: "0.144.4",
      cliVersion: "0.144.4",
      authenticateReceipt,
    });

    expect(getterCalls).toBe(0);
    expect(receipt.summary.completePairs).toBe(1);
    const usage =
      receipt.cases[0]?.baseline.status === "complete"
        ? receipt.cases[0].baseline.usage
        : null;
    expect(Object.keys(usage ?? {})).toEqual([
      "provenance",
      "inputTokens",
      "cachedInputTokens",
      "outputTokens",
      "reasoningOutputTokens",
    ]);
    const serialized = JSON.stringify(receipt);
    expect(serialized).not.toContain("PRIVATE EXTRA");
    expect(serialized).not.toContain("PRIVATE INHERITED");

    const getterUsage = {
      provenance: "host-observed-codex-sdk-run-result",
      get inputTokens() {
        getterCalls += 1;
        return 10;
      },
      cachedInputTokens: 2,
      outputTokens: 3,
      reasoningOutputTokens: 1,
    };
    const invalidReceipt = await runPairedBenchmark({
      plan,
      cases: oneCase,
      runner: {
        run: vi.fn(async () => ({
          usage: getterUsage as never,
          latencyMicros: 1,
        })),
      },
      runId: "00000000-0000-4000-8000-000000000002",
      executionMode: "injected-test-boundary",
      keyId,
      executableDigest: digest("e"),
      sdkVersion: "0.144.4",
      cliVersion: "0.144.4",
      authenticateReceipt,
    });
    expect(getterCalls).toBe(0);
    expect(invalidReceipt.summary.accountingIncompletePairs).toBe(1);
  });

  it("reprojects a hostile order tuple without invoking its serializer", async () => {
    const oneCase = cases.slice(0, 1);
    const cleanPlan = createCounterbalancedPlan({
      cases: oneCase,
      seed: "stable-seed",
      keyId,
      datasetDigest: hmac("c"),
      protocolDigest: digest("d"),
    });
    let serializerCalls = 0;
    const hostileOrder = [...cleanPlan.cases[0]!.order] as [
      "baseline" | "candidate",
      "baseline" | "candidate",
    ] & { toJSON?: () => unknown };
    hostileOrder.toJSON = () => {
      serializerCalls += 1;
      return { private: "PRIVATE ORDER PAYLOAD" };
    };
    const plan = {
      ...cleanPlan,
      cases: [{ ...cleanPlan.cases[0]!, order: hostileOrder }],
    };

    const receipt = await runPairedBenchmark({
      plan,
      cases: oneCase,
      runner: {
        run: vi.fn(async () => ({
          usage: {
            provenance: "host-observed-codex-sdk-run-result" as const,
            inputTokens: 10,
            cachedInputTokens: 0,
            outputTokens: 1,
            reasoningOutputTokens: 0,
          },
          latencyMicros: 1,
        })),
      },
      runId: "00000000-0000-4000-8000-000000000003",
      executionMode: "injected-test-boundary",
      keyId,
      executableDigest: digest("e"),
      sdkVersion: "0.144.4",
      cliVersion: "0.144.4",
      authenticateReceipt,
    });

    expect(JSON.stringify(receipt)).not.toContain("PRIVATE ORDER PAYLOAD");
    expect(serializerCalls).toBe(0);
    expect(Object.hasOwn(receipt.cases[0]!.order, "toJSON")).toBe(false);
  });

  it("rejects duplicate case references and a tampered external plan", async () => {
    expect(() =>
      createCounterbalancedPlan({
        cases: [cases[0]!, cases[0]!],
        seed: "stable-seed",
        keyId,
        datasetDigest: hmac("c"),
        protocolDigest: digest("d"),
      }),
    ).toThrow(/case set/u);

    const plan = createCounterbalancedPlan({
      cases,
      seed: "stable-seed",
      keyId,
      datasetDigest: hmac("c"),
      protocolDigest: digest("d"),
    });
    const tampered = {
      ...plan,
      cases: plan.cases.map((entry, index) =>
        index === 0 ? { ...entry, stratum: "adversarial" as const } : entry,
      ),
    };
    const run = vi.fn();
    await expect(
      runPairedBenchmark({
        plan: tampered,
        cases,
        runner: { run },
        runId: "00000000-0000-4000-8000-000000000001",
        executionMode: "injected-test-boundary",
        keyId,
        executableDigest: digest("e"),
        sdkVersion: "0.144.4",
        cliVersion: "0.144.4",
        authenticateReceipt,
      }),
    ).rejects.toThrow(/plan structure/u);
    expect(run).not.toHaveBeenCalled();
  });

  it("validates and preserves the public evidence key lineage", async () => {
    expect(() =>
      createCounterbalancedPlan({
        cases,
        seed: "stable-seed",
        keyId: "-invalid-key-id",
        datasetDigest: hmac("c"),
        protocolDigest: digest("d"),
      }),
    ).toThrow(/plan inputs/u);

    const plan = createCounterbalancedPlan({
      cases,
      seed: "stable-seed",
      keyId,
      datasetDigest: hmac("c"),
      protocolDigest: digest("d"),
    });
    const run = vi.fn();
    await expect(
      runPairedBenchmark({
        plan,
        cases,
        runner: { run },
        runId: "00000000-0000-4000-8000-000000000004",
        executionMode: "injected-test-boundary",
        keyId: "different-key-v2",
        executableDigest: digest("e"),
        sdkVersion: "0.144.4",
        cliVersion: "0.144.4",
        authenticateReceipt,
      }),
    ).rejects.toThrow(/execution binding/u);
    expect(run).not.toHaveBeenCalled();
  });

  it("aborts instead of downgrading a host integrity failure", async () => {
    const oneCase = cases.slice(0, 1);
    const plan = createCounterbalancedPlan({
      cases: oneCase,
      seed: "stable-seed",
      keyId,
      datasetDigest: hmac("c"),
      protocolDigest: digest("d"),
    });

    await expect(
      runPairedBenchmark({
        plan,
        cases: oneCase,
        runner: {
          run: vi.fn(async () => {
            throw new BenchmarkInvariantFailure("binary changed");
          }),
        },
        runId: "00000000-0000-4000-8000-000000000001",
        executionMode: "injected-test-boundary",
        keyId,
        executableDigest: digest("e"),
        sdkVersion: "0.144.4",
        cliVersion: "0.144.4",
        authenticateReceipt,
      }),
    ).rejects.toThrow(/binary changed/u);
  });

  it("fails closed when receipt authentication cannot produce a valid MAC", async () => {
    const oneCase = cases.slice(0, 1);
    const plan = createCounterbalancedPlan({
      cases: oneCase,
      seed: "stable-seed",
      keyId,
      datasetDigest: hmac("c"),
      protocolDigest: digest("d"),
    });
    const base = {
      plan,
      cases: oneCase,
      runner: {
        run: vi.fn(async () => ({ usage: null, latencyMicros: 1 })),
      },
      runId: "00000000-0000-4000-8000-000000000001",
      executionMode: "injected-test-boundary" as const,
      keyId,
      executableDigest: digest("e"),
      sdkVersion: "0.144.4",
      cliVersion: "0.144.4",
    };

    await expect(
      runPairedBenchmark({
        ...base,
        authenticateReceipt: () => {
          throw new Error("key unavailable");
        },
      }),
    ).rejects.toThrow(/receipt authentication failed/u);
    await expect(
      runPairedBenchmark({
        ...base,
        authenticateReceipt: () => "invalid" as never,
      }),
    ).rejects.toThrow(/invalid MAC/u);
  });
});
