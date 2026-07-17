import { describe, expect, it, vi } from "vitest";

import type { IntentInspector } from "@intentabi/core";

import { runCacheImpactStudy, type CacheImpactCase } from "../src/index.js";

const hmac = (character: string) =>
  `hmac-sha256:evidence:${character.repeat(64)}` as const;
const shadowHmac = (domain: string, character: string) =>
  `hmac-sha256:${domain}:${character.repeat(64)}` as const;
const digest = (character: string) => `sha256:${character.repeat(64)}` as const;
const route = { id: "fixture", revisionDigest: digest("1") };
const scope = { tenant: "demo", authorization: "reader" };

function cacheCase(
  ordinal: number,
  source: string,
  expectedValueDigest = digest("a"),
): CacheImpactCase {
  return {
    caseRef: hmac(String((ordinal % 9) + 1)),
    rawKey: hmac(String.fromCharCode(97 + ordinal)),
    expectedValueDigest,
    request: {
      source,
      locale: "en-US",
      scope,
      scopeEpoch: "test-v1",
      route,
      routeInput: { command: "status" },
    },
    usage: {
      modelInputTokens: 100,
      modelOutputTokens: 20,
      normalizationInputTokens: 3,
      normalizationOutputTokens: 1,
    },
  };
}

function eligibleInspector(intentCharacter = "a"): IntentInspector {
  return {
    inspect: vi.fn(async (request) => ({
      status: "eligible" as const,
      sourceDigest: shadowHmac("intent-source", "1"),
      scopeDigest: shadowHmac("shadow-scope", "2"),
      bindingDigest: shadowHmac("shadow-binding", "3"),
      routeInputDigest: shadowHmac("route-input", "4"),
      intentKey: shadowHmac("shadow-intent", intentCharacter),
      witnessKey: shadowHmac("shadow-witness", "5"),
      effect: "read" as const,
      reasons: Object.freeze(["INTENT_NORMALIZED"]),
      signalObserved: request.signal?.aborted,
    })) as never,
  };
}

function run(
  cases: readonly CacheImpactCase[],
  inspector: IntentInspector = eligibleInspector(),
) {
  return runCacheImpactStudy({
    cases,
    inspector,
    keyId: "cache-impact-v1",
    datasetDigest: hmac("d"),
    inspectionTimeoutMs: 50,
    authenticateReport: () => hmac("f"),
  });
}

describe("cache impact study", () => {
  it("measures safe hit lift and net tokens for normalized paraphrases", async () => {
    const workload = [
      cacheCase(0, "first phrasing"),
      cacheCase(1, "equivalent phrasing"),
      { ...cacheCase(2, "first phrasing"), rawKey: hmac("a") },
    ];
    const report = await run(workload);
    const replay = await run(workload);

    expect(report.summary.raw).toMatchObject({
      safeHits: 1,
      unsafeHits: 0,
      misses: 2,
    });
    expect(report.summary.normalized).toMatchObject({
      safeHits: 2,
      unsafeHits: 0,
      misses: 1,
    });
    expect(report.summary.safeHitLift).toBe(1);
    expect(report.summary.tokens).toMatchObject({
      rawModelInput: "200",
      normalizedModelInput: "100",
      normalizationInput: "9",
      netInputDeltaVersusRaw: "91",
      netOutputDeltaVersusRaw: "17",
      netTotalDeltaVersusRaw: "108",
    });
    expect(report.summary.gate).toEqual({ passed: true, reasons: [] });
    expect(replay).toEqual(report);
    expect(report).toMatchObject({
      mode: "shadow",
      activationAuthorized: false,
      promotionManifest: "not-produced",
      reportMac: hmac("f"),
    });
    const serialized = JSON.stringify(report);
    expect(serialized).not.toContain("first phrasing");
    expect(serialized).not.toContain("equivalent phrasing");
    expect(serialized).not.toContain(digest("a"));
  });

  it("detects an unsafe semantic collision and excludes it from savings", async () => {
    const report = await run([
      cacheCase(0, "read status", digest("a")),
      cacheCase(1, "read another value", digest("b")),
    ]);

    expect(report.summary.normalized).toMatchObject({
      candidateHits: 1,
      safeHits: 0,
      unsafeHits: 1,
    });
    expect(report.summary.tokens.normalizedModelInput).toBe("200");
    expect(report.summary.gate).toEqual({
      passed: false,
      reasons: [
        "NORMALIZED_UNSAFE_HITS",
        "NO_SAFE_HIT_LIFT",
        "NO_POSITIVE_NET_TOKEN_DELTA",
      ],
    });
  });

  it("falls back to exact keys on bypass without inventing semantic hits", async () => {
    const inspector: IntentInspector = {
      inspect: async () => ({
        status: "bypass",
        sourceDigest: shadowHmac("intent-source", "1"),
        scopeDigest: shadowHmac("shadow-scope", "2"),
        bindingDigest: shadowHmac("shadow-binding", "3"),
        routeInputDigest: shadowHmac("route-input", "4"),
        reasons: ["INTENT_NO_MATCH"],
      }),
    };
    const repeated = cacheCase(0, "unknown");
    const report = await run(
      [repeated, { ...cacheCase(1, "unknown"), rawKey: repeated.rawKey }],
      inspector,
    );

    expect(report.summary.normalization).toMatchObject({ bypassed: 2 });
    expect(report.summary.raw.safeHits).toBe(1);
    expect(report.summary.normalized.safeHits).toBe(1);
    expect(report.summary.gate.reasons).toContain("NO_SAFE_HIT_LIFT");
  });

  it("bounds a stalled inspector and authenticates no optimistic result", async () => {
    const report = await run([cacheCase(0, "stalled")], {
      inspect: async () => await new Promise(() => undefined),
    });

    expect(report.cases[0]).toMatchObject({
      normalization: "inspection-timeout",
      reasons: ["INSPECTION_TIMEOUT"],
    });
    expect(report.summary.gate.reasons).toContain("INSPECTION_FAILURES");
  });

  it("rejects duplicate cases and invalid report authentication", async () => {
    const item = cacheCase(0, "one");
    await expect(run([item, item])).rejects.toThrow(/case set/u);
    await expect(
      runCacheImpactStudy({
        cases: [item],
        inspector: eligibleInspector(),
        keyId: "cache-impact-v1",
        datasetDigest: hmac("d"),
        inspectionTimeoutMs: 50,
        authenticateReport: () => "invalid" as never,
      }),
    ).rejects.toThrow(/authenticator/u);
  });

  it("snapshots trusted case data without invoking hostile accessors", async () => {
    let getterCalls = 0;
    const hostileUsage = {
      get modelInputTokens() {
        getterCalls += 1;
        return 100;
      },
      modelOutputTokens: 20,
      normalizationInputTokens: 0,
      normalizationOutputTokens: 0,
    };
    const hostileRouteInput = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(hostileRouteInput, "command", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return "status";
      },
    });

    await expect(
      run([
        {
          ...cacheCase(0, "hostile usage"),
          usage: hostileUsage as never,
        },
      ]),
    ).rejects.toThrow(/case set/u);
    await expect(
      run([
        {
          ...cacheCase(0, "hostile route input"),
          request: {
            ...cacheCase(0, "hostile route input").request,
            routeInput: hostileRouteInput,
          },
        },
      ]),
    ).rejects.toThrow(/case set/u);
    expect(getterCalls).toBe(0);
  });

  it("rejects an accessor-backed inspector result without reading reasons", async () => {
    let getterCalls = 0;
    const reasons: string[] = [];
    Object.defineProperty(reasons, "0", {
      enumerable: true,
      configurable: true,
      get: () => {
        getterCalls += 1;
        return "INTENT_NORMALIZED";
      },
    });
    reasons.length = 1;
    const report = await run([cacheCase(0, "hostile result")], {
      inspect: async () =>
        ({
          status: "eligible",
          intentKey: shadowHmac("shadow-intent", "a"),
          reasons,
        }) as never,
    });

    expect(getterCalls).toBe(0);
    expect(report.cases[0]?.normalization).toBe("inspector-failed");
    expect(report.summary.gate.reasons).toContain("INSPECTION_FAILURES");
  });
});
