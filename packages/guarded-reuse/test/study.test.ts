import { createHash } from "node:crypto";

import {
  createHmacOpaqueDigester,
  type HmacEvidenceDigest,
} from "@intentabi/core";
import {
  createCacheEntry,
  createNormalizationWitness,
  hmacIntentSourceDigest,
  hmacScopeDigest,
  type IntentIR,
  type NormalizerBinding,
} from "semwitness/intent";
import { describe, expect, it } from "vitest";

import {
  runObservationReuseStudy,
  type ObservationCacheBinding,
  type ObservationReuseCase,
} from "../src/index.js";

const secret = "guarded-reuse-test-secret-32-bytes";
const digester = createHmacOpaqueDigester(secret, "guarded-reuse-test");
const sha = (value: string) =>
  `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}` as const;
const key = (value: string): HmacEvidenceDigest =>
  digester.digestJson({ domain: value });
const ontology = Object.freeze({
  id: "external-test",
  version: "1.0.0",
  digest: sha("ontology"),
});
const normalizer = Object.freeze({
  id: "external-label-oracle",
  version: "1.0.0",
  artifactDigest: sha("oracle-artifact"),
  configDigest: sha("oracle-config"),
});
const normalizationPolicyDigest = sha("normalization-policy");

function intent(effect: "read" | "write" = "read"): IntentIR {
  return Object.freeze({
    schema: "semwitness.dev/intent-ir/v1alpha1",
    ontology,
    goal: {
      namespace: "external",
      action: effect === "read" ? "search" : "reserve",
      object: "hotel",
      polarity: "affirm",
    },
    slots: Object.freeze([]),
    constraints: Object.freeze([]),
    temporal: { kind: "none" },
    output: { format: "json", locale: "en-US", detail: "exact" },
    effect,
  });
}

function binding(
  frame: IntentIR,
  source: string,
  overrides: {
    readonly tenant?: string;
    readonly principal?: string;
    readonly authorization?: string;
    readonly context?: string;
    readonly policy?: string;
    readonly plan?: string;
    readonly execution?: string;
    readonly tool?: string;
  } = {},
  oracleNormalizer: NormalizerBinding = normalizer,
) {
  const sourceDigest = hmacIntentSourceDigest(secret, source);
  const witness = createNormalizationWitness({
    sourceDigest,
    intent: frame,
    normalizer: oracleNormalizer,
    ontology,
    policyDigest: normalizationPolicyDigest,
    assessment: {
      ambiguous: false,
      confidencePpm: 1_000_000,
      minimumConfidencePpm: 1_000_000,
    },
    candidateEvidence: [],
  });
  const cacheBinding: ObservationCacheBinding = {
    intentDigest: witness.intentDigest,
    normalization: {
      normalizer: witness.normalizer,
      policyDigest: witness.policyDigest,
      minimumConfidencePpm: witness.assessment.minimumConfidencePpm,
    },
    scope: {
      cacheNamespace: hmacScopeDigest(
        "cache-namespace",
        secret,
        "observation-lab",
      ),
      tenant: hmacScopeDigest("tenant", secret, overrides.tenant ?? "tenant-a"),
      principal: hmacScopeDigest(
        "principal",
        secret,
        overrides.principal ?? "principal-a",
      ),
    },
    authorizationDigest: hmacScopeDigest(
      "authorization",
      secret,
      overrides.authorization ?? "reader-v1",
    ),
    contextDigest: hmacScopeDigest(
      "context",
      secret,
      overrides.context ?? "workspace-a",
    ),
    policyDigest: sha(overrides.policy ?? "host-policy-v1"),
    effect: frame.effect,
    tier: "observation",
    dependencies: {
      planDigest: sha(overrides.plan ?? "plan-v1"),
      executionDigest: sha(overrides.execution ?? "execution-v1"),
      toolDigest: sha(overrides.tool ?? "tool-v1"),
    },
  };
  return { sourceDigest, witness, cacheBinding };
}

function studyCase(input: {
  readonly id: string;
  readonly source: string;
  readonly exact?: string;
  readonly scenario: ObservationReuseCase["scenario"];
  readonly expectedGuardedOutcome: ObservationReuseCase["expectedGuardedOutcome"];
  readonly expectedGuardedReasons?: ObservationReuseCase["expectedGuardedReasons"];
  readonly value?: string;
  readonly oracleAllowsReuse?: boolean;
  readonly frame?: IntentIR;
  readonly overrides?: Parameters<typeof binding>[2];
  readonly entryFreshness?: ObservationReuseCase["entryFreshness"];
  readonly lookupFreshness?: ObservationReuseCase["lookupFreshness"];
  readonly guardedCandidateOverride?: ObservationReuseCase["guardedCandidateOverride"];
  readonly normalizerOverride?: NormalizerBinding;
}): ObservationReuseCase {
  const frame = input.frame ?? intent();
  const prepared = binding(
    frame,
    input.source,
    input.overrides,
    input.normalizerOverride,
  );
  return Object.freeze({
    caseRef: key(`case:${input.id}`),
    exactKey: key(`exact:${input.exact ?? input.source}`),
    unguardedIntentKey: key(`intent:${prepared.witness.intentDigest}`),
    scenario: input.scenario,
    expectedGuardedOutcome: input.expectedGuardedOutcome,
    expectedGuardedReasons: Object.freeze([
      ...(input.expectedGuardedReasons ??
        (input.expectedGuardedOutcome === "safe-hit"
          ? ["CACHE_HIT_ELIGIBLE"]
          : input.expectedGuardedOutcome === "ineligible"
            ? ["CACHE_TIER_EFFECT_FORBIDDEN"]
            : [])),
    ]),
    expectedValueDigest: sha(input.value ?? "value-a"),
    oracleAllowsReuse: input.oracleAllowsReuse ?? true,
    intent: frame,
    normalizationWitness: prepared.witness,
    sourceDigest: prepared.sourceDigest,
    binding: prepared.cacheBinding,
    entryFreshness:
      input.entryFreshness ??
      Object.freeze({
        kind: "ttl" as const,
        createdAtEpochMs: 1_000,
        ttlMs: 1_000,
      }),
    lookupFreshness:
      input.lookupFreshness ??
      Object.freeze({ kind: "ttl" as const, checkedAtEpochMs: 1_500 }),
    ...(input.guardedCandidateOverride === undefined
      ? {}
      : { guardedCandidateOverride: input.guardedCandidateOverride }),
  });
}

function run(
  cases: readonly ObservationReuseCase[],
  requiredScenarios = [...new Set(cases.map((item) => item.scenario))],
  cacheKeySecret: Uint8Array | string = secret,
) {
  return runObservationReuseStudy({
    cases,
    keyId: "guarded-reuse-test",
    cacheKeySecret,
    digester,
    datasetDigest: key("dataset"),
    sourceDigest: sha("external-source"),
    sourceRevision: "a".repeat(40),
    requiredScenarios,
    normalizationContract: {
      normalizer,
      policyDigest: normalizationPolicyDigest,
      minimumConfidencePpm: 1_000_000,
    },
  });
}

describe("guarded observation reuse study", () => {
  it("keeps paraphrase lift while isolating tenant drift and quarantining an unguarded collision", () => {
    const cases = Object.freeze([
      studyCase({
        id: "base",
        source: "Find a hotel",
        scenario: "equivalent-paraphrase",
        expectedGuardedOutcome: "miss",
      }),
      studyCase({
        id: "paraphrase",
        source: "Show me a place to stay",
        scenario: "equivalent-paraphrase",
        expectedGuardedOutcome: "safe-hit",
      }),
      studyCase({
        id: "tenant-drift",
        source: "Find accommodation",
        scenario: "tenant-drift",
        expectedGuardedOutcome: "miss",
        value: "value-b",
        oracleAllowsReuse: false,
        overrides: { tenant: "tenant-b" },
      }),
      studyCase({
        id: "return",
        source: "Find a hotel",
        exact: "Find a hotel",
        scenario: "return-after-conflict",
        expectedGuardedOutcome: "safe-hit",
      }),
    ]);

    const report = run(cases);

    expect(report.summary).toMatchObject({
      exact: { safeHits: 1, unsafeHits: 0 },
      unguardedIntent: {
        safeHits: 1,
        unsafeHits: 1,
        quarantined: 1,
        quarantinedKeys: 1,
      },
      guarded: {
        safeHits: 2,
        unsafeHits: 0,
        admissionBypasses: 0,
      },
      safeHitLiftVsExact: 1,
      gate: { passed: true, reasons: [] },
    });
    expect(report.cases.map((item) => item.guarded)).toEqual([
      "miss",
      "safe-hit",
      "miss",
      "safe-hit",
    ]);
    expect(report.cases[3]?.unguardedIntent).toBe("quarantined");
    expect(report).toMatchObject({
      mode: "shadow",
      servingAuthority: "none",
      activationAuthorized: false,
      applied: false,
      promotionManifest: "not-produced",
    });
  });

  it("uses SemWitness admission for TTL and hostile-store checks", () => {
    const base = studyCase({
      id: "ttl-base",
      source: "Find a hotel",
      scenario: "ttl-fresh",
      expectedGuardedOutcome: "miss",
    });
    const stale = studyCase({
      id: "ttl-stale",
      source: "Show me a hotel",
      scenario: "ttl-stale",
      expectedGuardedOutcome: "admission-bypass",
      expectedGuardedReasons: ["CACHE_STALE"],
      oracleAllowsReuse: false,
      lookupFreshness: Object.freeze({
        kind: "ttl" as const,
        checkedAtEpochMs: 2_000,
      }),
    });
    const other = binding(intent(), "hostile", { tenant: "tenant-b" });
    const hostileEntry = createCacheEntry({
      valueDigest: sha("hostile-value"),
      binding: other.cacheBinding,
      freshness: { kind: "ttl", createdAtEpochMs: 1_000, ttlMs: 1_000 },
    });
    const hostile = studyCase({
      id: "hostile",
      source: "Find another hotel",
      scenario: "hostile-store-substitution",
      expectedGuardedOutcome: "admission-bypass",
      expectedGuardedReasons: ["CACHE_TENANT_MISMATCH"],
      oracleAllowsReuse: false,
      guardedCandidateOverride: hostileEntry,
    });

    const ttlReport = run(Object.freeze([base, stale]), [
      "ttl-fresh",
      "ttl-stale",
    ]);
    const hostileReport = run(Object.freeze([hostile]), [
      "hostile-store-substitution",
    ]);

    expect(ttlReport.cases[1]).toMatchObject({
      guarded: "admission-bypass",
      guardedMatchedExpectation: true,
    });
    expect(ttlReport.cases[1]?.guardedReasons).toContain("CACHE_STALE");
    expect(hostileReport.cases[0]?.guardedReasons).toContain(
      "CACHE_TENANT_MISMATCH",
    );
  });

  it("never looks up or stores a transactional observation and emits no private content", () => {
    const write = intent("write");
    const report = run(
      Object.freeze([
        studyCase({
          id: "write-a",
          source: "Book a restaurant",
          scenario: "transactional-effect",
          expectedGuardedOutcome: "ineligible",
          oracleAllowsReuse: false,
          frame: write,
        }),
        studyCase({
          id: "write-b",
          source: "Reserve a table",
          scenario: "transactional-effect",
          expectedGuardedOutcome: "ineligible",
          oracleAllowsReuse: false,
          frame: write,
        }),
      ]),
      ["transactional-effect"],
    );

    expect(report.summary.guarded).toMatchObject({
      candidateHits: 0,
      misses: 0,
      ineligible: 2,
    });
    expect(report.summary.unguardedIntent.unsafeHits).toBe(1);
    const serialized = JSON.stringify(report);
    expect(serialized).not.toContain("Book a restaurant");
    expect(serialized).not.toContain("tenant-a");
    expect(serialized).not.toContain("principal-a");
    expect(serialized).not.toContain("hostile-value");
  });

  it("binds the MAC to the report body and rejects a self-declared normalizer on the first miss", () => {
    const accepted = run(
      Object.freeze([
        studyCase({
          id: "mac-a",
          source: "Find a hotel",
          scenario: "equivalent-paraphrase",
          expectedGuardedOutcome: "miss",
        }),
      ]),
    );
    const changed = run(
      Object.freeze([
        studyCase({
          id: "mac-b",
          source: "Locate a hotel",
          scenario: "equivalent-paraphrase",
          expectedGuardedOutcome: "miss",
        }),
      ]),
    );
    expect(accepted.reportMac).not.toBe(changed.reportMac);

    const alternateNormalizer: NormalizerBinding = Object.freeze({
      ...normalizer,
      id: "self-declared-oracle",
      artifactDigest: sha("self-declared-artifact"),
    });
    const rejected = run(
      Object.freeze([
        studyCase({
          id: "self-declared",
          source: "Find a hotel",
          scenario: "equivalent-paraphrase",
          expectedGuardedOutcome: "admission-bypass",
          expectedGuardedReasons: ["CACHE_NORMALIZATION_WITNESS_INVALID"],
          normalizerOverride: alternateNormalizer,
        }),
      ]),
    );
    expect(rejected.cases[0]).toMatchObject({
      guarded: "admission-bypass",
      guardedMatchedExpectation: true,
    });
    expect(rejected.summary.guarded.misses).toBe(0);
  });

  it("evicts freshness drift without weakening collision quarantine", () => {
    const revisions = Object.freeze([
      Object.freeze({ namespace: "model", digest: sha("model-v1") }),
      Object.freeze({ namespace: "tool", digest: sha("tool-v1") }),
    ]);
    const reversed = Object.freeze([...revisions].reverse());
    const drifted = Object.freeze([
      Object.freeze({ namespace: "model", digest: sha("model-v2") }),
      revisions[1]!,
    ]);
    const report = run(
      Object.freeze([
        studyCase({
          id: "revision-base",
          source: "Find a hotel",
          scenario: "revision-equivalent",
          expectedGuardedOutcome: "miss",
          entryFreshness: { kind: "revision-set", revisions },
          lookupFreshness: { kind: "revision-set", revisions },
        }),
        studyCase({
          id: "revision-warm",
          source: "Show me a hotel",
          scenario: "revision-equivalent",
          expectedGuardedOutcome: "safe-hit",
          entryFreshness: { kind: "revision-set", revisions },
          lookupFreshness: { kind: "revision-set", revisions: reversed },
        }),
        studyCase({
          id: "revision-drift",
          source: "Locate a hotel",
          scenario: "revision-drift",
          expectedGuardedOutcome: "admission-bypass",
          expectedGuardedReasons: ["CACHE_REVISION_MISMATCH"],
          entryFreshness: { kind: "revision-set", revisions },
          lookupFreshness: { kind: "revision-set", revisions: drifted },
          oracleAllowsReuse: false,
        }),
        studyCase({
          id: "revision-refresh",
          source: "Find accommodation",
          scenario: "revision-equivalent",
          expectedGuardedOutcome: "miss",
          entryFreshness: { kind: "revision-set", revisions },
          lookupFreshness: { kind: "revision-set", revisions },
        }),
      ]),
      ["revision-equivalent", "revision-drift"],
    );
    expect(report.cases.map((item) => item.guarded)).toEqual([
      "miss",
      "safe-hit",
      "admission-bypass",
      "miss",
    ]);
    expect(report.summary.guarded.quarantinedKeys).toBe(0);

    const collision = run(
      Object.freeze([
        studyCase({
          id: "collision-a",
          source: "Find a hotel",
          scenario: "equivalent-paraphrase",
          expectedGuardedOutcome: "miss",
        }),
        studyCase({
          id: "collision-b",
          source: "Show me a hotel",
          scenario: "hostile-store-substitution",
          expectedGuardedOutcome: "safe-hit",
          value: "different-value",
          oracleAllowsReuse: false,
        }),
        studyCase({
          id: "collision-return",
          source: "Locate a hotel",
          scenario: "return-after-conflict",
          expectedGuardedOutcome: "safe-hit",
        }),
      ]),
    );
    expect(collision.cases.map((item) => item.guarded)).toEqual([
      "miss",
      "unsafe-hit",
      "quarantined",
    ]);
    expect(collision.summary.guarded.quarantinedKeys).toBe(1);
    expect(collision.summary.gate.reasons).toContain("GUARDED_UNSAFE_HITS");
  });

  it("rejects accessors before invocation and validates the cache secret even for writes", () => {
    const valid = studyCase({
      id: "accessor",
      source: "Find a hotel",
      scenario: "equivalent-paraphrase",
      expectedGuardedOutcome: "miss",
    });
    let invoked = false;
    const accessor = { ...valid } as Record<string, unknown>;
    Object.defineProperty(accessor, "exactKey", {
      enumerable: true,
      get() {
        invoked = true;
        return valid.exactKey;
      },
    });
    Object.freeze(accessor);
    expect(() =>
      run(Object.freeze([accessor as unknown as ObservationReuseCase])),
    ).toThrow("Guarded reuse case set is invalid");
    expect(invoked).toBe(false);

    const write = studyCase({
      id: "short-secret-write",
      source: "Book a table",
      scenario: "transactional-effect",
      expectedGuardedOutcome: "ineligible",
      oracleAllowsReuse: false,
      frame: intent("write"),
    });
    expect(() => run(Object.freeze([write]), undefined, "too-short")).toThrow(
      "Guarded reuse study configuration is invalid",
    );

    const malformedWrite = Object.freeze({
      ...write,
      intent: Object.freeze({ effect: "write" }) as unknown as IntentIR,
    });
    expect(() => run(Object.freeze([malformedWrite]))).toThrow(
      "Guarded reuse case set is invalid",
    );

    const hostileMalformed = studyCase({
      id: "hostile-malformed",
      source: "Find a hotel",
      scenario: "hostile-store-substitution",
      expectedGuardedOutcome: "admission-bypass",
      expectedGuardedReasons: ["INTENT_MALFORMED"],
      oracleAllowsReuse: false,
      guardedCandidateOverride: Object.freeze(
        {},
      ) as ObservationReuseCase["guardedCandidateOverride"],
    });
    const hostileReport = run(Object.freeze([hostileMalformed]));
    expect(hostileReport.cases[0]).toMatchObject({
      guarded: "admission-bypass",
      guardedMatchedExpectation: true,
    });
    expect(hostileReport.summary.guarded.quarantinedKeys).toBe(1);

    const read = studyCase({
      id: "effect-mismatch",
      source: "Find a hotel",
      scenario: "transactional-effect",
      expectedGuardedOutcome: "miss",
    });
    const effectMismatch = Object.freeze({
      ...read,
      expectedGuardedOutcome: "admission-bypass" as const,
      expectedGuardedReasons: Object.freeze(["CACHE_EFFECT_MISMATCH" as const]),
      binding: Object.freeze({ ...read.binding, effect: "write" as const }),
    });
    const mismatchReport = run(Object.freeze([effectMismatch]));
    expect(mismatchReport.cases[0]).toMatchObject({
      guarded: "admission-bypass",
      guardedMatchedExpectation: true,
    });

    const planTier = Object.freeze({
      ...read,
      binding: Object.freeze({
        ...read.binding,
        tier: "plan",
        dependencies: {
          operationRegistryDigest: sha("operations"),
          plannerDigest: sha("planner"),
          toolRegistryDigest: sha("tools"),
        },
      }) as unknown as ObservationCacheBinding,
    });
    expect(() => run(Object.freeze([planTier]))).toThrow(
      "Guarded reuse case set is invalid",
    );
  });
});
