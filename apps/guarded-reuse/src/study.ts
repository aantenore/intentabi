import { createHmacOpaqueDigester } from "@intentabi/core";
import {
  runObservationReuseStudy,
  type GuardedReuseReasonCode,
  type GuardedReuseReport,
  type GuardedReuseScenario,
  type ObservationCacheBinding,
  type ObservationReuseCase,
} from "@intentabi/guarded-reuse";
import {
  createCacheEntry,
  createNormalizationWitness,
  hmacIntentSourceDigest,
  hmacScopeDigest,
  type CacheEntryFreshness,
  type CacheLookupFreshness,
  type IntentIR,
  type NormalizerBinding,
  type OntologyBinding,
} from "semwitness/intent";

import {
  sha256Canonical,
  sourceManifestDigest,
  type SgdGuardedReuseConfig,
} from "./config.js";
import {
  prepareSgdSource,
  type PreparedSgdSource,
  type SelectedSgdExample,
} from "./sgd.js";

const NORMALIZER_ID = "google-sgd-external-label-oracle";
const NORMALIZER_VERSION = "1.0.0";
const MINIMUM_CONFIDENCE_PPM = 1_000_000;

export interface GuardedReuseExecution {
  readonly selectionOrderDigest: `sha256:${string}`;
  readonly report: GuardedReuseReport;
}

export function executeSgdGuardedReuse(input: {
  readonly config: SgdGuardedReuseConfig;
  readonly schemaBytes: Uint8Array;
  readonly dialoguesBytes: Uint8Array;
  readonly hmacSecret: Uint8Array | string;
}): GuardedReuseExecution {
  const prepared = prepareSgdSource(
    input.config,
    input.schemaBytes,
    input.dialoguesBytes,
  );
  const sourceDigest = sourceManifestDigest(
    input.config,
    prepared.selectionOrderDigest,
  );
  const digester = createHmacOpaqueDigester(
    input.hmacSecret,
    input.config.study.keyId,
  );
  const ontology: OntologyBinding = Object.freeze({
    id: "google-sgd",
    version: input.config.source.revision,
    digest: input.config.source.schema.sha256,
  });
  const normalizer: NormalizerBinding = Object.freeze({
    id: NORMALIZER_ID,
    version: NORMALIZER_VERSION,
    artifactDigest: sourceDigest,
    configDigest: input.config.source.selector.manifestSha256,
  });
  const cases = materializeCases({
    config: input.config,
    prepared,
    hmacSecret: input.hmacSecret,
    digester,
    ontology,
    normalizer,
    sourceDigest,
  });
  const datasetDigest = digester.digestJson({
    schema: "io.github.aantenore.intentabi/sgd-guarded-reuse-dataset/v1",
    sourceDigest,
    selectionOrderDigest: prepared.selectionOrderDigest,
    orderedCaseRefs: cases.map((item) => item.caseRef),
  });
  const report = runObservationReuseStudy({
    cases,
    keyId: input.config.study.keyId,
    cacheKeySecret: input.hmacSecret,
    digester,
    datasetDigest,
    sourceDigest,
    sourceRevision: input.config.source.revision,
    requiredScenarios: input.config.study.requiredScenarios,
    normalizationContract: {
      normalizer,
      policyDigest: input.config.study.normalizationPolicyDigest,
      minimumConfidencePpm: MINIMUM_CONFIDENCE_PPM,
    },
  });
  return deepFreeze({
    selectionOrderDigest: prepared.selectionOrderDigest,
    report,
  });
}

function materializeCases(input: {
  readonly config: SgdGuardedReuseConfig;
  readonly prepared: PreparedSgdSource;
  readonly hmacSecret: Uint8Array | string;
  readonly digester: ReturnType<typeof createHmacOpaqueDigester>;
  readonly ontology: OntologyBinding;
  readonly normalizer: NormalizerBinding;
  readonly sourceDigest: `sha256:${string}`;
}): readonly ObservationReuseCase[] {
  const cases = input.prepared.selected.map((example) => {
    const scenario = scenarioFor(example);
    const intent = intentFor(example, input.config, input.ontology);
    const sourceDigest = hmacIntentSourceDigest(
      input.hmacSecret,
      example.utterance,
    );
    const witness = createNormalizationWitness({
      sourceDigest,
      intent,
      normalizer: input.normalizer,
      ontology: input.ontology,
      policyDigest: input.config.study.normalizationPolicyDigest,
      assessment: {
        ambiguous: false,
        confidencePpm: MINIMUM_CONFIDENCE_PPM,
        minimumConfidencePpm: MINIMUM_CONFIDENCE_PPM,
      },
      candidateEvidence: [],
    });
    const binding = bindingFor({
      config: input.config,
      example,
      scenario,
      witnessIntentDigest: witness.intentDigest,
      normalizer: input.normalizer,
      hmacSecret: input.hmacSecret,
    });
    const freshness = freshnessFor(
      input.config,
      example,
      scenario,
      input.sourceDigest,
    );
    const expectedValueDigest = observationDigest(example, scenario);
    const expected = guardedExpectation(example, scenario);
    const guardedCandidateOverride =
      scenario === "hostile-store-substitution"
        ? createCacheEntry({
            valueDigest: sha256Canonical({
              schema:
                "io.github.aantenore.intentabi/sgd-synthetic-observation/v1",
              familyId: example.family.id,
              hostProfile: "hostile-store",
            }),
            binding: bindingFor({
              config: input.config,
              example,
              scenario: "tenant-drift",
              witnessIntentDigest: witness.intentDigest,
              normalizer: input.normalizer,
              hmacSecret: input.hmacSecret,
            }),
            freshness: freshness.entry,
          })
        : undefined;
    return deepFreeze({
      caseRef: input.digester.digestJson({
        schema: "io.github.aantenore.intentabi/sgd-case-ref/v1",
        familyId: example.family.id,
        ordinalInFamily: example.ordinalInFamily,
        dialogueId: example.dialogueId,
      }),
      exactKey: input.digester.digestJson({
        schema: "io.github.aantenore.intentabi/unguarded-exact-request/v1",
        locale: input.config.study.locale,
        utterance: example.utterance,
      }),
      unguardedIntentKey: input.digester.digestJson({
        schema: "io.github.aantenore.intentabi/unguarded-oracle-intent/v1",
        intent,
      }),
      scenario,
      expectedGuardedOutcome: expected.outcome,
      expectedGuardedReasons: expected.reasons,
      expectedValueDigest,
      oracleAllowsReuse: oracleAllowsReuse(example, scenario),
      intent,
      normalizationWitness: witness,
      sourceDigest,
      binding,
      entryFreshness: freshness.entry,
      lookupFreshness: freshness.lookup,
      ...(guardedCandidateOverride === undefined
        ? {}
        : { guardedCandidateOverride }),
    }) satisfies ObservationReuseCase;
  });
  return Object.freeze(cases);
}

function intentFor(
  example: SelectedSgdExample,
  config: SgdGuardedReuseConfig,
  ontology: OntologyBinding,
): IntentIR {
  return deepFreeze({
    schema: "semwitness.dev/intent-ir/v1alpha1" as const,
    ontology,
    goal: {
      namespace: "google-sgd",
      action: safeId(example.family.intent),
      object: safeId(example.family.service),
      polarity: "affirm" as const,
    },
    slots: Object.entries(example.family.slots)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([name, values]) => ({
        name: safeId(name),
        value: values.length === 1 ? values[0]! : [...values].sort(),
      })),
    constraints: [],
    temporal: { kind: "none" as const },
    output: {
      format: "json",
      locale: config.study.locale,
      detail: "exact",
    },
    effect: example.family.effect,
  });
}

function bindingFor(input: {
  readonly config: SgdGuardedReuseConfig;
  readonly example: SelectedSgdExample;
  readonly scenario: GuardedReuseScenario;
  readonly witnessIntentDigest: `sha256:${string}`;
  readonly normalizer: NormalizerBinding;
  readonly hmacSecret: Uint8Array | string;
}): ObservationCacheBinding {
  const familyId = input.example.family.id;
  const changed = (target: GuardedReuseScenario, base: string): string =>
    input.scenario === target ? `${base}:drift` : `${base}:base`;
  return deepFreeze({
    intentDigest: input.witnessIntentDigest,
    normalization: {
      normalizer: input.normalizer,
      policyDigest: input.config.study.normalizationPolicyDigest,
      minimumConfidencePpm: MINIMUM_CONFIDENCE_PPM,
    },
    scope: {
      cacheNamespace: hmacScopeDigest(
        "cache-namespace",
        input.hmacSecret,
        "sgd-guarded-observations-v1",
      ),
      tenant: hmacScopeDigest(
        "tenant",
        input.hmacSecret,
        changed("tenant-drift", `${familyId}:tenant`),
      ),
      principal: hmacScopeDigest(
        "principal",
        input.hmacSecret,
        changed("principal-drift", `${familyId}:principal`),
      ),
    },
    authorizationDigest: hmacScopeDigest(
      "authorization",
      input.hmacSecret,
      changed("authorization-drift", `${familyId}:authorization`),
    ),
    contextDigest: hmacScopeDigest(
      "context",
      input.hmacSecret,
      changed("context-drift", `${familyId}:context`),
    ),
    policyDigest:
      input.scenario === "policy-drift"
        ? sha256Canonical({
            schema: "io.github.aantenore.intentabi/sgd-cache-policy/v1",
            base: input.config.study.cachePolicyDigest,
            revision: "drift",
          })
        : input.config.study.cachePolicyDigest,
    effect: input.example.family.effect,
    tier: "observation" as const,
    dependencies: {
      planDigest: dependencyDigest(
        familyId,
        "plan",
        input.scenario === "plan-drift",
      ),
      executionDigest: dependencyDigest(
        familyId,
        "execution",
        input.scenario === "execution-drift",
      ),
      toolDigest: dependencyDigest(
        familyId,
        "tool",
        input.scenario === "tool-drift",
      ),
    },
  });
}

function freshnessFor(
  config: SgdGuardedReuseConfig,
  example: SelectedSgdExample,
  scenario: GuardedReuseScenario,
  sourceDigest: `sha256:${string}`,
): {
  readonly entry: CacheEntryFreshness;
  readonly lookup: CacheLookupFreshness;
} {
  if (scenario === "revision-equivalent" || scenario === "revision-drift") {
    const revision = Object.freeze({
      namespace: config.study.revisionNamespace,
      digest: sourceDigest,
    });
    return deepFreeze({
      entry: { kind: "revision-set" as const, revisions: [revision] },
      lookup: {
        kind: "revision-set" as const,
        revisions: [
          scenario === "revision-drift"
            ? {
                namespace: config.study.revisionNamespace,
                digest: sha256Canonical({
                  schema:
                    "io.github.aantenore.intentabi/sgd-synthetic-revision/v1",
                  familyId: example.family.id,
                  revision: "drift",
                }),
              }
            : revision,
        ],
      },
    });
  }
  const createdAtEpochMs = config.study.ttl.createdAtEpochMs;
  return deepFreeze({
    entry: {
      kind: "ttl" as const,
      createdAtEpochMs,
      ttlMs: config.study.ttl.ttlMs,
    },
    lookup: {
      kind: "ttl" as const,
      checkedAtEpochMs:
        createdAtEpochMs +
        (scenario === "ttl-stale"
          ? config.study.ttl.staleOffsetMs
          : config.study.ttl.freshOffsetMs),
    },
  });
}

function scenarioFor(example: SelectedSgdExample): GuardedReuseScenario {
  const ordinal = example.ordinalInFamily;
  switch (example.family.id) {
    case "hotels-search-empty": {
      const scenarios: readonly GuardedReuseScenario[] = [
        "equivalent-paraphrase",
        "equivalent-paraphrase",
        "tenant-drift",
        "principal-drift",
        "authorization-drift",
        "context-drift",
        "policy-drift",
        "plan-drift",
        "execution-drift",
        "tool-drift",
        "return-after-conflict",
      ];
      return scenarios[ordinal] ?? "equivalent-paraphrase";
    }
    case "hotels-search-london":
      return "ttl-fresh";
    case "hotels-search-room-star":
      return ordinal === 0 ? "ttl-fresh" : "ttl-stale";
    case "hotels-search-smoking":
      return ordinal < 2 ? "revision-equivalent" : "revision-drift";
    case "hotels-search-star":
      return ordinal === 3
        ? "hostile-store-substitution"
        : "equivalent-paraphrase";
    case "music-lookup-empty":
      return "equivalent-paraphrase";
    case "restaurants-reserve-empty":
      return "transactional-effect";
    default:
      throw new TypeError("Selected SGD family is unsupported");
  }
}

function guardedExpectation(
  example: SelectedSgdExample,
  scenario: GuardedReuseScenario,
): {
  readonly outcome: ObservationReuseCase["expectedGuardedOutcome"];
  readonly reasons: readonly GuardedReuseReasonCode[];
} {
  if (scenario === "transactional-effect") {
    return {
      outcome: "ineligible",
      reasons: Object.freeze(["CACHE_TIER_EFFECT_FORBIDDEN"]),
    };
  }
  if (scenario === "ttl-stale") {
    return {
      outcome: "admission-bypass",
      reasons: Object.freeze(["CACHE_STALE"]),
    };
  }
  if (scenario === "revision-drift") {
    return {
      outcome: "admission-bypass",
      reasons: Object.freeze(["CACHE_REVISION_MISMATCH"]),
    };
  }
  if (scenario === "hostile-store-substitution") {
    return {
      outcome: "admission-bypass",
      reasons: Object.freeze(["CACHE_TENANT_MISMATCH"]),
    };
  }
  if (isInitialKey(example, scenario)) {
    return { outcome: "miss", reasons: Object.freeze([]) };
  }
  if (
    scenario === "tenant-drift" ||
    scenario === "principal-drift" ||
    scenario === "authorization-drift" ||
    scenario === "context-drift" ||
    scenario === "policy-drift" ||
    scenario === "plan-drift" ||
    scenario === "execution-drift" ||
    scenario === "tool-drift"
  ) {
    return { outcome: "miss", reasons: Object.freeze([]) };
  }
  return {
    outcome: "safe-hit",
    reasons: Object.freeze(["CACHE_HIT_ELIGIBLE"]),
  };
}

function isInitialKey(
  example: SelectedSgdExample,
  scenario: GuardedReuseScenario,
): boolean {
  if (example.ordinalInFamily !== 0) return false;
  return (
    scenario === "equivalent-paraphrase" ||
    scenario === "ttl-fresh" ||
    scenario === "revision-equivalent"
  );
}

function oracleAllowsReuse(
  example: SelectedSgdExample,
  scenario: GuardedReuseScenario,
): boolean {
  return (
    example.family.effect === "read" &&
    (scenario === "equivalent-paraphrase" ||
      scenario === "ttl-fresh" ||
      scenario === "revision-equivalent" ||
      scenario === "return-after-conflict")
  );
}

function observationDigest(
  example: SelectedSgdExample,
  scenario: GuardedReuseScenario,
): `sha256:${string}` {
  const drift = [
    "tenant-drift",
    "principal-drift",
    "authorization-drift",
    "context-drift",
    "policy-drift",
    "plan-drift",
    "execution-drift",
    "tool-drift",
  ].includes(scenario);
  return sha256Canonical({
    schema: "io.github.aantenore.intentabi/sgd-synthetic-observation/v1",
    familyId: example.family.id,
    hostProfile: drift ? scenario : "base",
  });
}

function dependencyDigest(
  familyId: string,
  dependency: "plan" | "execution" | "tool",
  drift: boolean,
): `sha256:${string}` {
  return sha256Canonical({
    schema: "io.github.aantenore.intentabi/sgd-synthetic-dependency/v1",
    familyId,
    dependency,
    revision: drift ? "drift" : "base",
  });
}

function safeId(value: string): string {
  const normalized = value
    .replace(/([a-z0-9])([A-Z])/gu, "$1-$2")
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/gu, "-")
    .replace(/^-+|-+$/gu, "");
  if (!/^[a-z0-9][a-z0-9._-]{0,127}$/u.test(normalized)) {
    throw new TypeError("SGD label cannot be represented as an IntentIR id");
  }
  return normalized;
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const nested of Object.values(value)) deepFreeze(nested);
  }
  return value;
}
