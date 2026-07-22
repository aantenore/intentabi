import { isProxy } from "node:util/types";

import type {
  HmacEvidenceDigest,
  KeyedHmacDigester,
  Sha256Digest,
} from "@intentabi/core";
import {
  admitCacheHit,
  createCacheEntry,
  hmacCacheKey,
  INTENT_REASON_CODES,
  parseIntentIR,
  parseNormalizationWitness,
  type CacheBinding,
  type CacheEntry,
  type CacheEntryFreshness,
  type CacheLookupFreshness,
  type IntentIR,
  type IntentReasonCode,
  type IntentSourceDigest,
  type NormalizationWitness,
  type NormalizerBinding,
  type ShadowDecision,
} from "semwitness/intent";

export const GUARDED_REUSE_REPORT_SCHEMA =
  "io.github.aantenore.intentabi/guarded-observation-reuse-report/v1alpha1" as const;
export const GUARDED_REUSE_IMPLEMENTATION =
  "io.github.aantenore.intentabi/guarded-observation-reuse/semwitness-admission-v1" as const;
export const GUARDED_REUSE_REPORT_MAC_SCHEMA =
  "io.github.aantenore.intentabi/guarded-observation-reuse-report-mac/v1" as const;

const HMAC_EVIDENCE = /^hmac-sha256:evidence:[a-f0-9]{64}$/u;
const SHA256 = /^sha256:[a-f0-9]{64}$/u;
const INTENT_SOURCE = /^(?:sha256|hmac-sha256:intent-source):[a-f0-9]{64}$/u;
const CACHE_KEY = /^hmac-sha256:cache-key:[a-f0-9]{64}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const NORMALIZER_ID = /^[a-z0-9][a-z0-9._-]{0,127}$/u;
const NORMALIZER_VERSION = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/u;
const MAX_CASES = 10_000;
const MAX_CASE_DATA_NODES = 20_000;
const MAX_STUDY_DATA_NODES = 2_000_000;
const MAX_CASE_DATA_DEPTH = 32;
const REQUIRED_CASE_KEYS = Object.freeze([
  "binding",
  "caseRef",
  "entryFreshness",
  "exactKey",
  "expectedGuardedOutcome",
  "expectedGuardedReasons",
  "expectedValueDigest",
  "intent",
  "lookupFreshness",
  "normalizationWitness",
  "oracleAllowsReuse",
  "scenario",
  "sourceDigest",
  "unguardedIntentKey",
] as const);
const ALLOWED_CASE_KEYS = new Set<string>([
  ...REQUIRED_CASE_KEYS,
  "guardedCandidateOverride",
]);

export const GUARDED_REUSE_SCENARIOS = Object.freeze([
  "equivalent-paraphrase",
  "tenant-drift",
  "principal-drift",
  "authorization-drift",
  "context-drift",
  "policy-drift",
  "plan-drift",
  "execution-drift",
  "tool-drift",
  "ttl-fresh",
  "ttl-stale",
  "revision-equivalent",
  "revision-drift",
  "transactional-effect",
  "return-after-conflict",
  "hostile-store-substitution",
] as const);

export type GuardedReuseScenario = (typeof GUARDED_REUSE_SCENARIOS)[number];
export type ReuseOutcome =
  | "miss"
  | "safe-hit"
  | "unsafe-hit"
  | "admission-bypass"
  | "quarantined"
  | "ineligible";
export type GuardedReuseReasonCode =
  IntentReasonCode | "HOST_ORACLE_VALUE_MISMATCH" | "KEY_QUARANTINED";
export type ObservationCacheBinding = Extract<
  CacheBinding,
  { readonly tier: "observation" }
>;
const GUARDED_REUSE_REASON_CODES = new Set<string>([
  ...INTENT_REASON_CODES,
  "HOST_ORACLE_VALUE_MISMATCH",
  "KEY_QUARANTINED",
]);

export interface ObservationReuseCase {
  readonly caseRef: HmacEvidenceDigest;
  readonly exactKey: HmacEvidenceDigest;
  readonly unguardedIntentKey: HmacEvidenceDigest;
  readonly scenario: GuardedReuseScenario;
  readonly expectedGuardedOutcome:
    "miss" | "safe-hit" | "admission-bypass" | "ineligible";
  readonly expectedGuardedReasons: readonly GuardedReuseReasonCode[];
  readonly expectedValueDigest: Sha256Digest;
  /** Host oracle: whether reusing a prior observation is valid for this case. */
  readonly oracleAllowsReuse: boolean;
  readonly intent: IntentIR;
  readonly normalizationWitness: NormalizationWitness;
  readonly sourceDigest: IntentSourceDigest;
  readonly binding: ObservationCacheBinding;
  readonly entryFreshness: CacheEntryFreshness;
  readonly lookupFreshness: CacheLookupFreshness;
  /** Test-only hostile-store projection under the current guarded lookup key. */
  readonly guardedCandidateOverride?: CacheEntry;
}

export interface GuardedReuseNormalizationContract {
  readonly normalizer: NormalizerBinding;
  readonly policyDigest: Sha256Digest;
  readonly minimumConfidencePpm: number;
}

export interface StrategyMetrics {
  readonly candidateHits: number;
  readonly safeHits: number;
  readonly unsafeHits: number;
  readonly admissionBypasses: number;
  readonly quarantined: number;
  readonly misses: number;
  readonly ineligible: number;
  readonly safeHitRatePpm: number;
  readonly quarantinedKeys: number;
}

export type GuardedReuseGateReason =
  | "GUARDED_UNSAFE_HITS"
  | "GUARDED_OUTCOME_MISMATCH"
  | "NO_SAFE_HIT_LIFT_VS_EXACT"
  | "MISSING_REQUIRED_SCENARIO";

export interface GuardedReuseCaseResult {
  readonly ordinal: number;
  readonly caseRef: HmacEvidenceDigest;
  readonly scenario: GuardedReuseScenario;
  readonly expectedGuardedOutcome: ObservationReuseCase["expectedGuardedOutcome"];
  readonly expectedGuardedReasons: readonly GuardedReuseReasonCode[];
  readonly guardedMatchedExpectation: boolean;
  readonly exact: ReuseOutcome;
  readonly unguardedIntent: ReuseOutcome;
  readonly guarded: ReuseOutcome;
  readonly guardedReasons: readonly GuardedReuseReasonCode[];
}

export interface UnsignedGuardedReuseReport {
  readonly schema: typeof GUARDED_REUSE_REPORT_SCHEMA;
  readonly implementation: typeof GUARDED_REUSE_IMPLEMENTATION;
  readonly mode: "shadow";
  readonly classification: "external-guarded-reuse-conformance";
  readonly tier: "observation";
  readonly servingAuthority: "none";
  readonly activationAuthorized: false;
  readonly applied: false;
  readonly promotionManifest: "not-produced";
  readonly statisticalQualification: false;
  readonly economicQualification: false;
  readonly keyId: string;
  readonly datasetDigest: HmacEvidenceDigest;
  readonly sourceDigest: Sha256Digest;
  readonly sourceRevision: string;
  readonly provenance: Readonly<{
    normalization: "external-label-oracle";
    workload: "pinned-public-source-plus-synthetic-host-boundaries";
    hostBindings: "synthetic-conformance";
    valueOracle: "deterministic-unattested";
    clock: "deterministic-unattested";
  }>;
  readonly cases: readonly GuardedReuseCaseResult[];
  readonly summary: Readonly<{
    requests: number;
    scenarios: Readonly<Record<GuardedReuseScenario, number>>;
    exact: StrategyMetrics;
    unguardedIntent: StrategyMetrics;
    guarded: StrategyMetrics;
    safeHitLiftVsExact: number;
    guardedWouldServe: 0;
    gate: Readonly<{
      passed: boolean;
      reasons: readonly GuardedReuseGateReason[];
    }>;
  }>;
}

export interface GuardedReuseReport extends UnsignedGuardedReuseReport {
  readonly reportMac: HmacEvidenceDigest;
}

interface StableEntry {
  readonly status: "stable";
  readonly entry: CacheEntry;
}

interface QuarantinedEntry {
  readonly status: "quarantined";
}

type StoreEntry = StableEntry | QuarantinedEntry;

interface StableBaselineEntry {
  readonly status: "stable";
  readonly valueDigest: Sha256Digest;
}

type BaselineStoreEntry = StableBaselineEntry | QuarantinedEntry;

export function runObservationReuseStudy(input: {
  readonly cases: readonly ObservationReuseCase[];
  readonly keyId: string;
  readonly cacheKeySecret: Uint8Array | string;
  readonly digester: KeyedHmacDigester;
  readonly datasetDigest: HmacEvidenceDigest;
  readonly sourceDigest: Sha256Digest;
  readonly sourceRevision: string;
  readonly requiredScenarios: readonly GuardedReuseScenario[];
  readonly normalizationContract: GuardedReuseNormalizationContract;
}): GuardedReuseReport {
  const requiredScenarios = snapshotRequiredScenarios(input.requiredScenarios);
  const normalizationContract = snapshotNormalizationContract(
    input.normalizationContract,
  );
  const cases = snapshotCases(input.cases);
  validateStudyInput(
    { ...input, requiredScenarios, normalizationContract },
    cases,
  );

  const exact = new Map<string, BaselineStoreEntry>();
  const unguardedIntent = new Map<string, BaselineStoreEntry>();
  const guarded = new Map<string, StoreEntry>();
  const results: GuardedReuseCaseResult[] = [];

  for (const [ordinal, item] of cases.entries()) {
    const exactResult = observeUnguarded(exact, item.exactKey, item);
    const intentResult = observeUnguarded(
      unguardedIntent,
      item.unguardedIntentKey,
      item,
    );
    const guardedResult = observeGuarded(
      guarded,
      item,
      input.cacheKeySecret,
      normalizationContract,
    );
    results.push(
      Object.freeze({
        ordinal,
        caseRef: item.caseRef,
        scenario: item.scenario,
        expectedGuardedOutcome: item.expectedGuardedOutcome,
        expectedGuardedReasons: Object.freeze([...item.expectedGuardedReasons]),
        guardedMatchedExpectation:
          guardedResult.outcome === item.expectedGuardedOutcome &&
          sameReasonSet(guardedResult.reasons, item.expectedGuardedReasons),
        exact: exactResult.outcome,
        unguardedIntent: intentResult.outcome,
        guarded: guardedResult.outcome,
        guardedReasons: Object.freeze([...guardedResult.reasons]),
      }),
    );
  }

  const scenarioCounts = scenarioSummary(results);
  const exactMetrics = summarize(
    results.map((item) => item.exact),
    exact,
  );
  const unguardedMetrics = summarize(
    results.map((item) => item.unguardedIntent),
    unguardedIntent,
  );
  const guardedMetrics = summarize(
    results.map((item) => item.guarded),
    guarded,
  );
  const safeHitLiftVsExact = guardedMetrics.safeHits - exactMetrics.safeHits;
  const gateReasons: GuardedReuseGateReason[] = [];
  if (guardedMetrics.unsafeHits > 0) {
    gateReasons.push("GUARDED_UNSAFE_HITS");
  }
  if (results.some((item) => !item.guardedMatchedExpectation)) {
    gateReasons.push("GUARDED_OUTCOME_MISMATCH");
  }
  if (safeHitLiftVsExact <= 0) {
    gateReasons.push("NO_SAFE_HIT_LIFT_VS_EXACT");
  }
  if (requiredScenarios.some((item) => scenarioCounts[item] === 0)) {
    gateReasons.push("MISSING_REQUIRED_SCENARIO");
  }

  const unsigned = deepFreeze({
    schema: GUARDED_REUSE_REPORT_SCHEMA,
    implementation: GUARDED_REUSE_IMPLEMENTATION,
    mode: "shadow" as const,
    classification: "external-guarded-reuse-conformance" as const,
    tier: "observation" as const,
    servingAuthority: "none" as const,
    activationAuthorized: false as const,
    applied: false as const,
    promotionManifest: "not-produced" as const,
    statisticalQualification: false as const,
    economicQualification: false as const,
    keyId: input.keyId,
    datasetDigest: input.datasetDigest,
    sourceDigest: input.sourceDigest,
    sourceRevision: input.sourceRevision,
    provenance: {
      normalization: "external-label-oracle" as const,
      workload: "pinned-public-source-plus-synthetic-host-boundaries" as const,
      hostBindings: "synthetic-conformance" as const,
      valueOracle: "deterministic-unattested" as const,
      clock: "deterministic-unattested" as const,
    },
    cases: Object.freeze(results),
    summary: {
      requests: results.length,
      scenarios: scenarioCounts,
      exact: exactMetrics,
      unguardedIntent: unguardedMetrics,
      guarded: guardedMetrics,
      safeHitLiftVsExact,
      guardedWouldServe: 0 as const,
      gate: {
        passed: gateReasons.length === 0,
        reasons: Object.freeze(gateReasons),
      },
    },
  }) satisfies UnsignedGuardedReuseReport;

  let reportMac: string;
  try {
    reportMac = input.digester.digestJson({
      schema: GUARDED_REUSE_REPORT_MAC_SCHEMA,
      report: unsigned,
    });
  } catch {
    throw new TypeError("Guarded reuse report authentication failed");
  }
  if (!HMAC_EVIDENCE.test(reportMac)) {
    throw new TypeError(
      "Guarded reuse report authenticator returned invalid data",
    );
  }
  return deepFreeze({
    ...unsigned,
    reportMac: reportMac as HmacEvidenceDigest,
  });
}

function observeUnguarded(
  store: Map<string, BaselineStoreEntry>,
  key: string,
  item: ObservationReuseCase,
): { readonly outcome: ReuseOutcome } {
  const current = store.get(key);
  if (current?.status === "quarantined") {
    return { outcome: "quarantined" };
  }
  if (current === undefined) {
    store.set(key, {
      status: "stable",
      valueDigest: item.expectedValueDigest,
    });
    return { outcome: "miss" };
  }
  const safe =
    item.oracleAllowsReuse &&
    item.intent.effect === "read" &&
    current.valueDigest === item.expectedValueDigest;
  if (safe) return { outcome: "safe-hit" };
  store.set(key, { status: "quarantined" });
  return { outcome: "unsafe-hit" };
}

function observeGuarded(
  store: Map<string, StoreEntry>,
  item: ObservationReuseCase,
  cacheKeySecret: Uint8Array | string,
  normalizationContract: GuardedReuseNormalizationContract,
): {
  readonly outcome: ReuseOutcome;
  readonly reasons: readonly GuardedReuseReasonCode[];
} {
  if (item.intent.effect !== item.binding.effect) {
    return {
      outcome: "admission-bypass",
      reasons: Object.freeze(["CACHE_EFFECT_MISMATCH"]),
    };
  }
  if (item.intent.effect !== "read") {
    return {
      outcome: "ineligible",
      reasons: Object.freeze(["CACHE_TIER_EFFECT_FORBIDDEN"]),
    };
  }
  let key: string;
  try {
    key = hmacCacheKey(cacheKeySecret, item.binding);
  } catch {
    return malformedAdmission();
  }
  if (!CACHE_KEY.test(key)) {
    throw new TypeError("SemWitness returned an invalid guarded cache key");
  }
  const stored = store.get(key);
  if (stored?.status === "quarantined") {
    return {
      outcome: "quarantined",
      reasons: Object.freeze(["KEY_QUARANTINED"]),
    };
  }
  const candidate = item.guardedCandidateOverride ?? stored?.entry;
  if (candidate === undefined) {
    let entry: CacheEntry;
    try {
      entry = entryFor(item);
    } catch {
      return malformedAdmission();
    }
    const admission = admitCandidate(entry, item, normalizationContract);
    if (admission.verdict !== "eligible") {
      return {
        outcome: "admission-bypass",
        reasons: Object.freeze([...admission.reasons]),
      };
    }
    store.set(key, { status: "stable", entry });
    return { outcome: "miss", reasons: Object.freeze([]) };
  }
  const decision = admitCandidate(candidate, item, normalizationContract);
  if (decision.verdict !== "eligible") {
    if (item.guardedCandidateOverride !== undefined) {
      store.set(key, { status: "quarantined" });
    } else if (
      decision.reasons.some((reason) =>
        [
          "CACHE_FRESHNESS_MODE_MISMATCH",
          "CACHE_REVISION_MISMATCH",
          "CACHE_STALE",
        ].includes(reason),
      )
    ) {
      store.delete(key);
    }
    return {
      outcome: "admission-bypass",
      reasons: Object.freeze([...decision.reasons]),
    };
  }
  const safe =
    item.oracleAllowsReuse &&
    candidate.valueDigest === item.expectedValueDigest;
  if (!safe) {
    store.set(key, { status: "quarantined" });
    return {
      outcome: "unsafe-hit",
      reasons: Object.freeze(["HOST_ORACLE_VALUE_MISMATCH"]),
    };
  }
  return {
    outcome: "safe-hit",
    reasons: Object.freeze([...decision.reasons]),
  };
}

function admitCandidate(
  candidate: CacheEntry,
  item: ObservationReuseCase,
  normalizationContract: GuardedReuseNormalizationContract,
): ShadowDecision {
  try {
    return admitCacheHit({
      entry: candidate,
      lookup: { binding: item.binding, freshness: item.lookupFreshness },
      normalizationWitness: item.normalizationWitness,
      sourceDigest: item.sourceDigest,
      intent: item.intent,
      expectedNormalizer: normalizationContract.normalizer,
      expectedNormalizationPolicyDigest: normalizationContract.policyDigest,
      expectedMinimumConfidencePpm: normalizationContract.minimumConfidencePpm,
    }).decision;
  } catch {
    return Object.freeze({
      verdict: "bypass" as const,
      applied: false as const,
      reasons: Object.freeze(["INTENT_MALFORMED" as const]),
    });
  }
}

function malformedAdmission(): {
  readonly outcome: "admission-bypass";
  readonly reasons: readonly GuardedReuseReasonCode[];
} {
  return Object.freeze({
    outcome: "admission-bypass" as const,
    reasons: Object.freeze(["INTENT_MALFORMED" as const]),
  });
}

function entryFor(item: ObservationReuseCase): CacheEntry {
  return createCacheEntry({
    valueDigest: item.expectedValueDigest,
    binding: item.binding,
    freshness: item.entryFreshness,
  });
}

function summarize(
  outcomes: readonly ReuseOutcome[],
  store: ReadonlyMap<string, { readonly status: "stable" | "quarantined" }>,
): StrategyMetrics {
  const count = (outcome: ReuseOutcome): number =>
    outcomes.filter((item) => item === outcome).length;
  const safeHits = count("safe-hit");
  const unsafeHits = count("unsafe-hit");
  const admissionBypasses = count("admission-bypass");
  return Object.freeze({
    candidateHits: safeHits + unsafeHits + admissionBypasses,
    safeHits,
    unsafeHits,
    admissionBypasses,
    quarantined: count("quarantined"),
    misses: count("miss"),
    ineligible: count("ineligible"),
    safeHitRatePpm: Math.round((safeHits * 1_000_000) / outcomes.length),
    quarantinedKeys: [...store.values()].filter(
      (item) => item.status === "quarantined",
    ).length,
  });
}

function scenarioSummary(
  results: readonly GuardedReuseCaseResult[],
): Readonly<Record<GuardedReuseScenario, number>> {
  const summary = Object.fromEntries(
    GUARDED_REUSE_SCENARIOS.map((item) => [item, 0]),
  ) as Record<GuardedReuseScenario, number>;
  for (const item of results) summary[item.scenario] += 1;
  return Object.freeze(summary);
}

function sameReasonSet(
  observed: readonly GuardedReuseReasonCode[],
  expected: readonly GuardedReuseReasonCode[],
): boolean {
  if (observed.length !== expected.length) return false;
  const observedSet = new Set(observed);
  return (
    observedSet.size === observed.length &&
    expected.every((reason) => observedSet.has(reason))
  );
}

function snapshotCases(
  source: readonly ObservationReuseCase[],
): readonly ObservationReuseCase[] {
  try {
    if (!Array.isArray(source) || isProxy(source)) throw new Error();
    const descriptors = Object.getOwnPropertyDescriptors(source);
    const sourceKeys = Reflect.ownKeys(descriptors);
    if (
      source.length > MAX_CASES ||
      sourceKeys.some(
        (key) =>
          typeof key !== "string" ||
          (key !== "length" && !/^(0|[1-9][0-9]*)$/u.test(key)),
      )
    ) {
      throw new Error();
    }
    const seen = new Set<string>();
    const studyBudget = { nodes: 0 };
    const snapshot: ObservationReuseCase[] = [];
    for (let index = 0; index < source.length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (
        descriptor === undefined ||
        !("value" in descriptor) ||
        !descriptor.enumerable
      ) {
        throw new Error();
      }
      const item = clonePlainData(
        descriptor.value,
        new Set<object>(),
        { nodes: 0 },
        studyBudget,
        0,
      ) as ObservationReuseCase;
      const keys = Object.keys(item);
      if (
        item === null ||
        typeof item !== "object" ||
        isProxy(item) ||
        keys.some((key) => !ALLOWED_CASE_KEYS.has(key)) ||
        REQUIRED_CASE_KEYS.some((key) => !Object.hasOwn(item, key)) ||
        !HMAC_EVIDENCE.test(item.caseRef) ||
        !HMAC_EVIDENCE.test(item.exactKey) ||
        !HMAC_EVIDENCE.test(item.unguardedIntentKey) ||
        !GUARDED_REUSE_SCENARIOS.includes(item.scenario) ||
        !["miss", "safe-hit", "admission-bypass", "ineligible"].includes(
          item.expectedGuardedOutcome,
        ) ||
        !Array.isArray(item.expectedGuardedReasons) ||
        item.expectedGuardedReasons.length > 32 ||
        new Set(item.expectedGuardedReasons).size !==
          item.expectedGuardedReasons.length ||
        !item.expectedGuardedReasons.every(
          (reason) =>
            typeof reason === "string" &&
            GUARDED_REUSE_REASON_CODES.has(reason),
        ) ||
        !SHA256.test(item.expectedValueDigest) ||
        !INTENT_SOURCE.test(item.sourceDigest) ||
        typeof item.oracleAllowsReuse !== "boolean"
      ) {
        throw new Error();
      }
      if (seen.has(item.caseRef)) throw new Error();
      seen.add(item.caseRef);
      snapshot.push(canonicalizeObservationCase(item));
    }
    return Object.freeze(snapshot);
  } catch {
    throw new TypeError("Guarded reuse case set is invalid");
  }
}

function canonicalizeObservationCase(
  item: ObservationReuseCase,
): ObservationReuseCase {
  const intent = parseIntentIR(item.intent);
  const normalizationWitness = parseNormalizationWitness(
    item.normalizationWitness,
  );
  const entry = createCacheEntry({
    valueDigest: item.expectedValueDigest,
    binding: item.binding,
    freshness: item.entryFreshness,
  });
  const witness = admitCacheHit({
    entry,
    lookup: {
      binding: item.binding,
      freshness: item.lookupFreshness,
    },
    normalizationWitness,
    sourceDigest: item.sourceDigest,
    intent,
    expectedNormalizer: normalizationWitness.normalizer,
    expectedNormalizationPolicyDigest: normalizationWitness.policyDigest,
    expectedMinimumConfidencePpm:
      normalizationWitness.assessment.minimumConfidencePpm,
  });
  if (witness.lookup.binding.tier !== "observation") {
    throw new TypeError("Guarded reuse case cache tier is invalid");
  }
  return Object.freeze({
    ...item,
    intent,
    normalizationWitness,
    binding: witness.lookup.binding,
    entryFreshness: witness.entry.freshness,
    lookupFreshness: witness.lookup.freshness,
  });
}

function clonePlainData(
  value: unknown,
  seen: Set<object>,
  caseBudget: { nodes: number },
  studyBudget: { nodes: number },
  depth: number,
): unknown {
  caseBudget.nodes += 1;
  studyBudget.nodes += 1;
  if (
    caseBudget.nodes > MAX_CASE_DATA_NODES ||
    studyBudget.nodes > MAX_STUDY_DATA_NODES
  ) {
    throw new Error();
  }
  if (
    value === null ||
    value === undefined ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    typeof value === "number"
  ) {
    return value;
  }
  if (
    typeof value !== "object" ||
    isProxy(value) ||
    seen.has(value) ||
    depth > MAX_CASE_DATA_DEPTH
  ) {
    throw new Error();
  }
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      const descriptors = Object.getOwnPropertyDescriptors(value);
      if (
        Reflect.ownKeys(descriptors).some(
          (key) =>
            typeof key !== "string" ||
            (key !== "length" && !/^(0|[1-9][0-9]*)$/u.test(key)),
        )
      ) {
        throw new Error();
      }
      const output: unknown[] = [];
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = descriptors[String(index)];
        if (
          descriptor === undefined ||
          !("value" in descriptor) ||
          !descriptor.enumerable
        ) {
          throw new Error();
        }
        output.push(
          clonePlainData(
            descriptor.value,
            seen,
            caseBudget,
            studyBudget,
            depth + 1,
          ),
        );
      }
      return Object.freeze(output);
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new Error();
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const output = Object.create(null) as Record<string, unknown>;
    for (const key of Reflect.ownKeys(descriptors)) {
      if (typeof key !== "string") throw new Error();
      const descriptor = descriptors[key];
      if (
        descriptor === undefined ||
        !("value" in descriptor) ||
        !descriptor.enumerable
      ) {
        throw new Error();
      }
      Object.defineProperty(output, key, {
        configurable: true,
        enumerable: true,
        value: clonePlainData(
          descriptor.value,
          seen,
          caseBudget,
          studyBudget,
          depth + 1,
        ),
        writable: true,
      });
    }
    return Object.freeze(output);
  } finally {
    seen.delete(value);
  }
}

function snapshotRequiredScenarios(
  source: readonly GuardedReuseScenario[],
): readonly GuardedReuseScenario[] {
  try {
    const snapshot = clonePlainData(
      source,
      new Set<object>(),
      { nodes: 0 },
      { nodes: 0 },
      0,
    );
    if (
      !Array.isArray(snapshot) ||
      !snapshot.every(
        (item) =>
          typeof item === "string" &&
          GUARDED_REUSE_SCENARIOS.includes(item as GuardedReuseScenario),
      )
    ) {
      throw new Error();
    }
    return snapshot as readonly GuardedReuseScenario[];
  } catch {
    throw new TypeError("Guarded reuse study configuration is invalid");
  }
}

function snapshotNormalizationContract(
  source: GuardedReuseNormalizationContract,
): GuardedReuseNormalizationContract {
  try {
    const snapshot = clonePlainData(
      source,
      new Set<object>(),
      { nodes: 0 },
      { nodes: 0 },
      0,
    ) as GuardedReuseNormalizationContract;
    if (!isNormalizationContract(snapshot)) throw new Error();
    return snapshot;
  } catch {
    throw new TypeError("Guarded reuse study configuration is invalid");
  }
}

function validateStudyInput(
  input: {
    readonly keyId: string;
    readonly cacheKeySecret: Uint8Array | string;
    readonly digester: KeyedHmacDigester;
    readonly datasetDigest: HmacEvidenceDigest;
    readonly sourceDigest: Sha256Digest;
    readonly sourceRevision: string;
    readonly requiredScenarios: readonly GuardedReuseScenario[];
    readonly normalizationContract: GuardedReuseNormalizationContract;
  },
  cases: readonly ObservationReuseCase[],
): void {
  if (
    cases.length < 1 ||
    cases.length > MAX_CASES ||
    !IDENTIFIER.test(input.keyId) ||
    !HMAC_EVIDENCE.test(input.datasetDigest) ||
    !SHA256.test(input.sourceDigest) ||
    !/^[a-f0-9]{40}$/u.test(input.sourceRevision) ||
    cacheKeySecretLength(input.cacheKeySecret) < 32 ||
    input.digester?.kind !== "keyed-hmac-sha256" ||
    input.digester.keyId !== input.keyId ||
    !isNormalizationContract(input.normalizationContract) ||
    !Array.isArray(input.requiredScenarios) ||
    new Set(input.requiredScenarios).size !== input.requiredScenarios.length
  ) {
    throw new TypeError("Guarded reuse study configuration is invalid");
  }
  if (
    input.requiredScenarios.some(
      (item) => !GUARDED_REUSE_SCENARIOS.includes(item),
    )
  ) {
    throw new TypeError("Guarded reuse study configuration is invalid");
  }
}

function cacheKeySecretLength(secret: unknown): number {
  if (typeof secret === "string") return Buffer.byteLength(secret, "utf8");
  return secret instanceof Uint8Array ? secret.byteLength : -1;
}

function isNormalizationContract(
  value: GuardedReuseNormalizationContract | undefined,
): value is GuardedReuseNormalizationContract {
  return (
    value !== undefined &&
    value !== null &&
    typeof value === "object" &&
    !isProxy(value) &&
    hasExactOwnKeys(value, [
      "minimumConfidencePpm",
      "normalizer",
      "policyDigest",
    ]) &&
    value.normalizer !== null &&
    typeof value.normalizer === "object" &&
    !isProxy(value.normalizer) &&
    hasExactOwnKeys(value.normalizer, [
      "artifactDigest",
      "configDigest",
      "id",
      "version",
    ]) &&
    NORMALIZER_ID.test(value.normalizer.id) &&
    NORMALIZER_VERSION.test(value.normalizer.version) &&
    SHA256.test(value.normalizer.artifactDigest) &&
    SHA256.test(value.normalizer.configDigest) &&
    SHA256.test(value.policyDigest) &&
    Number.isSafeInteger(value.minimumConfidencePpm) &&
    value.minimumConfidencePpm >= 0 &&
    value.minimumConfidencePpm <= 1_000_000
  );
}

function hasExactOwnKeys(value: object, expected: readonly string[]): boolean {
  const keys = Object.keys(value);
  return (
    keys.length === expected.length &&
    expected.every((key) => Object.hasOwn(value, key))
  );
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const nested of Object.values(value)) deepFreeze(nested);
  }
  return value;
}
