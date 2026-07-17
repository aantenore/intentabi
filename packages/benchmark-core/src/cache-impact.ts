import type {
  HmacEvidenceDigest,
  IntentInspection,
  IntentInspectionRequest,
  IntentInspector,
  Sha256Digest,
} from "@intentabi/core";

export const CACHE_IMPACT_REPORT_SCHEMA =
  "io.github.aantenore.intentabi/cache-impact-report/v1alpha1" as const;
export const CACHE_IMPACT_IMPLEMENTATION =
  "io.github.aantenore.intentabi/cache-impact/safe-hit-token-accounting-v1" as const;

const HMAC_PATTERN = /^hmac-sha256:evidence:[a-f0-9]{64}$/u;
const SHA_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const KEY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const REASON_PATTERN = /^[A-Z][A-Z0-9_]{0,63}$/u;
const MAX_CASES = 10_000;

export interface CacheImpactUsage {
  /** Tokens observed for the ordinary model request on a cache miss. */
  readonly modelInputTokens: number;
  /** Tokens observed for the ordinary model response on a cache miss. */
  readonly modelOutputTokens: number;
  /** Optional compiler/provider input overhead paid by normalization. */
  readonly normalizationInputTokens: number;
  /** Optional compiler/provider output overhead paid by normalization. */
  readonly normalizationOutputTokens: number;
}

export interface CacheImpactCase {
  /** Content-free case identity derived by the trusted host. */
  readonly caseRef: HmacEvidenceDigest;
  /** Exact-request cache key derived by the trusted host with keyed HMAC. */
  readonly rawKey: HmacEvidenceDigest;
  /** Host oracle for whether two candidate hits may reuse the same value. */
  readonly expectedValueDigest: Sha256Digest;
  readonly request: Omit<IntentInspectionRequest, "signal">;
  readonly usage: CacheImpactUsage;
}

export type CacheProbeOutcome = "miss" | "safe-hit" | "unsafe-hit";
export type CacheNormalizationOutcome =
  "eligible" | "bypass" | "inspector-failed" | "inspection-timeout";

export interface CacheImpactCaseResult {
  readonly ordinal: number;
  readonly caseRef: HmacEvidenceDigest;
  readonly normalization: CacheNormalizationOutcome;
  readonly raw: CacheProbeOutcome;
  readonly normalized: CacheProbeOutcome;
  readonly reasons: readonly string[];
}

export type CacheImpactGateReason =
  | "RAW_UNSAFE_HITS"
  | "NORMALIZED_UNSAFE_HITS"
  | "INSPECTION_FAILURES"
  | "NO_SAFE_HIT_LIFT"
  | "NO_POSITIVE_NET_TOKEN_DELTA";

export interface CacheImpactStrategyMetrics {
  readonly candidateHits: number;
  readonly safeHits: number;
  readonly unsafeHits: number;
  readonly misses: number;
  readonly safeHitRatePpm: number;
}

export interface UnsignedCacheImpactReport {
  readonly schema: typeof CACHE_IMPACT_REPORT_SCHEMA;
  readonly implementation: typeof CACHE_IMPACT_IMPLEMENTATION;
  readonly mode: "shadow";
  readonly classification: "diagnostic-cache-impact";
  readonly activationAuthorized: false;
  readonly promotionManifest: "not-produced";
  readonly keyId: string;
  readonly datasetDigest: HmacEvidenceDigest;
  readonly inspectionTimeoutMs: number;
  readonly cases: readonly CacheImpactCaseResult[];
  readonly summary: Readonly<{
    requests: number;
    normalization: Readonly<{
      eligible: number;
      bypassed: number;
      failed: number;
      timedOut: number;
    }>;
    raw: CacheImpactStrategyMetrics;
    normalized: CacheImpactStrategyMetrics;
    safeHitLift: number;
    safeHitRateLiftPpm: number;
    tokens: Readonly<{
      noCacheModelInput: string;
      noCacheModelOutput: string;
      rawModelInput: string;
      rawModelOutput: string;
      normalizedModelInput: string;
      normalizedModelOutput: string;
      normalizationInput: string;
      normalizationOutput: string;
      netInputDeltaVersusRaw: string;
      netOutputDeltaVersusRaw: string;
      netTotalDeltaVersusRaw: string;
    }>;
    gate: Readonly<{
      passed: boolean;
      reasons: readonly CacheImpactGateReason[];
    }>;
    statisticalReadiness: Readonly<{
      ready: false;
      reasons: readonly ["IID_SAMPLING_NOT_ATTESTED"];
    }>;
  }>;
}

export interface CacheImpactReport extends UnsignedCacheImpactReport {
  /** HMAC over the complete unsigned report, supplied by the trusted host. */
  readonly reportMac: HmacEvidenceDigest;
}

export async function runCacheImpactStudy(input: {
  readonly cases: readonly CacheImpactCase[];
  readonly inspector: IntentInspector;
  readonly keyId: string;
  readonly datasetDigest: HmacEvidenceDigest;
  readonly inspectionTimeoutMs: number;
  readonly authenticateReport: (
    report: UnsignedCacheImpactReport,
  ) => HmacEvidenceDigest;
}): Promise<CacheImpactReport> {
  const cases = snapshotCases(input.cases);
  if (
    cases.length === 0 ||
    cases.length > MAX_CASES ||
    !KEY_ID_PATTERN.test(input.keyId) ||
    !HMAC_PATTERN.test(input.datasetDigest) ||
    !Number.isSafeInteger(input.inspectionTimeoutMs) ||
    input.inspectionTimeoutMs < 1 ||
    input.inspectionTimeoutMs > 30_000 ||
    typeof input.inspector?.inspect !== "function" ||
    typeof input.authenticateReport !== "function"
  ) {
    throw new TypeError("Cache impact study configuration is invalid");
  }

  const rawCache = new Map<string, Sha256Digest>();
  const normalizedCache = new Map<string, Sha256Digest>();
  const results: CacheImpactCaseResult[] = [];
  let eligible = 0;
  let bypassed = 0;
  let failed = 0;
  let timedOut = 0;
  let noCacheModelInput = 0n;
  let noCacheModelOutput = 0n;
  let rawModelInput = 0n;
  let rawModelOutput = 0n;
  let normalizedModelInput = 0n;
  let normalizedModelOutput = 0n;
  let normalizationInput = 0n;
  let normalizationOutput = 0n;

  for (const [ordinal, item] of cases.entries()) {
    const observation = await inspectWithDeadline(
      input.inspector,
      item.request,
      input.inspectionTimeoutMs,
    );
    const raw = observe(rawCache, item.rawKey, item.expectedValueDigest);
    let normalizedKey: string = item.rawKey;
    let normalization: CacheNormalizationOutcome;
    let reasons: readonly string[];

    if (observation.status === "eligible") {
      eligible += 1;
      normalization = "eligible";
      normalizedKey = observation.intentKey;
      reasons = observation.reasons;
    } else if (observation.status === "bypass") {
      bypassed += 1;
      normalization = "bypass";
      reasons = observation.reasons;
    } else if (observation.status === "inspection-timeout") {
      timedOut += 1;
      normalization = "inspection-timeout";
      reasons = Object.freeze(["INSPECTION_TIMEOUT"]);
    } else {
      failed += 1;
      normalization = "inspector-failed";
      reasons = Object.freeze(["INSPECTOR_FAILURE"]);
    }

    const normalized = observe(
      normalizedCache,
      normalizedKey,
      item.expectedValueDigest,
    );
    const modelInput = BigInt(item.usage.modelInputTokens);
    const modelOutput = BigInt(item.usage.modelOutputTokens);
    noCacheModelInput += modelInput;
    noCacheModelOutput += modelOutput;
    normalizationInput += BigInt(item.usage.normalizationInputTokens);
    normalizationOutput += BigInt(item.usage.normalizationOutputTokens);
    if (raw !== "safe-hit") {
      rawModelInput += modelInput;
      rawModelOutput += modelOutput;
    }
    if (normalized !== "safe-hit") {
      normalizedModelInput += modelInput;
      normalizedModelOutput += modelOutput;
    }

    results.push(
      deepFreeze({
        ordinal,
        caseRef: item.caseRef,
        normalization,
        raw,
        normalized,
        reasons: Object.freeze([...reasons]),
      }),
    );
  }

  const raw = summarizeStrategy(results.map((item) => item.raw));
  const normalized = summarizeStrategy(results.map((item) => item.normalized));
  const normalizedTotalInput = normalizedModelInput + normalizationInput;
  const normalizedTotalOutput = normalizedModelOutput + normalizationOutput;
  const netInputDelta = rawModelInput - normalizedTotalInput;
  const netOutputDelta = rawModelOutput - normalizedTotalOutput;
  const netTotalDelta = netInputDelta + netOutputDelta;
  const gateReasons: CacheImpactGateReason[] = [];
  if (raw.unsafeHits > 0) gateReasons.push("RAW_UNSAFE_HITS");
  if (normalized.unsafeHits > 0) {
    gateReasons.push("NORMALIZED_UNSAFE_HITS");
  }
  if (failed + timedOut > 0) gateReasons.push("INSPECTION_FAILURES");
  if (normalized.safeHits <= raw.safeHits) {
    gateReasons.push("NO_SAFE_HIT_LIFT");
  }
  if (netTotalDelta <= 0n) {
    gateReasons.push("NO_POSITIVE_NET_TOKEN_DELTA");
  }

  const unsigned: UnsignedCacheImpactReport = deepFreeze({
    schema: CACHE_IMPACT_REPORT_SCHEMA,
    implementation: CACHE_IMPACT_IMPLEMENTATION,
    mode: "shadow",
    classification: "diagnostic-cache-impact",
    activationAuthorized: false,
    promotionManifest: "not-produced",
    keyId: input.keyId,
    datasetDigest: input.datasetDigest,
    inspectionTimeoutMs: input.inspectionTimeoutMs,
    cases: results,
    summary: {
      requests: results.length,
      normalization: { eligible, bypassed, failed, timedOut },
      raw,
      normalized,
      safeHitLift: normalized.safeHits - raw.safeHits,
      safeHitRateLiftPpm: normalized.safeHitRatePpm - raw.safeHitRatePpm,
      tokens: {
        noCacheModelInput: noCacheModelInput.toString(),
        noCacheModelOutput: noCacheModelOutput.toString(),
        rawModelInput: rawModelInput.toString(),
        rawModelOutput: rawModelOutput.toString(),
        normalizedModelInput: normalizedModelInput.toString(),
        normalizedModelOutput: normalizedModelOutput.toString(),
        normalizationInput: normalizationInput.toString(),
        normalizationOutput: normalizationOutput.toString(),
        netInputDeltaVersusRaw: netInputDelta.toString(),
        netOutputDeltaVersusRaw: netOutputDelta.toString(),
        netTotalDeltaVersusRaw: netTotalDelta.toString(),
      },
      gate: {
        passed: gateReasons.length === 0,
        reasons: gateReasons,
      },
      statisticalReadiness: {
        ready: false,
        reasons: ["IID_SAMPLING_NOT_ATTESTED"] as const,
      },
    },
  });

  let reportMac: string;
  try {
    reportMac = input.authenticateReport(unsigned);
  } catch {
    throw new TypeError("Cache impact report authentication failed");
  }
  if (!HMAC_PATTERN.test(reportMac)) {
    throw new TypeError(
      "Cache impact report authenticator returned invalid data",
    );
  }
  return deepFreeze({
    ...unsigned,
    reportMac: reportMac as HmacEvidenceDigest,
  });
}

type ProjectedInspection =
  | Readonly<{
      status: "eligible";
      intentKey: string;
      reasons: readonly string[];
    }>
  | Readonly<{ status: "bypass"; reasons: readonly string[] }>
  | Readonly<{ status: "inspector-failed" | "inspection-timeout" }>;

async function inspectWithDeadline(
  inspector: IntentInspector,
  request: Omit<IntentInspectionRequest, "signal">,
  timeoutMs: number,
): Promise<ProjectedInspection> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<"inspection-timeout">((resolvePromise) => {
    timer = setTimeout(() => {
      controller.abort();
      resolvePromise("inspection-timeout");
    }, timeoutMs);
    timer.unref?.();
  });
  const inspected = Promise.resolve()
    .then(() => inspector.inspect({ ...request, signal: controller.signal }))
    .then(projectInspection)
    .catch(() => ({ status: "inspector-failed" }) as const);
  const result = await Promise.race([inspected, timeout]);
  if (timer !== undefined) clearTimeout(timer);
  return result === "inspection-timeout"
    ? Object.freeze({ status: "inspection-timeout" })
    : result;
}

function projectInspection(value: IntentInspection): ProjectedInspection {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return Object.freeze({ status: "inspector-failed" });
  }
  let descriptors: PropertyDescriptorMap;
  try {
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    return Object.freeze({ status: "inspector-failed" });
  }
  const status = ownData(descriptors, "status");
  const reasons = projectReasons(ownData(descriptors, "reasons"));
  if (reasons === null) {
    return Object.freeze({ status: "inspector-failed" });
  }
  if (status === "bypass") {
    return Object.freeze({ status, reasons });
  }
  const intentKey = ownData(descriptors, "intentKey");
  if (
    status !== "eligible" ||
    typeof intentKey !== "string" ||
    !/^hmac-sha256:shadow-intent:[a-f0-9]{64}$/u.test(intentKey)
  ) {
    return Object.freeze({ status: "inspector-failed" });
  }
  return Object.freeze({ status, intentKey, reasons });
}

function projectReasons(value: unknown): readonly string[] | null {
  if (!Array.isArray(value) || value.length > 16) return null;
  const reasons: string[] = [];
  for (let index = 0; index < value.length; index += 1) {
    if (!(index in value)) return null;
    const reason = value[index];
    if (typeof reason !== "string" || !REASON_PATTERN.test(reason)) return null;
    reasons.push(reason);
  }
  return Object.freeze(reasons);
}

function ownData(descriptors: PropertyDescriptorMap, key: string): unknown {
  const descriptor = descriptors[key];
  return descriptor !== undefined &&
    descriptor.enumerable === true &&
    "value" in descriptor
    ? descriptor.value
    : undefined;
}

function observe(
  cache: Map<string, Sha256Digest>,
  key: string,
  expectedValueDigest: Sha256Digest,
): CacheProbeOutcome {
  const existing = cache.get(key);
  if (existing === undefined) {
    cache.set(key, expectedValueDigest);
    return "miss";
  }
  return existing === expectedValueDigest ? "safe-hit" : "unsafe-hit";
}

function summarizeStrategy(
  outcomes: readonly CacheProbeOutcome[],
): CacheImpactStrategyMetrics {
  const safeHits = outcomes.filter((item) => item === "safe-hit").length;
  const unsafeHits = outcomes.filter((item) => item === "unsafe-hit").length;
  const misses = outcomes.length - safeHits - unsafeHits;
  return Object.freeze({
    candidateHits: safeHits + unsafeHits,
    safeHits,
    unsafeHits,
    misses,
    safeHitRatePpm:
      outcomes.length === 0
        ? 0
        : Math.round((safeHits * 1_000_000) / outcomes.length),
  });
}

function snapshotCases(
  source: readonly CacheImpactCase[],
): readonly CacheImpactCase[] {
  if (!Array.isArray(source) || source.length > MAX_CASES) {
    throw new TypeError("Cache impact case set is invalid");
  }
  const seen = new Set<string>();
  return Object.freeze(
    source.map((item) => {
      if (
        item === null ||
        typeof item !== "object" ||
        !HMAC_PATTERN.test(item.caseRef) ||
        !HMAC_PATTERN.test(item.rawKey) ||
        !SHA_PATTERN.test(item.expectedValueDigest) ||
        seen.has(item.caseRef) ||
        !validUsage(item.usage) ||
        !validRequest(item.request)
      ) {
        throw new TypeError("Cache impact case set is invalid");
      }
      seen.add(item.caseRef);
      return deepFreeze({
        caseRef: item.caseRef,
        rawKey: item.rawKey,
        expectedValueDigest: item.expectedValueDigest,
        request: {
          source: item.request.source,
          locale: item.request.locale,
          scope: {
            tenant: item.request.scope.tenant,
            authorization: item.request.scope.authorization,
          },
          scopeEpoch: item.request.scopeEpoch,
          route: {
            id: item.request.route.id,
            revisionDigest: item.request.route.revisionDigest,
          },
          routeInput: structuredClone(item.request.routeInput),
        },
        usage: {
          modelInputTokens: item.usage.modelInputTokens,
          modelOutputTokens: item.usage.modelOutputTokens,
          normalizationInputTokens: item.usage.normalizationInputTokens,
          normalizationOutputTokens: item.usage.normalizationOutputTokens,
        },
      });
    }),
  );
}

function validUsage(value: CacheImpactUsage): boolean {
  return (
    value !== null &&
    typeof value === "object" &&
    [
      value.modelInputTokens,
      value.modelOutputTokens,
      value.normalizationInputTokens,
      value.normalizationOutputTokens,
    ].every((item) => Number.isSafeInteger(item) && item >= 0)
  );
}

function validRequest(value: Omit<IntentInspectionRequest, "signal">): boolean {
  return (
    value !== null &&
    typeof value === "object" &&
    typeof value.source === "string" &&
    value.source.length > 0 &&
    value.source.length <= 16_384 &&
    typeof value.locale === "string" &&
    /^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,4}$/u.test(value.locale) &&
    typeof value.scopeEpoch === "string" &&
    /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value.scopeEpoch) &&
    value.scope !== null &&
    typeof value.scope === "object" &&
    typeof value.scope.tenant === "string" &&
    value.scope.tenant.length > 0 &&
    typeof value.scope.authorization === "string" &&
    value.scope.authorization.length > 0 &&
    value.route !== null &&
    typeof value.route === "object" &&
    /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value.route.id) &&
    SHA_PATTERN.test(value.route.revisionDigest)
  );
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const entry of Object.values(value as Record<string, unknown>)) {
      deepFreeze(entry);
    }
  }
  return value;
}
