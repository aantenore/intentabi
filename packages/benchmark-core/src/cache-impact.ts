import type {
  HmacEvidenceDigest,
  IntentInspection,
  IntentInspectionRequest,
  IntentInspector,
  Sha256Digest,
} from "@intentabi/core";
import { isProxy } from "node:util/types";

export const CACHE_IMPACT_REPORT_SCHEMA =
  "io.github.aantenore.intentabi/cache-impact-report/v1alpha1" as const;
export const CACHE_IMPACT_IMPLEMENTATION =
  "io.github.aantenore.intentabi/cache-impact/safe-hit-token-accounting-v1" as const;

const HMAC_PATTERN = /^hmac-sha256:evidence:[a-f0-9]{64}$/u;
const SHA_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const KEY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const REASON_PATTERN = /^[A-Z][A-Z0-9_]{0,63}$/u;
const MAX_CASES = 10_000;
const MAX_ROUTE_INPUT_NODES = 100_000;
const MAX_ROUTE_INPUT_STRING_CODE_UNITS = 1024 * 1024;
const INVALID_JSON_SNAPSHOT = Symbol("invalid-json-snapshot");

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
  /** Keyed binding of the registry, adapter, policy, scope, and route map. */
  readonly normalizationBindingDigest: HmacEvidenceDigest;
  readonly inspectionTimeoutMs: number;
  readonly measurementProvenance: Readonly<{
    readonly workload: "host-supplied-unattested";
    readonly usage: "host-declared-unverified";
    readonly freshness: "not-modeled";
  }>;
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
  readonly normalizationBindingDigest: HmacEvidenceDigest;
  readonly inspectionTimeoutMs: number;
  readonly authenticateReport: (
    report: UnsignedCacheImpactReport,
  ) => HmacEvidenceDigest;
}): Promise<CacheImpactReport> {
  const cases = snapshotCases(input.cases);
  if (
    cases.length === 0 ||
    cases.length > MAX_CASES ||
    typeof input.keyId !== "string" ||
    !KEY_ID_PATTERN.test(input.keyId) ||
    typeof input.datasetDigest !== "string" ||
    !HMAC_PATTERN.test(input.datasetDigest) ||
    typeof input.normalizationBindingDigest !== "string" ||
    !HMAC_PATTERN.test(input.normalizationBindingDigest) ||
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
    normalizationBindingDigest: input.normalizationBindingDigest,
    inspectionTimeoutMs: input.inspectionTimeoutMs,
    measurementProvenance: {
      workload: "host-supplied-unattested",
      usage: "host-declared-unverified",
      freshness: "not-modeled",
    },
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
  if (typeof reportMac !== "string" || !HMAC_PATTERN.test(reportMac)) {
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
  let descriptors: Record<string, PropertyDescriptor>;
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
  const values = snapshotDenseArray(value, 16);
  if (values === null) return null;
  const reasons: string[] = [];
  for (const reason of values) {
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
  const values = snapshotDenseArray(source, MAX_CASES);
  if (values === null) {
    throw new TypeError("Cache impact case set is invalid");
  }
  const seen = new Set<string>();
  const result: CacheImpactCase[] = [];
  for (const value of values) {
    const item = snapshotRecord(value, [
      "caseRef",
      "expectedValueDigest",
      "rawKey",
      "request",
      "usage",
    ]);
    const caseRef = item?.caseRef;
    const rawKey = item?.rawKey;
    const expectedValueDigest = item?.expectedValueDigest;
    const request = snapshotRequest(item?.request);
    const usage = snapshotUsage(item?.usage);
    if (
      typeof caseRef !== "string" ||
      !HMAC_PATTERN.test(caseRef) ||
      typeof rawKey !== "string" ||
      !HMAC_PATTERN.test(rawKey) ||
      typeof expectedValueDigest !== "string" ||
      !SHA_PATTERN.test(expectedValueDigest) ||
      seen.has(caseRef) ||
      request === null ||
      usage === null
    ) {
      throw new TypeError("Cache impact case set is invalid");
    }
    seen.add(caseRef);
    result.push(
      deepFreeze({
        caseRef: caseRef as HmacEvidenceDigest,
        rawKey: rawKey as HmacEvidenceDigest,
        expectedValueDigest: expectedValueDigest as Sha256Digest,
        request,
        usage,
      }),
    );
  }
  return Object.freeze(result);
}

function snapshotUsage(value: unknown): CacheImpactUsage | null {
  const record = snapshotRecord(value, [
    "modelInputTokens",
    "modelOutputTokens",
    "normalizationInputTokens",
    "normalizationOutputTokens",
  ]);
  if (record === null) return null;
  const counters = [
    record.modelInputTokens,
    record.modelOutputTokens,
    record.normalizationInputTokens,
    record.normalizationOutputTokens,
  ];
  if (
    !counters.every(
      (item) =>
        typeof item === "number" && Number.isSafeInteger(item) && item >= 0,
    )
  ) {
    return null;
  }
  return Object.freeze({
    modelInputTokens: record.modelInputTokens as number,
    modelOutputTokens: record.modelOutputTokens as number,
    normalizationInputTokens: record.normalizationInputTokens as number,
    normalizationOutputTokens: record.normalizationOutputTokens as number,
  });
}

function snapshotRequest(
  value: unknown,
): Omit<IntentInspectionRequest, "signal"> | null {
  const request = snapshotRecord(value, [
    "locale",
    "route",
    "routeInput",
    "scope",
    "scopeEpoch",
    "source",
  ]);
  const scope = snapshotRecord(request?.scope, ["authorization", "tenant"]);
  const route = snapshotRecord(request?.route, ["id", "revisionDigest"]);
  if (
    request === null ||
    scope === null ||
    route === null ||
    typeof request.source !== "string" ||
    request.source.length === 0 ||
    request.source.length > 16_384 ||
    typeof request.locale !== "string" ||
    !/^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,4}$/u.test(request.locale) ||
    typeof request.scopeEpoch !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(request.scopeEpoch) ||
    typeof scope.tenant !== "string" ||
    scope.tenant.length === 0 ||
    scope.tenant.length > 256 ||
    typeof scope.authorization !== "string" ||
    scope.authorization.length === 0 ||
    scope.authorization.length > 256 ||
    typeof route.id !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(route.id) ||
    typeof route.revisionDigest !== "string" ||
    !SHA_PATTERN.test(route.revisionDigest)
  ) {
    return null;
  }
  const routeInput = snapshotJson(
    request.routeInput,
    { nodes: 0, stringCodeUnits: 0 },
    new Set(),
  );
  if (routeInput === INVALID_JSON_SNAPSHOT) return null;
  return deepFreeze({
    source: request.source,
    locale: request.locale,
    scope: {
      tenant: scope.tenant,
      authorization: scope.authorization,
    },
    scopeEpoch: request.scopeEpoch,
    route: {
      id: route.id,
      revisionDigest: route.revisionDigest as Sha256Digest,
    },
    routeInput,
  });
}

function snapshotRecord(
  value: unknown,
  expectedKeys: readonly string[],
): Record<string, unknown> | null {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    isProxy(value)
  ) {
    return null;
  }
  let prototype: object | null;
  let descriptors: PropertyDescriptorMap;
  try {
    prototype = Object.getPrototypeOf(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    return null;
  }
  if (prototype !== Object.prototype && prototype !== null) return null;
  const keys = Reflect.ownKeys(descriptors);
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key) => typeof key !== "string" || !expectedKeys.includes(key))
  ) {
    return null;
  }
  const result: Record<string, unknown> = Object.create(null);
  for (const key of expectedKeys) {
    const descriptor = descriptors[key];
    if (
      descriptor === undefined ||
      descriptor.enumerable !== true ||
      !("value" in descriptor)
    ) {
      return null;
    }
    result[key] = descriptor.value;
  }
  return result;
}

function snapshotDenseArray(
  value: unknown,
  maximumLength: number,
): readonly unknown[] | null {
  if (!Array.isArray(value) || isProxy(value)) return null;
  let descriptors: Record<string, PropertyDescriptor>;
  try {
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    return null;
  }
  const lengthDescriptor = descriptors.length;
  if (
    lengthDescriptor === undefined ||
    !("value" in lengthDescriptor) ||
    !Number.isSafeInteger(lengthDescriptor.value) ||
    lengthDescriptor.value < 0 ||
    lengthDescriptor.value > maximumLength
  ) {
    return null;
  }
  const length = lengthDescriptor.value as number;
  if (Reflect.ownKeys(descriptors).length !== length + 1) return null;
  const result: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (
      descriptor === undefined ||
      descriptor.enumerable !== true ||
      !("value" in descriptor)
    ) {
      return null;
    }
    result.push(descriptor.value);
  }
  return result;
}

function snapshotJson(
  value: unknown,
  budget: { nodes: number; stringCodeUnits: number },
  ancestors: Set<object>,
): unknown | typeof INVALID_JSON_SNAPSHOT {
  budget.nodes += 1;
  if (budget.nodes > MAX_ROUTE_INPUT_NODES) return INVALID_JSON_SNAPSHOT;
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "number") {
    return Number.isFinite(value) ? value : INVALID_JSON_SNAPSHOT;
  }
  if (typeof value === "string") {
    budget.stringCodeUnits += value.length;
    return budget.stringCodeUnits <= MAX_ROUTE_INPUT_STRING_CODE_UNITS
      ? value
      : INVALID_JSON_SNAPSHOT;
  }
  if (typeof value !== "object" || isProxy(value) || ancestors.has(value)) {
    return INVALID_JSON_SNAPSHOT;
  }
  ancestors.add(value);
  if (Array.isArray(value)) {
    const entries = snapshotDenseArray(value, MAX_ROUTE_INPUT_NODES);
    if (entries === null) {
      ancestors.delete(value);
      return INVALID_JSON_SNAPSHOT;
    }
    const result: unknown[] = [];
    for (const entry of entries) {
      const snapshot = snapshotJson(entry, budget, ancestors);
      if (snapshot === INVALID_JSON_SNAPSHOT) {
        ancestors.delete(value);
        return INVALID_JSON_SNAPSHOT;
      }
      result.push(snapshot);
    }
    ancestors.delete(value);
    return result;
  }

  let prototype: object | null;
  let descriptors: PropertyDescriptorMap;
  try {
    prototype = Object.getPrototypeOf(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    ancestors.delete(value);
    return INVALID_JSON_SNAPSHOT;
  }
  if (prototype !== Object.prototype && prototype !== null) {
    ancestors.delete(value);
    return INVALID_JSON_SNAPSHOT;
  }
  const keys = Reflect.ownKeys(descriptors);
  if (keys.some((key) => typeof key !== "string")) {
    ancestors.delete(value);
    return INVALID_JSON_SNAPSHOT;
  }
  const result: Record<string, unknown> = Object.create(null);
  for (const key of keys as string[]) {
    budget.stringCodeUnits += key.length;
    const descriptor = descriptors[key];
    if (
      budget.stringCodeUnits > MAX_ROUTE_INPUT_STRING_CODE_UNITS ||
      descriptor === undefined ||
      descriptor.enumerable !== true ||
      !("value" in descriptor)
    ) {
      ancestors.delete(value);
      return INVALID_JSON_SNAPSHOT;
    }
    const snapshot = snapshotJson(descriptor.value, budget, ancestors);
    if (snapshot === INVALID_JSON_SNAPSHOT) {
      ancestors.delete(value);
      return INVALID_JSON_SNAPSHOT;
    }
    result[key] = snapshot;
  }
  ancestors.delete(value);
  return result;
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
