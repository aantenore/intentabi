import { createHash } from "node:crypto";

export const CODEX_BENCH_PLAN_SCHEMA =
  "io.github.aantenore.intentabi/codex-bench-plan/v1alpha1" as const;
export const CODEX_BENCH_RECEIPT_SCHEMA =
  "io.github.aantenore.intentabi/codex-bench-receipt/v1alpha1" as const;
export const BENCHMARK_CORE_IMPLEMENTATION =
  "io.github.aantenore.intentabi/benchmark-core/blocked-abba-receipt-hmac-v2" as const;

export type BenchmarkArm = "baseline" | "candidate";
export type BenchmarkStratum = "simple" | "medium" | "complex" | "adversarial";
export type BenchmarkCacheRegime = "cold" | "warm";
export type BenchmarkExecutionMode =
  "pinned-provider-boundary" | "injected-test-boundary";

export interface BenchmarkCase {
  readonly caseRef: `hmac-sha256:evidence:${string}`;
  readonly stratum: BenchmarkStratum;
  readonly cacheRegime: BenchmarkCacheRegime;
  readonly original: string;
  readonly candidate: string;
}

export interface BenchmarkPlanCase {
  readonly ordinal: number;
  readonly caseRef: BenchmarkCase["caseRef"];
  readonly stratum: BenchmarkStratum;
  readonly cacheRegime: BenchmarkCacheRegime;
  readonly order: readonly [BenchmarkArm, BenchmarkArm];
}

export interface BenchmarkPlan {
  readonly schema: typeof CODEX_BENCH_PLAN_SCHEMA;
  readonly classification: "research-conformance";
  readonly promotionEligible: false;
  /** Public identifier for the evidence HMAC key; never the key material. */
  readonly keyId: string;
  readonly datasetDigest: `hmac-sha256:evidence:${string}`;
  readonly protocolDigest: `sha256:${string}`;
  readonly cases: readonly BenchmarkPlanCase[];
}

export interface ProviderUsageObservation {
  /** Host observation of an SDK result, not a cryptographic provider receipt. */
  readonly provenance: "host-observed-codex-sdk-run-result";
  readonly inputTokens: number;
  readonly cachedInputTokens: number;
  readonly outputTokens: number;
  readonly reasoningOutputTokens: number;
}

export interface BenchmarkArmObservation {
  readonly usage: ProviderUsageObservation | null;
  readonly latencyMicros: number;
}

export interface BenchmarkArmRunner {
  /** Implementations must create a fresh provider thread for every call. */
  run(
    input: string,
    context: Readonly<{
      caseRef: BenchmarkCase["caseRef"];
      arm: BenchmarkArm;
    }>,
  ): Promise<BenchmarkArmObservation>;
}

export type BenchmarkFailureCode = "timeout" | "execution-failed";

export class BenchmarkArmFailure extends Error {
  constructor(readonly code: BenchmarkFailureCode) {
    super(code);
    this.name = "BenchmarkArmFailure";
  }
}

/** A host-side binding failure that must abort the whole benchmark. */
export class BenchmarkInvariantFailure extends Error {
  constructor(message = "benchmark-invariant-failed") {
    super(message);
    this.name = "BenchmarkInvariantFailure";
  }
}

export type BenchmarkArmReceipt =
  | Readonly<{
      status: "complete";
      usage: ProviderUsageObservation;
      latencyMicros: number;
    }>
  | Readonly<{
      status: "accounting-incomplete";
      reason: "usage-unavailable" | "usage-invalid";
      latencyMicros: number;
    }>
  | Readonly<{
      status: "execution-failed";
      reason: BenchmarkFailureCode;
    }>;

export interface BenchmarkCaseReceipt {
  readonly ordinal: number;
  readonly caseRef: BenchmarkCase["caseRef"];
  readonly stratum: BenchmarkStratum;
  readonly cacheRegime: BenchmarkCacheRegime;
  readonly order: readonly [BenchmarkArm, BenchmarkArm];
  readonly baseline: BenchmarkArmReceipt;
  readonly candidate: BenchmarkArmReceipt;
  /** Diagnostic only: it is not task quality, cost, or net-value evidence. */
  readonly observedInputTokenDelta?: number;
}

export interface BenchmarkReceipt {
  readonly schema: typeof CODEX_BENCH_RECEIPT_SCHEMA;
  readonly classification: "research-conformance";
  readonly promotionEligible: false;
  readonly promotionManifest: "not-produced";
  readonly runId: string;
  readonly executionMode: BenchmarkExecutionMode;
  /** Canonical HMAC over the complete receipt body, excluding this field. */
  readonly receiptMac: `hmac-sha256:evidence:${string}`;
  /** Public identifier for the evidence HMAC key; never the key material. */
  readonly keyId: BenchmarkPlan["keyId"];
  readonly datasetDigest: BenchmarkPlan["datasetDigest"];
  readonly protocolDigest: BenchmarkPlan["protocolDigest"];
  readonly executableDigest: `sha256:${string}`;
  readonly sdkVersion: string;
  readonly cliVersion: string;
  readonly cases: readonly BenchmarkCaseReceipt[];
  readonly summary: Readonly<{
    totalCases: number;
    completePairs: number;
    accountingIncompletePairs: number;
    executionFailedPairs: number;
    baselineInputTokens: string;
    candidateInputTokens: string;
    observedInputTokenDelta: string;
  }>;
}

export type UnsignedBenchmarkReceipt = Omit<BenchmarkReceipt, "receiptMac">;

export function createCounterbalancedPlan(input: {
  readonly cases: readonly BenchmarkCase[];
  readonly seed: string;
  readonly keyId: BenchmarkPlan["keyId"];
  readonly datasetDigest: BenchmarkPlan["datasetDigest"];
  readonly protocolDigest: BenchmarkPlan["protocolDigest"];
}): BenchmarkPlan {
  validatePlanInputs(input);
  const blockOrdinals = new Map<string, number>();
  const cases = input.cases.map((entry, ordinal) => {
    const block = `${entry.stratum}\0${entry.cacheRegime}`;
    const blockOrdinal = blockOrdinals.get(block) ?? 0;
    blockOrdinals.set(block, blockOrdinal + 1);
    const blockStartsWithCandidate =
      createHash("sha256")
        .update(input.seed)
        .update("\0")
        .update(block)
        .digest()[0]! %
        2 ===
      1;
    const candidateFirst =
      (blockOrdinal % 2 === 0) === blockStartsWithCandidate;
    return Object.freeze({
      ordinal,
      caseRef: entry.caseRef,
      stratum: entry.stratum,
      cacheRegime: entry.cacheRegime,
      order: Object.freeze(
        candidateFirst
          ? (["candidate", "baseline"] as const)
          : (["baseline", "candidate"] as const),
      ),
    });
  });
  return deepFreeze({
    schema: CODEX_BENCH_PLAN_SCHEMA,
    classification: "research-conformance",
    promotionEligible: false,
    keyId: input.keyId,
    datasetDigest: input.datasetDigest,
    protocolDigest: input.protocolDigest,
    cases,
  });
}

export async function runPairedBenchmark(input: {
  readonly plan: BenchmarkPlan;
  readonly cases: readonly BenchmarkCase[];
  readonly runner: BenchmarkArmRunner;
  readonly runId: string;
  readonly executionMode: BenchmarkExecutionMode;
  readonly keyId: BenchmarkPlan["keyId"];
  readonly executableDigest: BenchmarkReceipt["executableDigest"];
  readonly sdkVersion: string;
  readonly cliVersion: string;
  readonly authenticateReceipt: (
    receipt: UnsignedBenchmarkReceipt,
  ) => `hmac-sha256:evidence:${string}`;
}): Promise<BenchmarkReceipt> {
  validateExecutionInputs(input);
  const casesByRef = new Map(
    input.cases.map((entry) => [entry.caseRef, entry]),
  );
  if (
    input.plan.cases.length !== input.cases.length ||
    casesByRef.size !== input.cases.length
  ) {
    throw new TypeError("Benchmark plan and case set do not match");
  }

  const receipts: BenchmarkCaseReceipt[] = [];
  for (const [ordinal, planned] of input.plan.cases.entries()) {
    const benchmarkCase = casesByRef.get(planned.caseRef);
    if (
      benchmarkCase === undefined ||
      planned.ordinal !== ordinal ||
      planned.stratum !== benchmarkCase.stratum ||
      planned.cacheRegime !== benchmarkCase.cacheRegime ||
      !validOrder(planned.order)
    ) {
      throw new TypeError("Benchmark plan contains an unknown case reference");
    }
    const observed: Partial<Record<BenchmarkArm, BenchmarkArmReceipt>> = {};
    for (const arm of planned.order) {
      observed[arm] = await runArm(
        input.runner,
        arm === "baseline" ? benchmarkCase.original : benchmarkCase.candidate,
        { caseRef: benchmarkCase.caseRef, arm },
      );
    }
    const baseline = observed.baseline;
    const candidate = observed.candidate;
    if (baseline === undefined || candidate === undefined) {
      throw new TypeError("Benchmark arm execution was incomplete");
    }
    const delta =
      baseline.status === "complete" && candidate.status === "complete"
        ? baseline.usage.inputTokens - candidate.usage.inputTokens
        : undefined;
    receipts.push(
      deepFreeze({
        ordinal: planned.ordinal,
        caseRef: planned.caseRef,
        stratum: planned.stratum,
        cacheRegime: planned.cacheRegime,
        order: Object.freeze([planned.order[0], planned.order[1]] as const),
        baseline,
        candidate,
        ...(delta === undefined ? {} : { observedInputTokenDelta: delta }),
      }),
    );
  }

  const unsignedReceipt: UnsignedBenchmarkReceipt = deepFreeze({
    schema: CODEX_BENCH_RECEIPT_SCHEMA,
    classification: "research-conformance",
    promotionEligible: false,
    promotionManifest: "not-produced",
    runId: input.runId,
    executionMode: input.executionMode,
    keyId: input.keyId,
    datasetDigest: input.plan.datasetDigest,
    protocolDigest: input.plan.protocolDigest,
    executableDigest: input.executableDigest,
    sdkVersion: input.sdkVersion,
    cliVersion: input.cliVersion,
    cases: receipts,
    summary: summarize(receipts),
  });
  let receiptMac: string;
  try {
    receiptMac = input.authenticateReceipt(unsignedReceipt);
  } catch {
    throw new BenchmarkInvariantFailure(
      "Benchmark receipt authentication failed",
    );
  }
  if (!HMAC_PATTERN.test(receiptMac)) {
    throw new BenchmarkInvariantFailure(
      "Benchmark receipt authenticator returned an invalid MAC",
    );
  }
  return deepFreeze({
    ...unsignedReceipt,
    receiptMac: receiptMac as BenchmarkReceipt["receiptMac"],
  });
}

function summarize(cases: readonly BenchmarkCaseReceipt[]) {
  let completePairs = 0;
  let accountingIncompletePairs = 0;
  let executionFailedPairs = 0;
  let baselineInputTokens = 0n;
  let candidateInputTokens = 0n;
  for (const entry of cases) {
    const statuses = [entry.baseline.status, entry.candidate.status];
    if (statuses.includes("execution-failed")) {
      executionFailedPairs += 1;
    } else if (statuses.includes("accounting-incomplete")) {
      accountingIncompletePairs += 1;
    } else {
      completePairs += 1;
      baselineInputTokens += BigInt(
        (entry.baseline as Extract<BenchmarkArmReceipt, { status: "complete" }>)
          .usage.inputTokens,
      );
      candidateInputTokens += BigInt(
        (
          entry.candidate as Extract<
            BenchmarkArmReceipt,
            { status: "complete" }
          >
        ).usage.inputTokens,
      );
    }
  }
  return Object.freeze({
    totalCases: cases.length,
    completePairs,
    accountingIncompletePairs,
    executionFailedPairs,
    baselineInputTokens: baselineInputTokens.toString(),
    candidateInputTokens: candidateInputTokens.toString(),
    observedInputTokenDelta: (
      baselineInputTokens - candidateInputTokens
    ).toString(),
  });
}

async function runArm(
  runner: BenchmarkArmRunner,
  content: string,
  context: Readonly<{
    caseRef: BenchmarkCase["caseRef"];
    arm: BenchmarkArm;
  }>,
): Promise<BenchmarkArmReceipt> {
  try {
    const observed = await runner.run(content, context);
    if (!validLatency(observed.latencyMicros)) {
      return Object.freeze({
        status: "accounting-incomplete",
        reason: "usage-invalid",
        latencyMicros: 0,
      });
    }
    if (observed.usage === null) {
      return Object.freeze({
        status: "accounting-incomplete",
        reason: "usage-unavailable",
        latencyMicros: observed.latencyMicros,
      });
    }
    const usage = projectValidUsage(observed.usage);
    if (usage === null) {
      return Object.freeze({
        status: "accounting-incomplete",
        reason: "usage-invalid",
        latencyMicros: observed.latencyMicros,
      });
    }
    return deepFreeze({
      status: "complete",
      usage,
      latencyMicros: observed.latencyMicros,
    });
  } catch (error) {
    if (error instanceof BenchmarkInvariantFailure) throw error;
    return Object.freeze({
      status: "execution-failed",
      reason:
        error instanceof BenchmarkArmFailure
          ? error.code
          : ("execution-failed" as const),
    });
  }
}

function validLatency(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

function projectValidUsage(value: unknown): ProviderUsageObservation | null {
  if (typeof value !== "object" || value === null) return null;
  let descriptors: PropertyDescriptorMap;
  try {
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    return null;
  }
  const provenance = ownEnumerableDataValue(descriptors, "provenance");
  const inputTokens = ownEnumerableDataValue(descriptors, "inputTokens");
  const cachedInputTokens = ownEnumerableDataValue(
    descriptors,
    "cachedInputTokens",
  );
  const outputTokens = ownEnumerableDataValue(descriptors, "outputTokens");
  const reasoningOutputTokens = ownEnumerableDataValue(
    descriptors,
    "reasoningOutputTokens",
  );
  if (
    provenance !== "host-observed-codex-sdk-run-result" ||
    typeof inputTokens !== "number" ||
    typeof cachedInputTokens !== "number" ||
    typeof outputTokens !== "number" ||
    typeof reasoningOutputTokens !== "number"
  ) {
    return null;
  }
  const counters = [
    inputTokens,
    cachedInputTokens,
    outputTokens,
    reasoningOutputTokens,
  ];
  if (
    !counters.every((entry) => Number.isSafeInteger(entry) && entry >= 0) ||
    cachedInputTokens > inputTokens ||
    reasoningOutputTokens > outputTokens
  ) {
    return null;
  }
  return Object.freeze({
    provenance,
    inputTokens,
    cachedInputTokens,
    outputTokens,
    reasoningOutputTokens,
  });
}

function ownEnumerableDataValue(
  descriptors: PropertyDescriptorMap,
  key: string,
): unknown {
  const descriptor = descriptors[key];
  return descriptor !== undefined &&
    descriptor.enumerable === true &&
    "value" in descriptor
    ? descriptor.value
    : undefined;
}

const HMAC_PATTERN = /^hmac-sha256:evidence:[a-f0-9]{64}$/u;
const SHA_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const KEY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const VERSION_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$/u;
const UUID_V4_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const STRATA = new Set<BenchmarkStratum>([
  "simple",
  "medium",
  "complex",
  "adversarial",
]);
const CACHE_REGIMES = new Set<BenchmarkCacheRegime>(["cold", "warm"]);

function validatePlanInputs(input: {
  readonly cases: readonly BenchmarkCase[];
  readonly seed: string;
  readonly keyId: BenchmarkPlan["keyId"];
  readonly datasetDigest: BenchmarkPlan["datasetDigest"];
  readonly protocolDigest: BenchmarkPlan["protocolDigest"];
}): void {
  if (
    input.cases.length === 0 ||
    typeof input.seed !== "string" ||
    input.seed.length === 0 ||
    input.seed.length > 256 ||
    typeof input.keyId !== "string" ||
    !KEY_ID_PATTERN.test(input.keyId) ||
    !HMAC_PATTERN.test(input.datasetDigest) ||
    !SHA_PATTERN.test(input.protocolDigest)
  ) {
    throw new TypeError("Benchmark plan inputs are invalid");
  }
  const references = new Set<string>();
  for (const entry of input.cases) {
    if (
      !HMAC_PATTERN.test(entry.caseRef) ||
      references.has(entry.caseRef) ||
      !STRATA.has(entry.stratum) ||
      !CACHE_REGIMES.has(entry.cacheRegime) ||
      typeof entry.original !== "string" ||
      typeof entry.candidate !== "string" ||
      entry.original.length === 0 ||
      entry.candidate.length === 0 ||
      entry.original === entry.candidate
    ) {
      throw new TypeError("Benchmark case set is invalid");
    }
    references.add(entry.caseRef);
  }
}

function validateExecutionInputs(input: {
  readonly plan: BenchmarkPlan;
  readonly cases: readonly BenchmarkCase[];
  readonly runId: string;
  readonly executionMode: BenchmarkExecutionMode;
  readonly keyId: BenchmarkPlan["keyId"];
  readonly executableDigest: BenchmarkReceipt["executableDigest"];
  readonly sdkVersion: string;
  readonly cliVersion: string;
  readonly authenticateReceipt: (
    receipt: UnsignedBenchmarkReceipt,
  ) => `hmac-sha256:evidence:${string}`;
}): void {
  validatePlanInputs({
    cases: input.cases,
    seed: "validated-at-plan-boundary",
    keyId: input.plan.keyId,
    datasetDigest: input.plan.datasetDigest,
    protocolDigest: input.plan.protocolDigest,
  });
  if (
    input.plan.schema !== CODEX_BENCH_PLAN_SCHEMA ||
    input.plan.classification !== "research-conformance" ||
    input.plan.promotionEligible !== false ||
    (input.executionMode !== "pinned-provider-boundary" &&
      input.executionMode !== "injected-test-boundary") ||
    typeof input.keyId !== "string" ||
    !KEY_ID_PATTERN.test(input.keyId) ||
    input.plan.keyId !== input.keyId ||
    !UUID_V4_PATTERN.test(input.runId) ||
    !SHA_PATTERN.test(input.executableDigest) ||
    !VERSION_PATTERN.test(input.sdkVersion) ||
    !VERSION_PATTERN.test(input.cliVersion) ||
    input.sdkVersion !== input.cliVersion ||
    typeof input.authenticateReceipt !== "function"
  ) {
    throw new TypeError("Benchmark execution binding is invalid");
  }
  const references = new Set<string>();
  const casesByRef = new Map(
    input.cases.map((entry) => [entry.caseRef, entry]),
  );
  if (
    input.plan.cases.length !== input.cases.length ||
    casesByRef.size !== input.cases.length
  ) {
    throw new TypeError("Benchmark plan and case set do not match");
  }
  const blockOrders = new Map<
    string,
    { baselineFirst: number; candidateFirst: number }
  >();
  for (const [ordinal, planned] of input.plan.cases.entries()) {
    const benchmarkCase = casesByRef.get(planned.caseRef);
    if (
      planned.ordinal !== ordinal ||
      references.has(planned.caseRef) ||
      !HMAC_PATTERN.test(planned.caseRef) ||
      !STRATA.has(planned.stratum) ||
      !CACHE_REGIMES.has(planned.cacheRegime) ||
      !validOrder(planned.order) ||
      benchmarkCase === undefined ||
      planned.stratum !== benchmarkCase.stratum ||
      planned.cacheRegime !== benchmarkCase.cacheRegime
    ) {
      throw new TypeError("Benchmark plan structure is invalid");
    }
    references.add(planned.caseRef);
    const block = `${planned.stratum}\0${planned.cacheRegime}`;
    const counts = blockOrders.get(block) ?? {
      baselineFirst: 0,
      candidateFirst: 0,
    };
    if (planned.order[0] === "baseline") counts.baselineFirst += 1;
    else counts.candidateFirst += 1;
    blockOrders.set(block, counts);
  }
  for (const counts of blockOrders.values()) {
    if (Math.abs(counts.baselineFirst - counts.candidateFirst) > 1) {
      throw new TypeError("Benchmark plan is not block-counterbalanced");
    }
  }
}

function validOrder(value: readonly [BenchmarkArm, BenchmarkArm]): boolean {
  return (
    Array.isArray(value) &&
    value.length === 2 &&
    ((value[0] === "baseline" && value[1] === "candidate") ||
      (value[0] === "candidate" && value[1] === "baseline"))
  );
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}
