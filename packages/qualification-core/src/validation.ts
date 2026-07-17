import { isProxy } from "node:util/types";

import {
  MAX_QUALIFICATION_CASES,
  QUALIFICATION_PLAN_SCHEMA,
  QualificationCancelledFailure,
  type AuthorityCaseBinding,
  type CreateQualificationPlanInput,
  type EvidenceHmac,
  type QualificationAuthorityProjection,
  type QualificationAuthority,
  type QualificationCacheRegime,
  type QualificationCase,
  type QualificationCaseRunner,
  type QualificationCohort,
  type QualificationDifficulty,
  type QualificationPairOrder,
  type QualificationPlan,
  type QualificationPlanCase,
  type RunQualificationInput,
  type Sha256Digest,
} from "./types.js";

const HMAC_PATTERN = /^hmac-sha256:evidence:[a-f0-9]{64}$/u;
const SHA_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const KEY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const AUTHORITY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}$/u;
const UUID_V4_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const COHORTS = new Set<QualificationCohort>(["population", "adversarial"]);
const DIFFICULTIES = new Set<QualificationDifficulty>([
  "simple",
  "medium",
  "complex",
  "adversarial",
]);
const CACHE_REGIMES = new Set<QualificationCacheRegime>(["cold", "warm"]);
const PAIR_ORDERS = new Set<QualificationPairOrder>([
  "ordinary-first",
  "candidate-first",
]);
const ABORTED_GETTER = Object.getOwnPropertyDescriptor(
  AbortSignal.prototype,
  "aborted",
)?.get;

interface ParsedQualificationCase<
  TPayload,
> extends QualificationCase<TPayload> {}

export function parseCreatePlanInput<TPayload>(
  value: CreateQualificationPlanInput<TPayload>,
): {
  readonly cases: readonly ParsedQualificationCase<TPayload>[];
  readonly seed: string;
  readonly keyId: string;
  readonly datasetDigest: EvidenceHmac;
  readonly protocolDigest: Sha256Digest;
} {
  const source = dataRecord(value, [
    "cases",
    "seed",
    "keyId",
    "datasetDigest",
    "protocolDigest",
  ]);
  const seed = source.seed;
  const keyId = source.keyId;
  if (
    typeof seed !== "string" ||
    seed.length === 0 ||
    seed.length > 256 ||
    typeof keyId !== "string" ||
    !KEY_ID_PATTERN.test(keyId) ||
    !isEvidenceHmac(source.datasetDigest) ||
    !isSha256Digest(source.protocolDigest)
  ) {
    throw new TypeError("Qualification plan inputs are invalid");
  }
  return Object.freeze({
    cases: parseCases<TPayload>(source.cases),
    seed,
    keyId,
    datasetDigest: source.datasetDigest,
    protocolDigest: source.protocolDigest,
  });
}

export function parseRunInput<TPayload, TAttestation, TArtifact>(
  value: RunQualificationInput<TPayload, TAttestation, TArtifact>,
): RunQualificationInput<TPayload, TAttestation, TArtifact> {
  const source = dataRecord(
    value,
    [
      "plan",
      "cases",
      "runner",
      "authority",
      "attestation",
      "runId",
      "executableDigest",
      "authenticateReceipt",
    ],
    ["signal"],
  );
  const signal =
    source.signal === undefined ? undefined : parseAbortSignal(source.signal);
  return Object.freeze({
    plan: source.plan as QualificationPlan,
    cases: source.cases as readonly QualificationCase<TPayload>[],
    runner: source.runner as QualificationCaseRunner<TPayload>,
    authority: source.authority as QualificationAuthority<
      TAttestation,
      TArtifact
    >,
    attestation: source.attestation as TAttestation,
    runId: source.runId as string,
    executableDigest: source.executableDigest as Sha256Digest,
    authenticateReceipt: source.authenticateReceipt as RunQualificationInput<
      TPayload,
      TAttestation,
      TArtifact
    >["authenticateReceipt"],
    ...(signal === undefined ? {} : { signal }),
  });
}

export function parseCases<TPayload>(
  value: unknown,
): readonly ParsedQualificationCase<TPayload>[] {
  const references = new Set<string>();
  let adversarialSeen = false;
  const cases = denseArray(value, MAX_QUALIFICATION_CASES, (entry) => {
    const source = dataRecord(entry, [
      "caseRef",
      "balanceCellRef",
      "cohort",
      "difficulty",
      "cacheRegime",
      "payload",
    ]);
    if (
      !isEvidenceHmac(source.caseRef) ||
      references.has(source.caseRef) ||
      !isEvidenceHmac(source.balanceCellRef) ||
      !isCohort(source.cohort) ||
      !isDifficulty(source.difficulty) ||
      !isCacheRegime(source.cacheRegime)
    ) {
      throw new TypeError("Qualification case set is invalid");
    }
    if (source.cohort === "adversarial") adversarialSeen = true;
    if (source.cohort === "population" && adversarialSeen) {
      throw new TypeError("Qualification cohorts are not contiguous");
    }
    references.add(source.caseRef);
    return Object.freeze({
      caseRef: source.caseRef,
      balanceCellRef: source.balanceCellRef,
      cohort: source.cohort,
      difficulty: source.difficulty,
      cacheRegime: source.cacheRegime,
      payload: source.payload as TPayload,
    });
  });
  if (cases.length === 0) {
    throw new TypeError("Qualification case set is empty");
  }
  return Object.freeze(cases);
}

export function parsePlan(value: unknown): QualificationPlan {
  const source = dataRecord(value, [
    "schema",
    "classification",
    "activationCeiling",
    "keyId",
    "datasetDigest",
    "protocolDigest",
    "cases",
  ]);
  if (
    source.schema !== QUALIFICATION_PLAN_SCHEMA ||
    source.classification !== "shadow-qualification" ||
    source.activationCeiling !== "shadow-only" ||
    typeof source.keyId !== "string" ||
    !KEY_ID_PATTERN.test(source.keyId) ||
    !isEvidenceHmac(source.datasetDigest) ||
    !isSha256Digest(source.protocolDigest)
  ) {
    throw new TypeError("Qualification plan is invalid");
  }

  const references = new Set<string>();
  const blockOrders = new Map<
    string,
    { ordinaryFirst: number; candidateFirst: number }
  >();
  let adversarialSeen = false;
  const cases = denseArray(
    source.cases,
    MAX_QUALIFICATION_CASES,
    (entry, ordinal) => {
      const parsed = parsePlanCase(entry);
      if (parsed.ordinal !== ordinal || references.has(parsed.caseRef)) {
        throw new TypeError("Qualification plan case order is invalid");
      }
      if (parsed.cohort === "adversarial") adversarialSeen = true;
      if (parsed.cohort === "population" && adversarialSeen) {
        throw new TypeError("Qualification plan cohorts are not contiguous");
      }
      references.add(parsed.caseRef);
      const block = qualificationBlock(parsed);
      const counts = blockOrders.get(block) ?? {
        ordinaryFirst: 0,
        candidateFirst: 0,
      };
      if (parsed.pairOrder === "ordinary-first") counts.ordinaryFirst += 1;
      else counts.candidateFirst += 1;
      blockOrders.set(block, counts);
      return parsed;
    },
  );
  if (cases.length === 0) throw new TypeError("Qualification plan is empty");
  for (const counts of blockOrders.values()) {
    if (Math.abs(counts.ordinaryFirst - counts.candidateFirst) > 1) {
      throw new TypeError("Qualification plan is not cell-counterbalanced");
    }
  }
  return Object.freeze({
    schema: QUALIFICATION_PLAN_SCHEMA,
    classification: "shadow-qualification",
    activationCeiling: "shadow-only",
    keyId: source.keyId,
    datasetDigest: source.datasetDigest,
    protocolDigest: source.protocolDigest,
    cases: Object.freeze(cases),
  });
}

function parsePlanCase(value: unknown): QualificationPlanCase {
  const source = dataRecord(value, [
    "ordinal",
    "caseRef",
    "balanceCellRef",
    "cohort",
    "difficulty",
    "cacheRegime",
    "pairOrder",
  ]);
  if (
    !isNonNegativeSafeInteger(source.ordinal) ||
    !isEvidenceHmac(source.caseRef) ||
    !isEvidenceHmac(source.balanceCellRef) ||
    !isCohort(source.cohort) ||
    !isDifficulty(source.difficulty) ||
    !isCacheRegime(source.cacheRegime) ||
    !isPairOrder(source.pairOrder)
  ) {
    throw new TypeError("Qualification plan case is invalid");
  }
  return Object.freeze({
    ordinal: source.ordinal,
    caseRef: source.caseRef,
    balanceCellRef: source.balanceCellRef,
    cohort: source.cohort,
    difficulty: source.difficulty,
    cacheRegime: source.cacheRegime,
    pairOrder: source.pairOrder,
  });
}

export function matchCasesToPlan<TPayload>(
  cases: readonly ParsedQualificationCase<TPayload>[],
  plan: QualificationPlan,
): void {
  if (cases.length !== plan.cases.length) {
    throw new TypeError("Qualification plan and case set do not match");
  }
  for (const [ordinal, item] of cases.entries()) {
    const planned = plan.cases[ordinal];
    if (
      planned === undefined ||
      item.caseRef !== planned.caseRef ||
      item.balanceCellRef !== planned.balanceCellRef ||
      item.cohort !== planned.cohort ||
      item.difficulty !== planned.difficulty ||
      item.cacheRegime !== planned.cacheRegime
    ) {
      throw new TypeError("Qualification plan and case set do not match");
    }
  }
}

export function parseAuthorityResult<TArtifact>(value: unknown): {
  readonly projection: QualificationAuthorityProjection;
  readonly artifact: TArtifact;
} {
  const source = dataRecord(value, ["projection", "artifact"]);
  return Object.freeze({
    projection: parseAuthorityProjection(source.projection),
    artifact: source.artifact as TArtifact,
  });
}

function parseAuthorityProjection(
  value: unknown,
): QualificationAuthorityProjection {
  const source = dataRecord(
    value,
    [
      "authority",
      "activationCeiling",
      "decision",
      "evidenceDigest",
      "bindingDigest",
      "reportDigest",
      "cases",
    ],
    ["qualificationDigest"],
  );
  const authority = dataRecord(source.authority, ["id", "version"]);
  if (
    typeof authority.id !== "string" ||
    !AUTHORITY_ID_PATTERN.test(authority.id) ||
    typeof authority.version !== "string" ||
    !AUTHORITY_ID_PATTERN.test(authority.version) ||
    source.activationCeiling !== "shadow-only" ||
    (source.decision !== "qualified" && source.decision !== "unqualified") ||
    !isSha256Digest(source.evidenceDigest) ||
    !isSha256Digest(source.bindingDigest) ||
    !isSha256Digest(source.reportDigest) ||
    (source.qualificationDigest !== undefined &&
      !isSha256Digest(source.qualificationDigest)) ||
    (source.decision === "qualified") !==
      (source.qualificationDigest !== undefined)
  ) {
    throw new TypeError("Qualification authority projection is invalid");
  }
  const cases = denseArray(
    source.cases,
    MAX_QUALIFICATION_CASES,
    parseAuthorityCaseBinding,
  );
  const recordDigests = new Set(cases.map((item) => item.recordDigest));
  const hasQualificationDigest = Object.hasOwn(source, "qualificationDigest");
  if (
    recordDigests.size !== cases.length ||
    (source.decision === "qualified") !== hasQualificationDigest
  ) {
    throw new TypeError("Qualification authority projection is invalid");
  }
  return Object.freeze({
    authority: Object.freeze({ id: authority.id, version: authority.version }),
    activationCeiling: "shadow-only",
    decision: source.decision,
    evidenceDigest: source.evidenceDigest,
    bindingDigest: source.bindingDigest,
    reportDigest: source.reportDigest,
    ...(source.qualificationDigest === undefined
      ? {}
      : { qualificationDigest: source.qualificationDigest }),
    cases: Object.freeze(cases),
  });
}

function parseAuthorityCaseBinding(value: unknown): AuthorityCaseBinding {
  const source = dataRecord(value, [
    "ordinal",
    "cohort",
    "difficulty",
    "cacheRegime",
    "pairOrder",
    "recordDigest",
  ]);
  if (
    !isNonNegativeSafeInteger(source.ordinal) ||
    !isCohort(source.cohort) ||
    !isDifficulty(source.difficulty) ||
    !isCacheRegime(source.cacheRegime) ||
    !isPairOrder(source.pairOrder) ||
    !isSha256Digest(source.recordDigest)
  ) {
    throw new TypeError("Qualification authority case binding is invalid");
  }
  return Object.freeze({
    ordinal: source.ordinal,
    cohort: source.cohort,
    difficulty: source.difficulty,
    cacheRegime: source.cacheRegime,
    pairOrder: source.pairOrder,
    recordDigest: source.recordDigest,
  });
}

export function matchAuthorityToPlan(
  projection: QualificationAuthorityProjection,
  plan: QualificationPlan,
): void {
  if (projection.cases.length !== plan.cases.length) {
    throw new TypeError("Qualification authority case count does not match");
  }
  for (const [ordinal, binding] of projection.cases.entries()) {
    const planned = plan.cases[ordinal];
    if (
      planned === undefined ||
      binding.ordinal !== planned.ordinal ||
      binding.cohort !== planned.cohort ||
      binding.difficulty !== planned.difficulty ||
      binding.cacheRegime !== planned.cacheRegime ||
      binding.pairOrder !== planned.pairOrder
    ) {
      throw new TypeError(
        "Qualification authority binding does not match plan",
      );
    }
  }
}

export function validateExecutionBinding(
  runId: unknown,
  executableDigest: unknown,
  authenticateReceipt: unknown,
): void {
  if (
    typeof runId !== "string" ||
    !UUID_V4_PATTERN.test(runId) ||
    !isSha256Digest(executableDigest) ||
    typeof authenticateReceipt !== "function" ||
    isProxy(authenticateReceipt)
  ) {
    throw new TypeError("Qualification execution binding is invalid");
  }
}

export function isEvidenceHmac(value: unknown): value is EvidenceHmac {
  return typeof value === "string" && HMAC_PATTERN.test(value);
}

export function isSha256Digest(value: unknown): value is Sha256Digest {
  return typeof value === "string" && SHA_PATTERN.test(value);
}

export function qualificationBlock(
  value: Pick<
    QualificationPlanCase,
    "cohort" | "difficulty" | "cacheRegime" | "balanceCellRef"
  >,
): string {
  return `${value.cohort}\0${value.difficulty}\0${value.cacheRegime}\0${value.balanceCellRef}`;
}

export function dataMethod(value: unknown, key: string): Function {
  if (
    (typeof value !== "object" && typeof value !== "function") ||
    value === null ||
    isProxy(value)
  ) {
    throw new TypeError("Qualification port is invalid");
  }
  let cursor: object | null = value;
  for (let depth = 0; cursor !== null && depth < 8; depth += 1) {
    if (cursor === Object.prototype || cursor === Function.prototype) break;
    if (isProxy(cursor)) throw new TypeError("Qualification port is invalid");
    const descriptor = Object.getOwnPropertyDescriptor(cursor, key);
    if (descriptor !== undefined) {
      if (
        !("value" in descriptor) ||
        typeof descriptor.value !== "function" ||
        isProxy(descriptor.value)
      ) {
        throw new TypeError("Qualification port method is invalid");
      }
      return descriptor.value;
    }
    cursor = Object.getPrototypeOf(cursor) as object | null;
  }
  throw new TypeError("Qualification port method is missing");
}

export function throwIfQualificationCancelled(
  signal: AbortSignal | undefined,
): void {
  if (signal !== undefined && readAborted(signal)) {
    throw new QualificationCancelledFailure();
  }
}

function parseAbortSignal(value: unknown): AbortSignal {
  if (
    typeof value !== "object" ||
    value === null ||
    isProxy(value) ||
    ABORTED_GETTER === undefined
  ) {
    throw new TypeError("Qualification cancellation signal is invalid");
  }
  try {
    Reflect.apply(ABORTED_GETTER, value, []);
  } catch {
    throw new TypeError("Qualification cancellation signal is invalid");
  }
  return value as AbortSignal;
}

function readAborted(signal: AbortSignal): boolean {
  if (ABORTED_GETTER === undefined) {
    throw new TypeError("Qualification cancellation signal is invalid");
  }
  try {
    return Reflect.apply(ABORTED_GETTER, signal, []) as boolean;
  } catch {
    throw new TypeError("Qualification cancellation signal is invalid");
  }
}

function dataRecord(
  value: unknown,
  required: readonly string[],
  optional: readonly string[] = [],
): Readonly<Record<string, unknown>> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    isProxy(value)
  ) {
    throw new TypeError("Qualification record is invalid");
  }
  const prototype = Object.getPrototypeOf(value) as object | null;
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError("Qualification record prototype is invalid");
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const actualKeys = Reflect.ownKeys(descriptors);
  const allowed = new Set([...required, ...optional]);
  if (
    actualKeys.some((key) => typeof key !== "string" || !allowed.has(key)) ||
    required.some((key) => !actualKeys.includes(key))
  ) {
    throw new TypeError("Qualification record fields are invalid");
  }
  const result: Record<string, unknown> = {};
  for (const key of actualKeys) {
    if (typeof key !== "string") {
      throw new TypeError("Qualification record fields are invalid");
    }
    const descriptor = descriptors[key];
    if (
      descriptor === undefined ||
      descriptor.enumerable !== true ||
      !("value" in descriptor)
    ) {
      throw new TypeError("Qualification record field is not plain data");
    }
    result[key] = descriptor.value;
  }
  return Object.freeze(result);
}

function denseArray<T>(
  value: unknown,
  maximum: number,
  project: (entry: unknown, ordinal: number) => T,
): T[] {
  if (typeof value !== "object" || value === null || isProxy(value)) {
    throw new TypeError("Qualification array is invalid");
  }
  if (
    !Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Array.prototype
  ) {
    throw new TypeError("Qualification array is invalid");
  }
  const descriptors = Object.getOwnPropertyDescriptors(
    value,
  ) as unknown as PropertyDescriptorMap;
  const lengthDescriptor = descriptors["length"];
  if (
    lengthDescriptor === undefined ||
    !("value" in lengthDescriptor) ||
    !Number.isSafeInteger(lengthDescriptor.value) ||
    lengthDescriptor.value < 0 ||
    lengthDescriptor.value > maximum
  ) {
    throw new TypeError("Qualification array length is invalid");
  }
  const length = lengthDescriptor.value as number;
  const keys = Reflect.ownKeys(descriptors);
  if (
    keys.length !== length + 1 ||
    keys.some(
      (key) =>
        key !== "length" &&
        (typeof key !== "string" || !/^(?:0|[1-9][0-9]*)$/u.test(key)),
    )
  ) {
    throw new TypeError("Qualification array is sparse or extended");
  }
  const result: T[] = [];
  for (let ordinal = 0; ordinal < length; ordinal += 1) {
    const descriptor = descriptors[String(ordinal)];
    if (
      descriptor === undefined ||
      descriptor.enumerable !== true ||
      !("value" in descriptor)
    ) {
      throw new TypeError("Qualification array item is not plain data");
    }
    result.push(project(descriptor.value, ordinal));
  }
  return result;
}

function isCohort(value: unknown): value is QualificationCohort {
  return typeof value === "string" && COHORTS.has(value as QualificationCohort);
}

function isDifficulty(value: unknown): value is QualificationDifficulty {
  return (
    typeof value === "string" &&
    DIFFICULTIES.has(value as QualificationDifficulty)
  );
}

function isCacheRegime(value: unknown): value is QualificationCacheRegime {
  return (
    typeof value === "string" &&
    CACHE_REGIMES.has(value as QualificationCacheRegime)
  );
}

function isPairOrder(value: unknown): value is QualificationPairOrder {
  return (
    typeof value === "string" &&
    PAIR_ORDERS.has(value as QualificationPairOrder)
  );
}

function isNonNegativeSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}
