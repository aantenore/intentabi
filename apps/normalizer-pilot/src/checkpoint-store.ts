import { createHash } from "node:crypto";

import type {
  PrivateRunStore,
  PrivateRunStorePartition,
} from "@intentabi/private-run-store";
import {
  INTENT_EVALUATION_CHECKPOINT_CLAIM_SCHEMA,
  INTENT_EVALUATION_CHECKPOINT_SCHEMA,
  INTENT_REASON_CODES,
  type IntentEvaluationCheckpoint,
  type IntentEvaluationCheckpointClaim,
  type IntentEvaluationCheckpointStore,
} from "semwitness/intent";

export const NORMALIZER_PILOT_RUN_BINDING_FILE =
  "normalizer-pilot-run-binding.json" as const;
export const NORMALIZER_PILOT_CHECKPOINT_PARTITIONS = Object.freeze([
  "claims",
  "checkpoints",
] as const);

const SHA256_DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const CHECKPOINT_FILE_PATTERN = /^[a-f0-9]{64}\.json$/u;
const intentReasonCodes: ReadonlySet<string> = new Set(INTENT_REASON_CODES);
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

type JsonPrimitive = null | boolean | number | string;
type JsonValue =
  JsonPrimitive | readonly JsonValue[] | { readonly [key: string]: JsonValue };

interface CreateNormalizerPilotCheckpointStoreInput {
  readonly store: PrivateRunStore;
  readonly maximumBytes: number;
}

/** A deliberately content-free checkpoint boundary error. */
export class NormalizerPilotCheckpointStoreError extends Error {
  constructor() {
    super("Normalizer pilot checkpoint store failed");
    this.name = "NormalizerPilotCheckpointStoreError";
  }
}

/**
 * Adapts an already-open private run directory to SemWitness' append-only
 * checkpoint protocol. Claims are never leased or stolen: a durable claim
 * without a durable checkpoint is permanently indeterminate.
 */
export function createNormalizerPilotCheckpointStore(
  input: CreateNormalizerPilotCheckpointStoreInput,
): IntentEvaluationCheckpointStore {
  try {
    assertMaximumBytes(input.maximumBytes);
    const claims = input.store.partition("claims");
    const checkpoints = input.store.partition("checkpoints");

    return Object.freeze({
      inspect: async (claimInput: IntentEvaluationCheckpointClaim) =>
        checkpointBoundary(() =>
          inspectCheckpoint(
            claims,
            checkpoints,
            validateClaim(claimInput),
            input.maximumBytes,
          ),
        ),
      begin: async (claimInput: IntentEvaluationCheckpointClaim) =>
        checkpointBoundary(async () => {
          const claim = validateClaim(claimInput);
          const current = await inspectCheckpoint(
            claims,
            checkpoints,
            claim,
            input.maximumBytes,
          );
          if (current.status !== "missing") return current;

          const fileName = checkpointFileName(claim.checkpointRef);
          const claimBytes = encodeRecord(claim);
          const created = await claims.create(
            fileName,
            claimBytes,
            input.maximumBytes,
          );
          if (created === "exists") {
            const raced = await inspectCheckpoint(
              claims,
              checkpoints,
              claim,
              input.maximumBytes,
            );
            return raced.status === "missing"
              ? ({ status: "indeterminate" } as const)
              : raced;
          }

          return Object.freeze({
            status: "acquired" as const,
            commit: async (checkpointInput: IntentEvaluationCheckpoint) =>
              checkpointBoundary(async () => {
                const persistedClaim = await readClaim(
                  claims,
                  fileName,
                  input.maximumBytes,
                );
                if (
                  persistedClaim === null ||
                  !sameClaim(persistedClaim, claim)
                ) {
                  throw new NormalizerPilotCheckpointStoreError();
                }
                const checkpoint = validateCheckpoint(checkpointInput, claim);
                await checkpoints.publishOrVerify(
                  fileName,
                  encodeRecord(checkpoint),
                  input.maximumBytes,
                );
              }),
          });
        }),
    });
  } catch {
    throw new NormalizerPilotCheckpointStoreError();
  }
}

async function inspectCheckpoint(
  claims: PrivateRunStorePartition,
  checkpoints: PrivateRunStorePartition,
  expectedClaim: IntentEvaluationCheckpointClaim,
  maximumBytes: number,
) {
  const fileName = checkpointFileName(expectedClaim.checkpointRef);

  // Checkpoint first: a checkpoint can only be published after its claim. If
  // the claim appears between these reads, returning indeterminate is safe;
  // reading in the opposite order could misdiagnose a valid concurrent commit.
  const checkpoint = await readCheckpoint(
    checkpoints,
    fileName,
    expectedClaim,
    maximumBytes,
  );
  const claim = await readClaim(claims, fileName, maximumBytes);
  if (checkpoint !== null) {
    if (claim === null || !sameClaim(claim, expectedClaim)) {
      throw new NormalizerPilotCheckpointStoreError();
    }
    return Object.freeze({ status: "completed" as const, checkpoint });
  }
  if (claim === null) return Object.freeze({ status: "missing" as const });
  if (!sameClaim(claim, expectedClaim)) {
    throw new NormalizerPilotCheckpointStoreError();
  }
  return Object.freeze({ status: "indeterminate" as const });
}

async function readClaim(
  partition: PrivateRunStorePartition,
  fileName: string,
  maximumBytes: number,
): Promise<IntentEvaluationCheckpointClaim | null> {
  const value = await readRecord(partition, fileName, maximumBytes);
  return value === null ? null : validateClaim(value);
}

async function readCheckpoint(
  partition: PrivateRunStorePartition,
  fileName: string,
  claim: IntentEvaluationCheckpointClaim,
  maximumBytes: number,
): Promise<IntentEvaluationCheckpoint | null> {
  const value = await readRecord(partition, fileName, maximumBytes);
  return value === null ? null : validateCheckpoint(value, claim);
}

async function readRecord(
  partition: PrivateRunStorePartition,
  fileName: string,
  maximumBytes: number,
): Promise<unknown | null> {
  if (!CHECKPOINT_FILE_PATTERN.test(fileName)) {
    throw new NormalizerPilotCheckpointStoreError();
  }
  const bytes = await partition.readOptional(fileName, maximumBytes);
  if (bytes === null) return null;
  let value: unknown;
  try {
    value = JSON.parse(textDecoder.decode(bytes)) as unknown;
  } catch {
    throw new NormalizerPilotCheckpointStoreError();
  }
  const canonical = encodeRecord(cloneJson(value));
  if (!equalBytes(bytes, canonical)) {
    throw new NormalizerPilotCheckpointStoreError();
  }
  return value;
}

function validateClaim(value: unknown): IntentEvaluationCheckpointClaim {
  const claim = plainRecord(cloneJson(value));
  exactKeys(claim, [
    "schema",
    "checkpointRef",
    "evaluationBindingDigest",
    "caseRef",
    "attemptOrdinal",
    "claimDigest",
  ]);
  if (
    claim.schema !== INTENT_EVALUATION_CHECKPOINT_CLAIM_SCHEMA ||
    !isSha256Digest(claim.checkpointRef) ||
    !isSha256Digest(claim.evaluationBindingDigest) ||
    !isSha256Digest(claim.caseRef) ||
    !isAttemptOrdinal(claim.attemptOrdinal) ||
    !isSha256Digest(claim.claimDigest)
  ) {
    throw new NormalizerPilotCheckpointStoreError();
  }
  const payload = {
    schema: claim.schema,
    checkpointRef: claim.checkpointRef,
    evaluationBindingDigest: claim.evaluationBindingDigest,
    caseRef: claim.caseRef,
    attemptOrdinal: claim.attemptOrdinal,
  } as const;
  if (claim.claimDigest !== hashCanonical(payload)) {
    throw new NormalizerPilotCheckpointStoreError();
  }
  return Object.freeze({ ...payload, claimDigest: claim.claimDigest });
}

function validateCheckpoint(
  value: unknown,
  claim: IntentEvaluationCheckpointClaim,
): IntentEvaluationCheckpoint {
  const checkpoint = plainRecord(cloneJson(value));
  exactKeys(checkpoint, [
    "schema",
    "mode",
    "activeCacheQualified",
    "checkpointRef",
    "evaluationBindingDigest",
    "caseRef",
    "attemptOrdinal",
    "observation",
    "recordDigest",
  ]);
  if (
    checkpoint.schema !== INTENT_EVALUATION_CHECKPOINT_SCHEMA ||
    checkpoint.mode !== "shadow" ||
    checkpoint.activeCacheQualified !== false ||
    !isSha256Digest(checkpoint.checkpointRef) ||
    !isSha256Digest(checkpoint.evaluationBindingDigest) ||
    !isSha256Digest(checkpoint.caseRef) ||
    !isAttemptOrdinal(checkpoint.attemptOrdinal) ||
    !isSha256Digest(checkpoint.recordDigest) ||
    checkpoint.checkpointRef !== claim.checkpointRef ||
    checkpoint.evaluationBindingDigest !== claim.evaluationBindingDigest ||
    checkpoint.caseRef !== claim.caseRef ||
    checkpoint.attemptOrdinal !== claim.attemptOrdinal
  ) {
    throw new NormalizerPilotCheckpointStoreError();
  }
  const observation = validateContentFreeObservation(checkpoint.observation);
  const payload = {
    schema: checkpoint.schema,
    mode: checkpoint.mode,
    activeCacheQualified: checkpoint.activeCacheQualified,
    checkpointRef: checkpoint.checkpointRef,
    evaluationBindingDigest: checkpoint.evaluationBindingDigest,
    caseRef: checkpoint.caseRef,
    attemptOrdinal: checkpoint.attemptOrdinal,
    observation,
  } as const;
  if (checkpoint.recordDigest !== hashCanonical(payload)) {
    throw new NormalizerPilotCheckpointStoreError();
  }
  return Object.freeze({ ...payload, recordDigest: checkpoint.recordDigest });
}

function validateContentFreeObservation(value: unknown) {
  const observation = plainRecord(value);
  const keys = [
    "actual",
    "fingerprint",
    "reasons",
    "executionFailure",
    "contractDigest",
    "normalizerBindingDigest",
    "ontologyBindingDigest",
    ...(observation.intentDigest === undefined ? [] : ["intentDigest"]),
  ];
  exactKeys(observation, keys);
  if (
    (observation.actual !== "intent" && observation.actual !== "bypass") ||
    (observation.fingerprint !== "failure:INTENT_COMPILER_FAILURE" &&
      !isSha256Digest(observation.fingerprint)) ||
    !Array.isArray(observation.reasons) ||
    observation.reasons.length < 1 ||
    observation.reasons.some(
      (reason) => typeof reason !== "string" || !intentReasonCodes.has(reason),
    ) ||
    new Set(observation.reasons).size !== observation.reasons.length ||
    typeof observation.executionFailure !== "boolean" ||
    !isSha256Digest(observation.contractDigest) ||
    !isSha256Digest(observation.normalizerBindingDigest) ||
    !isSha256Digest(observation.ontologyBindingDigest) ||
    (observation.intentDigest !== undefined &&
      !isSha256Digest(observation.intentDigest))
  ) {
    throw new NormalizerPilotCheckpointStoreError();
  }
  return Object.freeze({
    actual: observation.actual,
    fingerprint: observation.fingerprint,
    ...(observation.intentDigest === undefined
      ? {}
      : { intentDigest: observation.intentDigest }),
    reasons: Object.freeze([...observation.reasons]),
    executionFailure: observation.executionFailure,
    contractDigest: observation.contractDigest,
    normalizerBindingDigest: observation.normalizerBindingDigest,
    ontologyBindingDigest: observation.ontologyBindingDigest,
  });
}

function sameClaim(
  left: IntentEvaluationCheckpointClaim,
  right: IntentEvaluationCheckpointClaim,
): boolean {
  return (
    left.schema === right.schema &&
    left.checkpointRef === right.checkpointRef &&
    left.evaluationBindingDigest === right.evaluationBindingDigest &&
    left.caseRef === right.caseRef &&
    left.attemptOrdinal === right.attemptOrdinal &&
    left.claimDigest === right.claimDigest
  );
}

function checkpointFileName(checkpointRef: unknown): string {
  if (!isSha256Digest(checkpointRef)) {
    throw new NormalizerPilotCheckpointStoreError();
  }
  const fileName = `${checkpointRef.slice(7)}.json`;
  if (!CHECKPOINT_FILE_PATTERN.test(fileName)) {
    throw new NormalizerPilotCheckpointStoreError();
  }
  return fileName;
}

function cloneJson(value: unknown): JsonValue {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string"
  ) {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new NormalizerPilotCheckpointStoreError();
    }
    return Object.is(value, -0) ? 0 : value;
  }
  if (Array.isArray(value)) {
    return Object.freeze(value.map((item) => cloneJson(item)));
  }
  const record = plainRecord(value);
  if (Object.getOwnPropertySymbols(record).length > 0) {
    throw new NormalizerPilotCheckpointStoreError();
  }
  const clone: Record<string, JsonValue> = Object.create(null) as Record<
    string,
    JsonValue
  >;
  const descriptors = Object.getOwnPropertyDescriptors(record);
  for (const key of Object.keys(descriptors).sort()) {
    const descriptor = descriptors[key];
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true ||
      descriptor.value === undefined
    ) {
      throw new NormalizerPilotCheckpointStoreError();
    }
    clone[key] = cloneJson(descriptor.value);
  }
  return Object.freeze(clone);
}

function plainRecord(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new NormalizerPilotCheckpointStoreError();
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new NormalizerPilotCheckpointStoreError();
  }
  return value as Record<string, unknown>;
}

function exactKeys(
  value: Readonly<Record<string, unknown>>,
  expected: readonly string[],
): void {
  const actual = Object.keys(value).sort();
  const required = [...expected].sort();
  if (
    actual.length !== required.length ||
    actual.some((key, index) => key !== required[index])
  ) {
    throw new NormalizerPilotCheckpointStoreError();
  }
}

function hashCanonical(value: JsonValue): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(canonicalJson(value), "utf8").digest("hex")}`;
}

function canonicalJson(value: JsonValue): string {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string" ||
    typeof value === "number"
  ) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  const record = value as { readonly [key: string]: JsonValue };
  return `{${Object.keys(record)
    .sort()
    .map(
      (key) =>
        `${JSON.stringify(key)}:${canonicalJson(record[key] as JsonValue)}`,
    )
    .join(",")}}`;
}

function encodeRecord(value: unknown): Uint8Array {
  return textEncoder.encode(`${canonicalJson(cloneJson(value))}\n`);
}

function isSha256Digest(value: unknown): value is `sha256:${string}` {
  return typeof value === "string" && SHA256_DIGEST_PATTERN.test(value);
}

function isAttemptOrdinal(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function assertMaximumBytes(value: number): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new NormalizerPilotCheckpointStoreError();
  }
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  return left.every((value, index) => value === right[index]);
}

async function checkpointBoundary<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch {
    throw new NormalizerPilotCheckpointStoreError();
  }
}
