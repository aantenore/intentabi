import { timingSafeEqual } from "node:crypto";

import type { HmacEvidenceDigest, KeyedHmacDigester } from "@intentabi/core";

import {
  CODEX_SHADOW_EVIDENCE_ENVELOPE_SCHEMA,
  CODEX_SHADOW_EVIDENCE_SCHEMA,
  type AuthenticatedCodexShadowEvidence,
  type CodexPreparationOutcome,
  type CodexPreparationReason,
  type CodexShadowEvidence,
} from "./types.js";

const HMAC_PATTERN = /^hmac-sha256:evidence:[a-f0-9]{64}$/u;
const KEY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const UUID_V4_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

const OUTCOMES = new Set<CodexPreparationOutcome>([
  "candidate-observed",
  "identity",
  "bypass",
  "preparer-fault",
  "preparer-timeout",
  "invalid-preparer-result",
]);

const REASONS = new Set<CodexPreparationReason>([
  "CANDIDATE_ATTESTED",
  "IDENTITY_ATTESTED",
  "NON_TEXT_INPUT",
  "REQUEST_ID_INVALID",
  "INPUT_LIMIT_EXCEEDED",
  "PREPARATION_TIMEOUT_UNCANCELLED",
  "PREPARER_FAULT",
  "PREPARER_RESULT_INVALID",
]);

export interface CodexEvidenceReplayClaim {
  readonly schema: typeof CODEX_SHADOW_EVIDENCE_ENVELOPE_SCHEMA;
  readonly keyId: string;
  readonly eventId: string;
  readonly bindingDigest: HmacEvidenceDigest;
}

export interface CodexEvidenceReplayGuard {
  /** Atomically returns false when this bound event was already claimed. */
  claim(claim: CodexEvidenceReplayClaim): Promise<boolean>;
}

export interface CodexEvidenceVerificationContext {
  readonly digester: KeyedHmacDigester;
  readonly expectedBindingDigest: HmacEvidenceDigest;
}

/** Verify and return a detached frozen snapshot. This is replay-agnostic. */
export function verifyCodexShadowEvidenceEnvelope(
  envelope: unknown,
  context: CodexEvidenceVerificationContext,
): AuthenticatedCodexShadowEvidence | null {
  const parsed = parseEnvelope(envelope);
  return parsed !== undefined && verifyParsed(parsed, context) ? parsed : null;
}

/** Verify integrity and atomically claim eventId for replay protection. */
export async function verifyAndClaimCodexShadowEvidenceEnvelope(
  envelope: unknown,
  context: CodexEvidenceVerificationContext & {
    readonly replayGuard: CodexEvidenceReplayGuard;
  },
): Promise<AuthenticatedCodexShadowEvidence | null> {
  const parsed = parseEnvelope(envelope);
  if (parsed === undefined || !verifyParsed(parsed, context)) return null;
  try {
    const claimed = await context.replayGuard.claim({
      schema: parsed.schema,
      keyId: parsed.keyId,
      eventId: parsed.eventId,
      bindingDigest: parsed.evidence.bindingDigest as HmacEvidenceDigest,
    });
    return claimed ? parsed : null;
  } catch {
    return null;
  }
}

function verifyParsed(
  envelope: AuthenticatedCodexShadowEvidence,
  context: CodexEvidenceVerificationContext,
): boolean {
  const { digester, expectedBindingDigest } = context;
  if (
    envelope.keyId !== digester.keyId ||
    envelope.evidence.bindingDigest !== expectedBindingDigest
  )
    return false;
  try {
    const expected = digester.digestJson({
      domain: "io.github.aantenore.intentabi/codex-evidence-envelope/v1",
      schema: envelope.schema,
      eventId: envelope.eventId,
      keyId: envelope.keyId,
      evidence: envelope.evidence,
    });
    return isHmac(expected) && constantTimeEqual(expected, envelope.mac);
  } catch {
    return false;
  }
}

function parseEnvelope(
  value: unknown,
): AuthenticatedCodexShadowEvidence | undefined {
  try {
    const envelope = snapshotRecord(value, [
      "schema",
      "eventId",
      "keyId",
      "evidence",
      "mac",
    ]);
    if (
      envelope.schema !== CODEX_SHADOW_EVIDENCE_ENVELOPE_SCHEMA ||
      typeof envelope.eventId !== "string" ||
      !UUID_V4_PATTERN.test(envelope.eventId) ||
      typeof envelope.keyId !== "string" ||
      !KEY_ID_PATTERN.test(envelope.keyId) ||
      !isHmac(envelope.mac)
    ) {
      return undefined;
    }
    const evidence = parseEvidence(envelope.evidence);
    if (evidence === undefined) return undefined;
    return deepFreeze({
      schema: CODEX_SHADOW_EVIDENCE_ENVELOPE_SCHEMA,
      eventId: envelope.eventId,
      keyId: envelope.keyId,
      evidence,
      mac: envelope.mac,
    });
  } catch {
    return undefined;
  }
}

function parseEvidence(value: unknown): CodexShadowEvidence | undefined {
  const evidence = snapshotRecord(value, [
    "schema",
    "mode",
    "submitted",
    "inputKind",
    "bindingDigest",
    "originalDigest",
    "optionsDigest",
    "execution",
    "preparation",
  ]);
  if (
    evidence.schema !== CODEX_SHADOW_EVIDENCE_SCHEMA ||
    evidence.mode !== "shadow" ||
    evidence.submitted !== "original" ||
    (evidence.inputKind !== "text" && evidence.inputKind !== "non-text") ||
    !isHmac(evidence.bindingDigest) ||
    !isHmacOr(
      evidence.originalDigest,
      "unavailable:original-digest",
      "unavailable:non-text-input",
    ) ||
    (evidence.optionsDigest !== "unavailable:not-provided" &&
      evidence.optionsDigest !== "unavailable:unbound-options")
  ) {
    return undefined;
  }
  const execution = snapshotRecord(evidence.execution, [
    "status",
    "outputDigest",
  ]);
  if (
    execution.status !== "succeeded" ||
    execution.outputDigest !== "unavailable:opaque-output"
  ) {
    return undefined;
  }
  const preparation = parsePreparation(evidence.preparation);
  if (preparation === undefined) return undefined;
  if (
    (evidence.inputKind === "non-text" &&
      (evidence.originalDigest !== "unavailable:non-text-input" ||
        preparation.outcome !== "bypass" ||
        preparation.reason !== "NON_TEXT_INPUT")) ||
    (evidence.inputKind === "text" &&
      (evidence.originalDigest === "unavailable:non-text-input" ||
        preparation.reason === "NON_TEXT_INPUT"))
  ) {
    return undefined;
  }
  return deepFreeze({
    schema: CODEX_SHADOW_EVIDENCE_SCHEMA,
    mode: "shadow",
    submitted: "original",
    inputKind: evidence.inputKind,
    bindingDigest: evidence.bindingDigest,
    originalDigest: evidence.originalDigest,
    optionsDigest: evidence.optionsDigest,
    execution: {
      status: "succeeded",
      outputDigest: "unavailable:opaque-output",
    },
    preparation,
  }) as CodexShadowEvidence;
}

function parsePreparation(
  value: unknown,
): CodexShadowEvidence["preparation"] | undefined {
  const allowed = [
    "outcome",
    "reason",
    "candidateDigest",
    "selectedCodecDigest",
    "reasonSetDigest",
    "promotionBindingDigest",
    "proof",
  ] as const;
  const record = snapshotAllowedRecord(value, allowed);
  if (
    !Object.hasOwn(record, "outcome") ||
    !Object.hasOwn(record, "reason") ||
    !Object.hasOwn(record, "proof") ||
    !OUTCOMES.has(record.outcome as CodexPreparationOutcome) ||
    !REASONS.has(record.reason as CodexPreparationReason) ||
    (record.proof !== "present-unverified" &&
      record.proof !== "not-observed") ||
    !isOptionalDigestField(
      record,
      "candidateDigest",
      "unavailable:candidate-digest",
    ) ||
    !isOptionalDigestField(
      record,
      "selectedCodecDigest",
      "unavailable:codec-digest",
    ) ||
    !isOptionalDigestField(
      record,
      "reasonSetDigest",
      "unavailable:reason-set-digest",
    ) ||
    !isOptionalDigestField(
      record,
      "promotionBindingDigest",
      "unavailable:promotion-binding-digest",
    )
  ) {
    return undefined;
  }
  const optionalFields = [
    "candidateDigest",
    "selectedCodecDigest",
    "reasonSetDigest",
    "promotionBindingDigest",
  ] as const;
  const present = (field: (typeof optionalFields)[number]) =>
    Object.hasOwn(record, field);
  const outcome = record.outcome as CodexPreparationOutcome;
  const reason = record.reason as CodexPreparationReason;
  const coherent =
    (outcome === "candidate-observed" &&
      reason === "CANDIDATE_ATTESTED" &&
      record.proof === "present-unverified" &&
      optionalFields.every(present)) ||
    (outcome === "identity" &&
      reason === "IDENTITY_ATTESTED" &&
      !present("candidateDigest") &&
      present("selectedCodecDigest") &&
      present("reasonSetDigest")) ||
    (outcome === "bypass" &&
      ["NON_TEXT_INPUT", "REQUEST_ID_INVALID", "INPUT_LIMIT_EXCEEDED"].includes(
        reason,
      ) &&
      record.proof === "not-observed" &&
      optionalFields.every((field) => !present(field))) ||
    (outcome === "preparer-timeout" &&
      reason === "PREPARATION_TIMEOUT_UNCANCELLED" &&
      record.proof === "not-observed" &&
      optionalFields.every((field) => !present(field))) ||
    (outcome === "preparer-fault" &&
      reason === "PREPARER_FAULT" &&
      record.proof === "not-observed" &&
      optionalFields.every((field) => !present(field))) ||
    (outcome === "invalid-preparer-result" &&
      reason === "PREPARER_RESULT_INVALID" &&
      record.proof === "not-observed" &&
      optionalFields.every((field) => !present(field)));
  if (!coherent) {
    return undefined;
  }
  return deepFreeze({ ...record }) as CodexShadowEvidence["preparation"];
}

function snapshotRecord(
  value: unknown,
  expected: readonly string[],
): Readonly<Record<string, unknown>> {
  const snapshot = snapshotAllowedRecord(value, expected);
  if (Reflect.ownKeys(snapshot).length !== expected.length) {
    throw new TypeError("Evidence has missing fields");
  }
  return snapshot;
}

function snapshotAllowedRecord(
  value: unknown,
  allowed: readonly string[],
): Readonly<Record<string, unknown>> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("Evidence must be a data record");
  }
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string" || !allowed.includes(key))) {
    throw new TypeError("Evidence has unexpected fields");
  }
  const snapshot: Record<string, unknown> = Object.create(null);
  for (const key of keys) {
    if (typeof key !== "string") throw new TypeError("Unexpected symbol");
    const descriptor = Reflect.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !descriptor.enumerable ||
      !Object.hasOwn(descriptor, "value") ||
      Object.hasOwn(descriptor, "get") ||
      Object.hasOwn(descriptor, "set")
    ) {
      throw new TypeError("Evidence must use own enumerable data fields");
    }
    snapshot[key] = descriptor.value;
  }
  return Object.freeze(snapshot);
}

function isHmac(value: unknown): value is `hmac-sha256:evidence:${string}` {
  return typeof value === "string" && HMAC_PATTERN.test(value);
}

function isHmacOr(value: unknown, ...fallbacks: readonly string[]): boolean {
  return (
    isHmac(value) || (typeof value === "string" && fallbacks.includes(value))
  );
}

function isOptionalDigestField(
  value: Readonly<Record<string, unknown>>,
  field: string,
  fallback: string,
): boolean {
  return !Object.hasOwn(value, field) || isHmacOr(value[field], fallback);
}

function constantTimeEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  return (
    leftBytes.byteLength === rightBytes.byteLength &&
    timingSafeEqual(leftBytes, rightBytes)
  );
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const nested of Object.values(value)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
}
