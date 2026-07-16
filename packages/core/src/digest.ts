import { createHmac, createSecretKey, timingSafeEqual } from "node:crypto";

import {
  SHADOW_EVIDENCE_ENVELOPE_SCHEMA,
  SHADOW_EVIDENCE_SCHEMA,
  type AuthenticatedShadowEvidence,
  type HmacEvidenceDigest,
  type KeyedHmacDigester,
} from "./types.js";

const EVIDENCE_DOMAIN =
  "io.github.aantenore.intentabi/content-free-evidence/v1\0";
const KEY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;

export function createHmacOpaqueDigester(
  secret: Uint8Array | string,
  keyId = "local-v1",
): KeyedHmacDigester {
  const bytes = Buffer.from(secret);
  if (bytes.byteLength < 32) {
    throw new TypeError("Evidence HMAC secret must contain at least 32 bytes");
  }
  if (!KEY_ID_PATTERN.test(keyId)) {
    throw new TypeError("Evidence HMAC key id is invalid");
  }
  const key = createSecretKey(bytes);
  bytes.fill(0);
  return Object.freeze({
    kind: "keyed-hmac-sha256" as const,
    keyId,
    digestJson(value: unknown): HmacEvidenceDigest {
      return `hmac-sha256:evidence:${createHmac("sha256", key)
        .update(EVIDENCE_DOMAIN)
        .update(canonicalJson(value))
        .digest("hex")}`;
    },
  });
}

export function verifyEvidenceEnvelope(
  envelope: AuthenticatedShadowEvidence,
  digester: KeyedHmacDigester,
): boolean {
  if (!isStrictEnvelope(envelope) || envelope.keyId !== digester.keyId) {
    return false;
  }
  try {
    const expected = digester.digestJson({
      schema: envelope.schema,
      eventId: envelope.eventId,
      keyId: envelope.keyId,
      evidence: envelope.evidence,
    });
    return constantTimeEqual(expected, envelope.mac);
  } catch {
    return false;
  }
}

function isStrictEnvelope(
  value: unknown,
): value is AuthenticatedShadowEvidence {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["eventId", "evidence", "keyId", "mac", "schema"]) ||
    value.schema !== SHADOW_EVIDENCE_ENVELOPE_SCHEMA ||
    typeof value.eventId !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
      value.eventId,
    ) ||
    typeof value.keyId !== "string" ||
    !KEY_ID_PATTERN.test(value.keyId) ||
    typeof value.mac !== "string" ||
    !/^hmac-sha256:evidence:[a-f0-9]{64}$/u.test(value.mac) ||
    !isStrictEvidence(value.evidence)
  ) {
    return false;
  }
  return true;
}

function isStrictEvidence(value: unknown): boolean {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "bindingDigest",
      "candidate",
      "execution",
      "mode",
      "routeDigest",
      "routeInputDigest",
      "schema",
      "scopeDigest",
      "sourceDigest",
    ]) ||
    value.schema !== SHADOW_EVIDENCE_SCHEMA ||
    value.mode !== "shadow" ||
    !isOpaqueOrUnavailable(value.routeDigest, "route-digest", "evidence") ||
    !isOpaqueOrUnavailable(value.sourceDigest, undefined, "intent-source") ||
    !isOpaqueOrUnavailable(value.scopeDigest, undefined, "shadow-scope") ||
    !isOpaqueOrUnavailable(value.bindingDigest, undefined, "shadow-binding") ||
    !isOpaqueOrUnavailable(value.routeInputDigest, undefined, "route-input") ||
    !isStrictExecution(value.execution) ||
    !isStrictCandidate(value.candidate)
  ) {
    return false;
  }
  return true;
}

function isStrictExecution(value: unknown): boolean {
  return (
    isRecord(value) &&
    hasExactKeys(value, ["outputDigest", "status"]) &&
    (value.status === "succeeded" || value.status === "failed") &&
    typeof value.outputDigest === "string" &&
    (/^hmac-sha256:evidence:[a-f0-9]{64}$/u.test(value.outputDigest) ||
      value.outputDigest === "unavailable:output-digest" ||
      value.outputDigest === "unavailable:error-digest")
  );
}

function isStrictCandidate(value: unknown): boolean {
  if (!isRecord(value)) return false;
  const allowed = new Set([
    "applied",
    "intentKey",
    "outcome",
    "reasons",
    "witnessKey",
  ]);
  const keys = Object.keys(value);
  if (
    keys.some((key) => !allowed.has(key)) ||
    !keys.includes("applied") ||
    !keys.includes("outcome") ||
    !keys.includes("reasons") ||
    value.applied !== false ||
    ![
      "bypass",
      "unverified-candidate-observed",
      "miss-observed",
      "normalizer-fault",
      "shadow-timeout",
      "store-fault",
    ].includes(String(value.outcome)) ||
    !Array.isArray(value.reasons) ||
    value.reasons.length > 16 ||
    !value.reasons.every(
      (reason) =>
        typeof reason === "string" && /^[A-Z][A-Z0-9_]{0,63}$/u.test(reason),
    )
  ) {
    return false;
  }
  const hasIntent = value.intentKey !== undefined;
  const hasWitness = value.witnessKey !== undefined;
  return (
    hasIntent === hasWitness &&
    (!hasIntent ||
      (typeof value.intentKey === "string" &&
        /^hmac-sha256:shadow-intent:[a-f0-9]{64}$/u.test(value.intentKey) &&
        typeof value.witnessKey === "string" &&
        /^hmac-sha256:shadow-witness:[a-f0-9]{64}$/u.test(value.witnessKey)))
  );
}

function isOpaqueOrUnavailable(
  value: unknown,
  exactUnavailableSuffix: string | undefined,
  domain: string,
): boolean {
  if (typeof value !== "string") return false;
  if (new RegExp(`^hmac-sha256:${domain}:[a-f0-9]{64}$`, "u").test(value)) {
    return true;
  }
  return exactUnavailableSuffix === undefined
    ? /^unavailable:[a-z0-9-]{1,64}$/u.test(value)
    : value === `unavailable:${exactUnavailableSuffix}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(
  value: Readonly<Record<string, unknown>>,
  expected: readonly string[],
): boolean {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  return (
    actual.length === sortedExpected.length &&
    actual.every((key, index) => key === sortedExpected[index])
  );
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalValue(value, new Set()));
}

function canonicalValue(value: unknown, ancestors: Set<object>): unknown {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) {
    if (ancestors.has(value)) throw new TypeError("Cyclic JSON is unsupported");
    ancestors.add(value);
    const result = value.map((entry, index) => {
      if (!(index in value))
        throw new TypeError("Sparse arrays are unsupported");
      return canonicalValue(entry, ancestors);
    });
    ancestors.delete(value);
    return result;
  }
  if (typeof value === "object") {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError("Only plain JSON objects can be digested");
    }
    if (ancestors.has(value)) throw new TypeError("Cyclic JSON is unsupported");
    ancestors.add(value);
    const record = value as Record<string, unknown>;
    const result = Object.fromEntries(
      Object.keys(record)
        .sort()
        .map((key) => [key, canonicalValue(record[key], ancestors)]),
    );
    ancestors.delete(value);
    return result;
  }
  throw new TypeError("Only strict JSON values can be digested");
}

function constantTimeEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  return (
    leftBytes.byteLength === rightBytes.byteLength &&
    timingSafeEqual(leftBytes, rightBytes)
  );
}
