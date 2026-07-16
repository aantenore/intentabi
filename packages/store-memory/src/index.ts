import type {
  CandidateObservation,
  CandidateProbe,
  HmacShadowIntentKey,
  ShadowCandidateStore,
} from "@intentabi/core";

export type MemoryStoreFaultMode = "none" | "probe" | "observe";

export interface MemoryShadowStoreOptions {
  readonly faultMode?: MemoryStoreFaultMode;
  readonly candidates?: readonly HmacShadowIntentKey[];
}

/** Metadata-only, single-scope test store; it cannot hold response bodies. */
export class MemoryShadowStore implements ShadowCandidateStore {
  readonly #faultMode: MemoryStoreFaultMode;
  readonly #candidates: ReadonlySet<HmacShadowIntentKey>;
  readonly #observations: CandidateObservation[] = [];

  constructor(options: MemoryShadowStoreOptions = {}) {
    const faultMode = options.faultMode ?? "none";
    if (!(["none", "probe", "observe"] as const).includes(faultMode)) {
      throw new TypeError("Memory store fault mode is invalid");
    }
    const candidates = [...(options.candidates ?? [])];
    for (const candidate of candidates) assertIntentKey(candidate);
    this.#faultMode = faultMode;
    this.#candidates = new Set(candidates);
  }

  async probe(
    intentKey: HmacShadowIntentKey,
    signal: AbortSignal,
  ): Promise<CandidateProbe> {
    throwIfAborted(signal);
    assertIntentKey(intentKey);
    if (this.#faultMode === "probe") throw new Error("Configured probe fault");
    return this.#candidates.has(intentKey)
      ? Object.freeze({ found: true as const })
      : Object.freeze({ found: false as const });
  }

  async observe(
    observation: CandidateObservation,
    signal: AbortSignal,
  ): Promise<void> {
    throwIfAborted(signal);
    if (this.#faultMode === "observe") {
      throw new Error("Configured observation fault");
    }
    const parsed = parseObservation(observation);
    throwIfAborted(signal);
    this.#observations.push(parsed);
  }

  observations(): readonly CandidateObservation[] {
    return Object.freeze([...this.#observations]);
  }
}

function parseObservation(input: CandidateObservation): CandidateObservation {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new TypeError("Candidate observation is malformed");
  }
  const keys = Object.keys(input).sort();
  const expected = [
    "bindingDigest",
    "intentKey",
    "observationId",
    "probe",
    "routeInputDigest",
    "scopeDigest",
    "sourceDigest",
    "witnessKey",
  ];
  if (
    keys.length !== expected.length ||
    keys.some((key, i) => key !== expected[i])
  ) {
    throw new TypeError("Candidate observation is malformed");
  }
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
      input.observationId,
    )
  ) {
    throw new TypeError("Candidate observation id is malformed");
  }
  assertPattern(
    input.sourceDigest,
    /^hmac-sha256:intent-source:[a-f0-9]{64}$/u,
  );
  assertIntentKey(input.intentKey);
  assertPattern(input.witnessKey, /^hmac-sha256:shadow-witness:[a-f0-9]{64}$/u);
  assertPattern(input.scopeDigest, /^hmac-sha256:shadow-scope:[a-f0-9]{64}$/u);
  assertPattern(
    input.bindingDigest,
    /^hmac-sha256:shadow-binding:[a-f0-9]{64}$/u,
  );
  assertPattern(
    input.routeInputDigest,
    /^hmac-sha256:route-input:[a-f0-9]{64}$/u,
  );
  if (
    input.probe === null ||
    typeof input.probe !== "object" ||
    Array.isArray(input.probe) ||
    Object.keys(input.probe).length !== 1 ||
    typeof input.probe.found !== "boolean"
  ) {
    throw new TypeError("Candidate probe is malformed");
  }
  const probe: CandidateProbe = input.probe.found
    ? Object.freeze({ found: true as const })
    : Object.freeze({ found: false as const });
  return Object.freeze({
    observationId: input.observationId,
    sourceDigest: input.sourceDigest,
    intentKey: input.intentKey,
    witnessKey: input.witnessKey,
    scopeDigest: input.scopeDigest,
    bindingDigest: input.bindingDigest,
    routeInputDigest: input.routeInputDigest,
    probe,
  });
}

function assertIntentKey(value: unknown): asserts value is HmacShadowIntentKey {
  assertPattern(value, /^hmac-sha256:shadow-intent:[a-f0-9]{64}$/u);
}

function assertPattern(
  value: unknown,
  pattern: RegExp,
): asserts value is string {
  if (typeof value !== "string" || !pattern.test(value)) {
    throw new TypeError("Opaque shadow metadata is malformed");
  }
}

function throwIfAborted(signal: AbortSignal): void {
  if (signal.aborted) throw new DOMException("Operation aborted", "AbortError");
}
