export const SHADOW_EVIDENCE_SCHEMA =
  "io.github.aantenore.intentabi/shadow-execution-evidence/v1alpha1" as const;

export const SHADOW_EVIDENCE_ENVELOPE_SCHEMA =
  "io.github.aantenore.intentabi/authenticated-shadow-evidence/v1alpha1" as const;

export type Sha256Digest = `sha256:${string}`;
export type HmacSourceDigest = `hmac-sha256:intent-source:${string}`;
export type HmacShadowIntentKey = `hmac-sha256:shadow-intent:${string}`;
export type HmacShadowWitnessKey = `hmac-sha256:shadow-witness:${string}`;
export type HmacShadowScopeDigest = `hmac-sha256:shadow-scope:${string}`;
export type HmacShadowBindingDigest = `hmac-sha256:shadow-binding:${string}`;
export type HmacRouteInputDigest = `hmac-sha256:route-input:${string}`;
export type HmacEvidenceDigest = `hmac-sha256:evidence:${string}`;

export interface RequestScope {
  readonly tenant: string;
  readonly authorization: string;
}

export interface RouteBinding {
  readonly id: string;
  readonly revisionDigest: Sha256Digest;
}

export interface IntentInspectionRequest {
  readonly source: string;
  readonly locale: string;
  /** Must come from an authenticated host context, never user-controlled JSON. */
  readonly scope: RequestScope;
  readonly scopeEpoch: string;
  readonly route: RouteBinding;
  readonly routeInput: unknown;
  readonly signal?: AbortSignal;
}

interface InspectionBinding {
  readonly sourceDigest: HmacSourceDigest;
  readonly scopeDigest: HmacShadowScopeDigest;
  readonly bindingDigest: HmacShadowBindingDigest;
  readonly routeInputDigest: HmacRouteInputDigest;
}

export type IntentInspection =
  | (InspectionBinding & {
      readonly status: "eligible";
      /** Shadow-only correlation key, never a cache-admission credential. */
      readonly intentKey: HmacShadowIntentKey;
      readonly witnessKey: HmacShadowWitnessKey;
      readonly effect: "read";
      readonly reasons: readonly string[];
    })
  | (InspectionBinding & {
      readonly status: "bypass";
      readonly reasons: readonly string[];
    });

/** Semantic authority port. Implementations return opaque keyed bindings only. */
export interface IntentInspector {
  inspect(request: IntentInspectionRequest): Promise<IntentInspection>;
}

export type CandidateProbe =
  { readonly found: false } | { readonly found: true };

export interface CandidateObservation {
  /** Idempotency key shared with the authenticated evidence envelope. */
  readonly observationId: string;
  readonly sourceDigest: HmacSourceDigest;
  readonly intentKey: HmacShadowIntentKey;
  readonly witnessKey: HmacShadowWitnessKey;
  readonly scopeDigest: HmacShadowScopeDigest;
  readonly bindingDigest: HmacShadowBindingDigest;
  readonly routeInputDigest: HmacRouteInputDigest;
  readonly probe: CandidateProbe;
}

/**
 * A shadow nomination index. It has no read-content or admission method. A
 * positive probe is explicitly unverified until a future authenticated store
 * and SemWitness cache-admission contract exist.
 */
export interface ShadowCandidateStore {
  probe(
    intentKey: HmacShadowIntentKey,
    signal: AbortSignal,
  ): Promise<CandidateProbe>;
  observe(
    observation: CandidateObservation,
    signal: AbortSignal,
  ): Promise<void>;
}

export interface OrdinaryRoute<Input, Output> extends RouteBinding {
  execute(input: Input): Promise<Output>;
}

/** Evidence digests must be keyed; plain hashes leak low-entropy content. */
export interface KeyedHmacDigester {
  readonly kind: "keyed-hmac-sha256";
  readonly keyId: string;
  digestJson(value: unknown): HmacEvidenceDigest;
}

export type CandidateOutcome =
  | "bypass"
  | "unverified-candidate-observed"
  | "miss-observed"
  | "normalizer-fault"
  | "shadow-timeout"
  | "store-fault";

export interface ShadowEvidence {
  readonly schema: typeof SHADOW_EVIDENCE_SCHEMA;
  readonly mode: "shadow";
  readonly routeDigest: HmacEvidenceDigest | "unavailable:route-digest";
  readonly sourceDigest: string;
  readonly scopeDigest: string;
  readonly bindingDigest: string;
  readonly routeInputDigest: string;
  readonly execution: {
    readonly status: "succeeded" | "failed";
    readonly outputDigest:
      | HmacEvidenceDigest
      | "unavailable:output-digest"
      | "unavailable:error-digest";
  };
  readonly candidate: {
    readonly outcome: CandidateOutcome;
    readonly applied: false;
    readonly intentKey?: HmacShadowIntentKey;
    readonly witnessKey?: HmacShadowWitnessKey;
    readonly reasons: readonly string[];
  };
}

export interface AuthenticatedShadowEvidence {
  readonly schema: typeof SHADOW_EVIDENCE_ENVELOPE_SCHEMA;
  readonly eventId: string;
  readonly keyId: string;
  readonly evidence: ShadowEvidence;
  readonly mac: HmacEvidenceDigest;
}

export interface EvidenceSink {
  /** Implementations must use eventId as an idempotency key and honor abort. */
  emit(
    envelope: AuthenticatedShadowEvidence,
    signal: AbortSignal,
  ): Promise<void>;
}

export interface ShadowRunRequest<Input> {
  readonly source: string;
  readonly locale: string;
  /** Must be derived by the trusted host. */
  readonly scope: RequestScope;
  readonly scopeEpoch: string;
  readonly routeInput: Input;
}

export interface ShadowRunResult<Output> {
  readonly output: Output;
  readonly evidence: ShadowEvidence;
  readonly envelope: AuthenticatedShadowEvidence | null;
  readonly evidenceDigest: HmacEvidenceDigest | null;
  readonly evidenceDelivery: "emitted" | "unacknowledged" | "dropped";
}
