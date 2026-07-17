export const QUALIFICATION_PLAN_SCHEMA =
  "io.github.aantenore.intentabi/qualification-plan/v1alpha1" as const;
export const QUALIFICATION_RECEIPT_SCHEMA =
  "io.github.aantenore.intentabi/qualification-receipt/v1alpha1" as const;

export const MAX_QUALIFICATION_CASES = 50_000 as const;

export type Sha256Digest = `sha256:${string}`;
export type EvidenceHmac = `hmac-sha256:evidence:${string}`;
export type QualificationCohort = "population" | "adversarial";
export type QualificationDifficulty =
  "simple" | "medium" | "complex" | "adversarial";
export type QualificationCacheRegime = "cold" | "warm";
export type QualificationPairOrder = "ordinary-first" | "candidate-first";

export interface QualificationCase<TPayload = unknown> {
  readonly caseRef: EvidenceHmac;
  /** Opaque cell identity used only for deterministic counterbalancing. */
  readonly balanceCellRef: EvidenceHmac;
  readonly cohort: QualificationCohort;
  readonly difficulty: QualificationDifficulty;
  readonly cacheRegime: QualificationCacheRegime;
  /** Private host state. Core retains the reference but never reflects on it. */
  readonly payload: TPayload;
}

export interface QualificationPlanCase {
  readonly ordinal: number;
  readonly caseRef: EvidenceHmac;
  readonly balanceCellRef: EvidenceHmac;
  readonly cohort: QualificationCohort;
  readonly difficulty: QualificationDifficulty;
  readonly cacheRegime: QualificationCacheRegime;
  readonly pairOrder: QualificationPairOrder;
}

export interface QualificationPlan {
  readonly schema: typeof QUALIFICATION_PLAN_SCHEMA;
  readonly classification: "shadow-qualification";
  readonly activationCeiling: "shadow-only";
  readonly keyId: string;
  readonly datasetDigest: EvidenceHmac;
  readonly protocolDigest: Sha256Digest;
  readonly cases: readonly QualificationPlanCase[];
}

export interface CreateQualificationPlanInput<TPayload = unknown> {
  readonly cases: readonly QualificationCase<TPayload>[];
  readonly seed: string;
  readonly keyId: string;
  readonly datasetDigest: EvidenceHmac;
  readonly protocolDigest: Sha256Digest;
}

export interface QualificationCaseContext {
  readonly planCase: QualificationPlanCase;
  readonly signal?: AbortSignal;
}

/**
 * A runner returns exactly one authority-owned, already-sealed record.
 * Expected execution failures belong in that record; a thrown error aborts.
 */
export interface QualificationCaseRunner<TPayload = unknown> {
  runCase(
    payload: TPayload,
    context: QualificationCaseContext,
  ): Promise<unknown> | unknown;
}

export interface AuthorityCaseBinding {
  readonly ordinal: number;
  readonly cohort: QualificationCohort;
  readonly difficulty: QualificationDifficulty;
  readonly cacheRegime: QualificationCacheRegime;
  readonly pairOrder: QualificationPairOrder;
  readonly recordDigest: Sha256Digest;
}

export interface QualificationAuthorityProjection {
  readonly authority: {
    readonly id: string;
    readonly version: string;
  };
  readonly activationCeiling: "shadow-only";
  readonly decision: "qualified" | "unqualified";
  readonly evidenceDigest: Sha256Digest;
  readonly bindingDigest: Sha256Digest;
  readonly reportDigest: Sha256Digest;
  readonly qualificationDigest?: Sha256Digest;
  readonly cases: readonly AuthorityCaseBinding[];
}

export interface QualificationAuthorityResult<TArtifact = unknown> {
  readonly projection: QualificationAuthorityProjection;
  /** Private authority artifact. Core never inspects or serializes it. */
  readonly artifact: TArtifact;
}

export interface QualificationAuthority<
  TAttestation = unknown,
  TArtifact = unknown,
> {
  evaluate(input: {
    readonly attestation: TAttestation;
    readonly records: readonly unknown[];
    readonly signal?: AbortSignal;
  }):
    | Promise<QualificationAuthorityResult<TArtifact>>
    | QualificationAuthorityResult<TArtifact>;
}

export type QualificationAuthorityReceipt = Omit<
  QualificationAuthorityProjection,
  "cases"
>;

export interface QualificationReceiptCase {
  readonly ordinal: number;
  readonly caseRef: EvidenceHmac;
  readonly recordDigest: Sha256Digest;
}

export interface QualificationReceipt {
  readonly schema: typeof QUALIFICATION_RECEIPT_SCHEMA;
  readonly classification: "shadow-qualification";
  readonly activationCeiling: "shadow-only";
  readonly activationAuthorized: false;
  readonly runId: string;
  readonly keyId: string;
  readonly datasetDigest: EvidenceHmac;
  readonly protocolDigest: Sha256Digest;
  readonly executableDigest: Sha256Digest;
  readonly authority: QualificationAuthorityReceipt;
  readonly cases: readonly QualificationReceiptCase[];
  readonly receiptMac: EvidenceHmac;
}

export type UnsignedQualificationReceipt = Omit<
  QualificationReceipt,
  "receiptMac"
>;

export interface RunQualificationInput<
  TPayload = unknown,
  TAttestation = unknown,
  TArtifact = unknown,
> {
  readonly plan: QualificationPlan;
  readonly cases: readonly QualificationCase<TPayload>[];
  readonly runner: QualificationCaseRunner<TPayload>;
  readonly authority: QualificationAuthority<TAttestation, TArtifact>;
  readonly attestation: TAttestation;
  readonly runId: string;
  readonly executableDigest: Sha256Digest;
  readonly authenticateReceipt: (
    receipt: UnsignedQualificationReceipt,
  ) => EvidenceHmac | Promise<EvidenceHmac>;
  readonly signal?: AbortSignal;
}

export interface QualificationRunResult<TArtifact = unknown> {
  readonly receipt: QualificationReceipt;
  readonly authorityArtifact: TArtifact;
}

/** A trusted-boundary mismatch, distinct from invalid caller configuration. */
export class QualificationInvariantFailure extends Error {
  constructor(message = "qualification-invariant-failed") {
    super(message);
    this.name = "QualificationInvariantFailure";
  }
}

/** Content-free cancellation that never exposes AbortSignal.reason. */
export class QualificationCancelledFailure extends Error {
  constructor() {
    super("Qualification run was cancelled");
    this.name = "QualificationCancelledFailure";
  }
}
