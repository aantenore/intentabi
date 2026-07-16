import type {
  HmacEvidenceDigest,
  KeyedHmacDigester,
  Sha256Digest,
} from "@intentabi/core";
import type {
  EquivalenceLevel,
  SegmentKind,
  SegmentRole,
  TrustLevel,
} from "semwitness";
import type { TextRequestPreparer } from "semwitness/host";

export const CODEX_SHADOW_EVIDENCE_SCHEMA =
  "io.github.aantenore.intentabi/codex-shadow-evidence/v1alpha1" as const;

export const CODEX_SHADOW_EVIDENCE_ENVELOPE_SCHEMA =
  "io.github.aantenore.intentabi/authenticated-codex-shadow-evidence/v1alpha1" as const;

export interface CodexTurnTransport<Input, Options, Output> {
  /**
   * Immutable execution description derived by the same adapter that creates
   * the Codex thread. It is evidence input, never proof of remote execution.
   */
  readonly executionBinding: CodexExecutionBinding;
  /** Submit this input exactly once without transforming or inspecting it. */
  runExact(input: Input, options?: Options): Promise<Output>;
}

export interface CodexExecutionBinding {
  readonly provenance: "adapter-thread-factory";
  readonly adapterId: string;
  readonly adapterContractDigest: Sha256Digest;
  readonly sdkVersion: string;
  /** Exact digest of the frozen options object passed to startThread. */
  readonly threadOptionsDigest: Sha256Digest;
  readonly externalClientConfiguration: "unavailable:external-client";
  readonly thread: {
    readonly model: string | "unavailable:not-explicit";
    readonly workingDirectory: string | "unavailable:not-explicit";
    readonly sandboxMode:
      | "read-only"
      | "workspace-write"
      | "danger-full-access"
      | "unavailable:not-explicit";
    readonly approvalPolicy:
      | "untrusted"
      | "on-failure"
      | "on-request"
      | "never"
      | "unavailable:not-explicit";
    readonly webSearchMode:
      "disabled" | "cached" | "live" | "unavailable:not-explicit";
    readonly skipGitRepoCheck: boolean | "unavailable:not-explicit";
    readonly modelReasoningEffort:
      | "minimal"
      | "low"
      | "medium"
      | "high"
      | "xhigh"
      | "unavailable:not-explicit";
    readonly networkAccessEnabled: boolean | "unavailable:not-explicit";
    readonly webSearchEnabled: boolean | "unavailable:not-explicit";
    readonly additionalDirectories: number;
    readonly additionalDirectoriesDigest:
      Sha256Digest | "unavailable:not-explicit";
  };
  readonly contracts: {
    readonly provenance: "host-declared-unverified";
    readonly runtimeRevisionDigest: Sha256Digest;
    readonly promptContractDigest: Sha256Digest;
    readonly toolContractDigest: Sha256Digest;
    readonly agentsDigest: Sha256Digest;
  };
}

export interface CodexPreparationBinding {
  readonly role: SegmentRole;
  readonly kind: SegmentKind;
  readonly trust: TrustLevel;
  readonly mediaType: string;
  readonly equivalence: EquivalenceLevel;
  readonly deploymentScopeDigest: Sha256Digest;
}

export interface CodexShadowLimits {
  readonly maximumInputBytes: number;
  readonly maximumCandidateBytes: number;
  readonly preparationMs: number;
  readonly evidenceSinkMs: number;
}

export interface CodexShadowEvidenceSink {
  /** Implementations must use eventId as an idempotency key and honor abort. */
  emit(
    envelope: AuthenticatedCodexShadowEvidence,
    signal: AbortSignal,
  ): Promise<void>;
}

export interface CodexShadowHostOptions<Input, Options, Output> {
  readonly preparer: TextRequestPreparer;
  readonly transport: CodexTurnTransport<Input, Options, Output>;
  readonly digester: KeyedHmacDigester;
  readonly evidenceSink: CodexShadowEvidenceSink;
  readonly preparationBinding: CodexPreparationBinding;
  readonly limits: CodexShadowLimits;
}

export interface CodexShadowRequest<Input, Options> {
  readonly id: string;
  readonly input: Input;
  readonly options?: Options;
}

export type CodexPreparationOutcome =
  | "candidate-observed"
  | "identity"
  | "bypass"
  | "preparer-fault"
  | "preparer-timeout"
  | "invalid-preparer-result";

export type CodexPreparationReason =
  | "CANDIDATE_ATTESTED"
  | "IDENTITY_ATTESTED"
  | "NON_TEXT_INPUT"
  | "REQUEST_ID_INVALID"
  | "INPUT_LIMIT_EXCEEDED"
  | "PREPARATION_TIMEOUT_UNCANCELLED"
  | "PREPARER_FAULT"
  | "PREPARER_RESULT_INVALID";

export type UnavailableEvidenceDigest =
  | "unavailable:binding-digest"
  | "unavailable:original-digest"
  | "unavailable:candidate-digest"
  | "unavailable:codec-digest"
  | "unavailable:reason-set-digest"
  | "unavailable:promotion-binding-digest";

export interface CodexShadowEvidence {
  readonly schema: typeof CODEX_SHADOW_EVIDENCE_SCHEMA;
  readonly mode: "shadow";
  readonly submitted: "original";
  readonly inputKind: "text" | "non-text";
  readonly bindingDigest: HmacEvidenceDigest | "unavailable:binding-digest";
  readonly originalDigest:
    | HmacEvidenceDigest
    | "unavailable:original-digest"
    | "unavailable:non-text-input";
  /** Opaque turn options are never reflected on before Thread.run. */
  readonly optionsDigest:
    "unavailable:not-provided" | "unavailable:unbound-options";
  readonly execution: {
    readonly status: "succeeded";
    /** The generic host never reflects on the opaque SDK output. */
    readonly outputDigest: "unavailable:opaque-output";
  };
  readonly preparation: {
    readonly outcome: CodexPreparationOutcome;
    readonly reason: CodexPreparationReason;
    readonly candidateDigest?:
      HmacEvidenceDigest | "unavailable:candidate-digest";
    readonly selectedCodecDigest?:
      HmacEvidenceDigest | "unavailable:codec-digest";
    readonly reasonSetDigest?:
      HmacEvidenceDigest | "unavailable:reason-set-digest";
    readonly promotionBindingDigest?:
      HmacEvidenceDigest | "unavailable:promotion-binding-digest";
    /** Presence is observed; SemWitness remains the semantic proof authority. */
    readonly proof: "present-unverified" | "not-observed";
  };
}

export interface AuthenticatedCodexShadowEvidence {
  readonly schema: typeof CODEX_SHADOW_EVIDENCE_ENVELOPE_SCHEMA;
  readonly eventId: string;
  readonly keyId: string;
  readonly evidence: CodexShadowEvidence;
  readonly mac: HmacEvidenceDigest;
}

export interface CodexShadowResult<Output> {
  readonly output: Output;
  readonly evidence: CodexShadowEvidence;
  readonly envelope: AuthenticatedCodexShadowEvidence | null;
  readonly evidenceDelivery: "emitted" | "unacknowledged" | "dropped";
}
