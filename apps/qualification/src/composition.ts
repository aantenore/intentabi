import { createHash } from "node:crypto";

import {
  createSemWitnessQualificationAuthority,
  type HostAttestedPromotionRunInput,
  type SemWitnessQualificationArtifact,
} from "@intentabi/adapter-semwitness";
import {
  reservePrivateArtifact,
  type PrivateArtifactReservation,
} from "@intentabi/cli-io";
import {
  createHmacOpaqueDigester,
  type KeyedHmacDigester,
} from "@intentabi/core";
import {
  createQualificationPlan,
  runQualification,
  type EvidenceHmac,
  type QualificationAuthority,
  type QualificationCase,
  type QualificationPlan,
  type QualificationReceipt,
  type Sha256Digest,
} from "@intentabi/qualification-core";

import type {
  QualificationConfig,
  QualificationDataset,
  QualificationEvidence,
  StrictJson,
} from "./config.js";

export const QUALIFICATION_ARTIFACT_SCHEMA =
  "io.github.aantenore.intentabi/qualification-artifact/v1alpha1" as const;
export const QUALIFICATION_APP_IMPLEMENTATION =
  "io.github.aantenore.intentabi/qualification/0.1.0-alpha.1;authority=semwitness-intent-cache-promotion-evaluator@1" as const;
/**
 * Digest of the fixed in-process composition contract. This is deliberately
 * not represented as a byte-for-byte digest of the platform launcher.
 */
export const QUALIFICATION_IMPLEMENTATION_CONTRACT_DIGEST = sha256(
  QUALIFICATION_APP_IMPLEMENTATION,
);

const CASE_REFERENCE_DOMAIN = "qualification-case-reference/v1";
const BALANCE_CELL_REFERENCE_DOMAIN = "qualification-balance-cell-reference/v1";
const DATASET_REFERENCE_DOMAIN = "qualification-dataset-reference/v1";
const PLAN_REFERENCE_DOMAIN = "qualification-plan-reference/v1";
const EVIDENCE_REFERENCE_DOMAIN = "qualification-evidence-reference/v1";
const RECEIPT_AUTHENTICATION_DOMAIN = "qualification-receipt-authentication/v1";
const RUN_IDENTIFIER_DOMAIN = "qualification-run-identifier/v1";

type SemWitnessAttestation = HostAttestedPromotionRunInput["attestation"];
export type QualificationAuthorityPort = QualificationAuthority<
  SemWitnessAttestation,
  SemWitnessQualificationArtifact
>;

export interface QualificationPlanMaterialization {
  readonly planRef: EvidenceHmac;
  readonly plan: QualificationPlan;
}

export interface ExecuteQualificationInput {
  readonly config: QualificationConfig;
  readonly dataset: QualificationDataset;
  readonly evidence: QualificationEvidence;
  readonly secret: string;
  readonly materialization: QualificationPlanMaterialization;
}

export interface QualificationExecutionResult {
  readonly planRef: EvidenceHmac;
  readonly receipt: QualificationReceipt;
  readonly semwitness: SemWitnessQualificationArtifact;
}

export interface QualificationArtifact {
  readonly schema: typeof QUALIFICATION_ARTIFACT_SCHEMA;
  readonly classification: "shadow-qualification";
  readonly activationCeiling: "shadow-only";
  readonly activationAuthorized: false;
  readonly planRef: EvidenceHmac;
  readonly receipt: QualificationReceipt;
  readonly semwitness: SemWitnessQualificationArtifact;
}

export function materializeQualificationPlan(input: {
  readonly config: QualificationConfig;
  readonly dataset: QualificationDataset;
  readonly secret: string;
}): QualificationPlanMaterialization {
  const digester = createHmacOpaqueDigester(
    input.secret,
    input.config.evidence.keyId,
  );
  const cases = materializeCases(input.dataset, digester, () => null);
  const plan = createQualificationPlan({
    cases,
    seed: input.config.qualification.seed,
    keyId: digester.keyId,
    datasetDigest: digester.digestJson({
      domain: DATASET_REFERENCE_DOMAIN,
      dataset: input.dataset,
    }),
    protocolDigest: input.config.protocolDigest as Sha256Digest,
  });
  const planRef = digestPlan(digester, plan);
  return Object.freeze({ planRef, plan });
}

export function assertQualificationEvidenceBinding(
  materialization: QualificationPlanMaterialization,
  evidence: QualificationEvidence,
): void {
  if (evidence.planRef !== materialization.planRef) {
    throw new TypeError("Qualification evidence is not bound to the plan");
  }
}

export async function executeQualification(
  input: ExecuteQualificationInput,
  authority: QualificationAuthorityPort = createSemWitnessQualificationAuthority(),
): Promise<QualificationExecutionResult> {
  const digester = createHmacOpaqueDigester(
    input.secret,
    input.config.evidence.keyId,
  );
  const expected = materializeQualificationPlan({
    config: input.config,
    dataset: input.dataset,
    secret: input.secret,
  });
  if (
    input.materialization.planRef !== expected.planRef ||
    digestPlan(digester, input.materialization.plan) !== expected.planRef
  ) {
    throw new TypeError("Qualification plan materialization is invalid");
  }
  assertQualificationEvidenceBinding(input.materialization, input.evidence);

  if (input.evidence.records.length !== input.dataset.cases.length) {
    throw new TypeError("Qualification evidence case count is invalid");
  }
  const cases = materializeCases(input.dataset, digester, (ordinal) => {
    const record = input.evidence.records[ordinal];
    if (record === undefined) {
      throw new TypeError("Qualification evidence case is missing");
    }
    return record;
  });
  const evidenceRef = digester.digestJson({
    domain: EVIDENCE_REFERENCE_DOMAIN,
    evidence: input.evidence,
  });
  const runId = deterministicUuid(
    digester.digestJson({
      domain: RUN_IDENTIFIER_DOMAIN,
      planRef: input.materialization.planRef,
      evidenceRef,
      executableDigest: QUALIFICATION_IMPLEMENTATION_CONTRACT_DIGEST,
    }),
  );
  const result = await runQualification({
    plan: input.materialization.plan,
    cases,
    runner: Object.freeze({
      runCase: (record: StrictJson) => record,
    }),
    authority,
    // The adapter remains the sole owner and validator of this opaque schema.
    attestation: input.evidence.attestation as unknown as SemWitnessAttestation,
    runId,
    // qualification-core calls this field executableDigest; this offline app
    // binds it to the fixed in-process implementation contract above.
    executableDigest: QUALIFICATION_IMPLEMENTATION_CONTRACT_DIGEST,
    authenticateReceipt: (receipt) =>
      digester.digestJson({
        domain: RECEIPT_AUTHENTICATION_DOMAIN,
        receipt,
      }),
  });
  if (
    result.receipt.authority.authority.id !==
      input.config.authority.expectedEvaluator.id ||
    result.receipt.authority.authority.version !==
      input.config.authority.expectedEvaluator.version ||
    result.receipt.authority.activationCeiling !== "shadow-only"
  ) {
    throw new TypeError("Qualification authority identity is invalid");
  }
  return Object.freeze({
    planRef: input.materialization.planRef,
    receipt: result.receipt,
    semwitness: result.authorityArtifact,
  });
}

export function createQualificationArtifact(
  result: QualificationExecutionResult,
): QualificationArtifact {
  return Object.freeze({
    schema: QUALIFICATION_ARTIFACT_SCHEMA,
    classification: "shadow-qualification" as const,
    activationCeiling: "shadow-only" as const,
    activationAuthorized: false as const,
    planRef: result.planRef,
    receipt: result.receipt,
    semwitness: result.semwitness,
  });
}

export function serializeQualificationArtifact(
  artifact: QualificationArtifact,
  maximumBytes: number,
): Uint8Array {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes <= 0) {
    throw new TypeError("Qualification artifact budget is invalid");
  }
  const bytes = Buffer.from(`${JSON.stringify(artifact)}\n`, "utf8");
  if (bytes.byteLength > maximumBytes) {
    throw new TypeError("Qualification artifact exceeds its byte budget");
  }
  return Uint8Array.from(bytes);
}

export function reserveQualificationArtifact(
  path: string,
  maximumBytes: number,
): Promise<PrivateArtifactReservation> {
  return reservePrivateArtifact(path, maximumBytes);
}

function materializeCases<TPayload>(
  dataset: QualificationDataset,
  digester: KeyedHmacDigester,
  payload: (ordinal: number) => TPayload,
): readonly QualificationCase<TPayload>[] {
  return Object.freeze(
    dataset.cases.map((item, ordinal) =>
      Object.freeze({
        caseRef: digester.digestJson({
          domain: CASE_REFERENCE_DOMAIN,
          datasetId: dataset.id,
          caseId: item.id,
        }),
        balanceCellRef: digester.digestJson({
          domain: BALANCE_CELL_REFERENCE_DOMAIN,
          datasetId: dataset.id,
          balanceCellId: item.balanceCellId,
        }),
        cohort: item.cohort,
        difficulty: item.difficulty,
        cacheRegime: item.cacheRegime,
        payload: payload(ordinal),
      }),
    ),
  );
}

function digestPlan(
  digester: KeyedHmacDigester,
  plan: QualificationPlan,
): EvidenceHmac {
  return digester.digestJson({ domain: PLAN_REFERENCE_DOMAIN, plan });
}

function deterministicUuid(value: EvidenceHmac): string {
  const bytes = Buffer.from(value.slice("hmac-sha256:evidence:".length), "hex");
  bytes[6] = (bytes[6]! & 0x0f) | 0x40;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytes.subarray(0, 16).toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

function sha256(value: string): Sha256Digest {
  return `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}
