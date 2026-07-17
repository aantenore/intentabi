import {
  QUALIFICATION_RECEIPT_SCHEMA,
  QualificationCancelledFailure,
  QualificationInvariantFailure,
  type QualificationAuthorityProjection,
  type QualificationAuthorityReceipt,
  type QualificationReceipt,
  type QualificationRunResult,
  type RunQualificationInput,
  type UnsignedQualificationReceipt,
} from "./types.js";
import {
  dataMethod,
  isEvidenceHmac,
  matchAuthorityToPlan,
  matchCasesToPlan,
  parseAuthorityResult,
  parseCases,
  parsePlan,
  parseRunInput,
  throwIfQualificationCancelled,
  validateExecutionBinding,
} from "./validation.js";

export async function runQualification<TPayload, TAttestation, TArtifact>(
  value: RunQualificationInput<TPayload, TAttestation, TArtifact>,
): Promise<QualificationRunResult<TArtifact>> {
  const input = parseRunInput(value);
  const plan = parsePlan(input.plan);
  const cases = parseCases<TPayload>(input.cases);
  matchCasesToPlan(cases, plan);
  validateExecutionBinding(
    input.runId,
    input.executableDigest,
    input.authenticateReceipt,
  );

  const runCase = dataMethod(input.runner, "runCase");
  const evaluate = dataMethod(input.authority, "evaluate");
  const records: unknown[] = [];
  for (const [ordinal, item] of cases.entries()) {
    throwIfQualificationCancelled(input.signal);
    const planCase = plan.cases[ordinal]!;
    const context = Object.freeze({
      planCase,
      ...(input.signal === undefined ? {} : { signal: input.signal }),
    });
    let record: unknown;
    try {
      record = await Reflect.apply(runCase, input.runner, [
        item.payload,
        context,
      ]);
    } catch (error) {
      throwIfQualificationCancelled(input.signal);
      throw error;
    }
    throwIfQualificationCancelled(input.signal);
    records.push(record);
  }

  throwIfQualificationCancelled(input.signal);
  let evaluated: ReturnType<typeof parseAuthorityResult<TArtifact>>;
  try {
    const authorityValue: unknown = await Reflect.apply(
      evaluate,
      input.authority,
      [
        Object.freeze({
          attestation: input.attestation,
          records: Object.freeze(records.slice()),
          ...(input.signal === undefined ? {} : { signal: input.signal }),
        }),
      ],
    );
    throwIfQualificationCancelled(input.signal);
    evaluated = parseAuthorityResult<TArtifact>(authorityValue);
    matchAuthorityToPlan(evaluated.projection, plan);
  } catch (error) {
    if (
      error instanceof QualificationInvariantFailure ||
      error instanceof QualificationCancelledFailure
    ) {
      throw error;
    }
    throwIfQualificationCancelled(input.signal);
    throw new QualificationInvariantFailure(
      "Qualification authority returned invalid evidence",
    );
  }

  const authority = authorityReceipt(evaluated.projection);
  const receiptCases = Object.freeze(
    plan.cases.map((item, ordinal) =>
      Object.freeze({
        ordinal: item.ordinal,
        caseRef: item.caseRef,
        recordDigest: evaluated.projection.cases[ordinal]!.recordDigest,
      }),
    ),
  );
  const unsigned: UnsignedQualificationReceipt = Object.freeze({
    schema: QUALIFICATION_RECEIPT_SCHEMA,
    classification: "shadow-qualification",
    activationCeiling: "shadow-only",
    activationAuthorized: false,
    runId: input.runId,
    keyId: plan.keyId,
    datasetDigest: plan.datasetDigest,
    protocolDigest: plan.protocolDigest,
    executableDigest: input.executableDigest,
    authority,
    cases: receiptCases,
  });

  let receiptMac: unknown;
  throwIfQualificationCancelled(input.signal);
  try {
    receiptMac = await input.authenticateReceipt(unsigned);
  } catch {
    throwIfQualificationCancelled(input.signal);
    throw new QualificationInvariantFailure(
      "Qualification receipt authentication failed",
    );
  }
  throwIfQualificationCancelled(input.signal);
  if (!isEvidenceHmac(receiptMac)) {
    throw new QualificationInvariantFailure(
      "Qualification receipt authenticator returned an invalid MAC",
    );
  }
  const receipt: QualificationReceipt = Object.freeze({
    ...unsigned,
    receiptMac,
  });
  return Object.freeze({
    receipt,
    authorityArtifact: evaluated.artifact,
  });
}

function authorityReceipt(
  source: QualificationAuthorityProjection,
): QualificationAuthorityReceipt {
  return Object.freeze({
    authority: Object.freeze({
      id: source.authority.id,
      version: source.authority.version,
    }),
    activationCeiling: "shadow-only",
    decision: source.decision,
    evidenceDigest: source.evidenceDigest,
    bindingDigest: source.bindingDigest,
    reportDigest: source.reportDigest,
    ...(source.qualificationDigest === undefined
      ? {}
      : { qualificationDigest: source.qualificationDigest }),
  });
}
