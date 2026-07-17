import { createHash } from "node:crypto";

import {
  QUALIFICATION_PLAN_SCHEMA,
  type CreateQualificationPlanInput,
  type QualificationPairOrder,
  type QualificationPlan,
} from "./types.js";
import { parseCreatePlanInput, qualificationBlock } from "./validation.js";

export function createQualificationPlan<TPayload>(
  value: CreateQualificationPlanInput<TPayload>,
): QualificationPlan {
  const input = parseCreatePlanInput(value);
  const blockOrdinals = new Map<string, number>();
  const cases = input.cases.map((item, ordinal) => {
    const block = qualificationBlock(item);
    const blockOrdinal = blockOrdinals.get(block) ?? 0;
    blockOrdinals.set(block, blockOrdinal + 1);
    const first = createHash("sha256")
      .update(input.seed)
      .update("\0")
      .update(block)
      .digest()[0]!;
    const candidateStarts = first % 2 === 1;
    const candidateFirst = (blockOrdinal % 2 === 0) === candidateStarts;
    const pairOrder: QualificationPairOrder = candidateFirst
      ? "candidate-first"
      : "ordinary-first";
    return Object.freeze({
      ordinal,
      caseRef: item.caseRef,
      balanceCellRef: item.balanceCellRef,
      cohort: item.cohort,
      difficulty: item.difficulty,
      cacheRegime: item.cacheRegime,
      pairOrder,
    });
  });
  return Object.freeze({
    schema: QUALIFICATION_PLAN_SCHEMA,
    classification: "shadow-qualification",
    activationCeiling: "shadow-only",
    keyId: input.keyId,
    datasetDigest: input.datasetDigest,
    protocolDigest: input.protocolDigest,
    cases: Object.freeze(cases),
  });
}
