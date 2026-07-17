import { createHash } from "node:crypto";
import { isProxy } from "node:util/types";

import {
  evaluateIntentCachePromotionEvidence,
  parseIntentCachePromotionEvidenceJsonl,
  type IntentCachePromotionWorkbenchResult,
} from "semwitness/intent/host";

export type SemWitnessQualificationDigest = `sha256:${string}`;

export interface SemWitnessQualificationArtifact {
  readonly evidenceJsonl: string;
  readonly workbench: IntentCachePromotionWorkbenchResult;
}

export interface SemWitnessQualificationAuthorityProjection {
  readonly authority: {
    readonly id: "semwitness-intent-cache-promotion-evaluator";
    readonly version: "1";
  };
  readonly activationCeiling: "shadow-only";
  readonly decision: "qualified" | "unqualified";
  readonly evidenceDigest: SemWitnessQualificationDigest;
  readonly bindingDigest: SemWitnessQualificationDigest;
  readonly reportDigest: SemWitnessQualificationDigest;
  readonly qualificationDigest?: SemWitnessQualificationDigest;
  readonly cases: readonly {
    readonly ordinal: number;
    readonly cohort: "population" | "adversarial";
    readonly difficulty: "simple" | "medium" | "complex" | "adversarial";
    readonly cacheRegime: "cold" | "warm";
    readonly pairOrder: "ordinary-first" | "candidate-first";
    readonly recordDigest: SemWitnessQualificationDigest;
  }[];
}

export interface SemWitnessQualificationAuthorityResult {
  readonly projection: SemWitnessQualificationAuthorityProjection;
  /** Kept separate so a generic core never serializes or inspects it. */
  readonly artifact: SemWitnessQualificationArtifact;
}

/**
 * Project an exact SemWitness run into the content-free authority contract used
 * by Qualification Lab. The exact JSONL is reparsed before any case binding is
 * exposed; no record is repaired, relabelled, or re-ordered here.
 */
export function projectSemWitnessQualificationResult(
  artifact: SemWitnessQualificationArtifact,
): SemWitnessQualificationAuthorityResult {
  const source = plainRecord(artifact, ["evidenceJsonl", "workbench"]);
  if (typeof source.evidenceJsonl !== "string") {
    throw new TypeError("SemWitness qualification artifact is invalid");
  }
  const fixture = parseIntentCachePromotionEvidenceJsonl(source.evidenceJsonl);
  // The projection is always derived again from the exact evidence bytes. A
  // detached caller-supplied result can therefore neither forge a decision nor
  // become the private artifact returned to the orchestration core.
  const workbench = evaluateIntentCachePromotionEvidence(source.evidenceJsonl);
  assertSameWorkbenchBinding(source.workbench, workbench);
  if (
    workbench.report.bindingDigest !== fixture.binding.bindingDigest ||
    workbench.report.activationCeiling !== "shadow-only"
  ) {
    throw new TypeError("SemWitness qualification result is not bound");
  }

  const projection: SemWitnessQualificationAuthorityProjection = Object.freeze({
    authority: Object.freeze({
      id: "semwitness-intent-cache-promotion-evaluator" as const,
      version: "1" as const,
    }),
    activationCeiling: "shadow-only" as const,
    decision: workbench.qualified
      ? ("qualified" as const)
      : ("unqualified" as const),
    evidenceDigest: sha256(source.evidenceJsonl),
    bindingDigest: fixture.binding.bindingDigest,
    reportDigest: workbench.reportDigest,
    ...(workbench.qualified
      ? { qualificationDigest: workbench.qualificationDigest }
      : {}),
    cases: Object.freeze(
      fixture.cases.map((record) =>
        Object.freeze({
          ordinal: record.ordinal,
          cohort: record.kind.startsWith("population-")
            ? ("population" as const)
            : ("adversarial" as const),
          difficulty: record.difficulty,
          cacheRegime: record.cacheRegime,
          pairOrder: record.pairOrder,
          recordDigest: record.caseDigest,
        }),
      ),
    ),
  });

  return Object.freeze({
    projection,
    artifact: Object.freeze({
      evidenceJsonl: source.evidenceJsonl,
      workbench,
    }),
  });
}

function assertSameWorkbenchBinding(
  value: unknown,
  expected: IntentCachePromotionWorkbenchResult,
): void {
  const source = plainRecord(
    value,
    ["schema", "qualified", "report", "reportDigest"],
    ["qualification", "qualificationDigest"],
  );
  const report = plainDataObject(source.report);
  const bindingDigest = dataProperty(report, "bindingDigest");
  const qualificationDigest = source.qualificationDigest;
  if (
    source.schema !== expected.schema ||
    source.qualified !== expected.qualified ||
    source.reportDigest !== expected.reportDigest ||
    bindingDigest !== expected.report.bindingDigest ||
    qualificationDigest !==
      (expected.qualified ? expected.qualificationDigest : undefined)
  ) {
    throw new TypeError("SemWitness qualification result is not bound");
  }
}

function plainRecord(
  value: unknown,
  required: readonly string[],
  optional: readonly string[] = [],
): Readonly<Record<string, unknown>> {
  const source = plainDataObject(value);
  const descriptors = Object.getOwnPropertyDescriptors(source);
  const keys = Reflect.ownKeys(descriptors);
  const allowed = new Set([...required, ...optional]);
  if (
    keys.some((key) => typeof key !== "string" || !allowed.has(key)) ||
    required.some((key) => !keys.includes(key))
  ) {
    throw new TypeError("SemWitness qualification artifact is invalid");
  }
  return Object.freeze(
    Object.fromEntries(
      keys.map((key) => {
        if (typeof key !== "string") {
          throw new TypeError("SemWitness qualification artifact is invalid");
        }
        return [key, dataProperty(source, key)];
      }),
    ),
  );
}

function plainDataObject(value: unknown): object {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    isProxy(value)
  ) {
    throw new TypeError("SemWitness qualification artifact is invalid");
  }
  const prototype = Object.getPrototypeOf(value) as object | null;
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError("SemWitness qualification artifact is invalid");
  }
  return value;
}

function dataProperty(value: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (
    descriptor === undefined ||
    descriptor.enumerable !== true ||
    !("value" in descriptor)
  ) {
    throw new TypeError("SemWitness qualification artifact is invalid");
  }
  return descriptor.value;
}

function sha256(value: string): SemWitnessQualificationDigest {
  return `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}
