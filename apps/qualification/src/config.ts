import { isProxy } from "node:util/types";

import { z } from "zod";

import { MAX_QUALIFICATION_CASES } from "@intentabi/qualification-core";

export const QUALIFICATION_CONFIG_SCHEMA =
  "io.github.aantenore.intentabi/qualification-config/v1alpha1" as const;
export const QUALIFICATION_DATASET_SCHEMA =
  "io.github.aantenore.intentabi/qualification-dataset/v1alpha1" as const;
export const QUALIFICATION_EVIDENCE_SCHEMA =
  "io.github.aantenore.intentabi/qualification-evidence/v1alpha1" as const;

export const MAX_QUALIFICATION_CONFIG_BYTES = 256 * 1024;
export const MAX_QUALIFICATION_DATASET_BYTES = 32 * 1024 * 1024;
export const MAX_QUALIFICATION_EVIDENCE_BYTES = 128 * 1024 * 1024;
export const MAX_QUALIFICATION_RECORD_BYTES = 256 * 1024;
export const MAX_QUALIFICATION_ARTIFACT_BYTES = 128 * 1024 * 1024;

const identifier = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u);
const environmentName = z.string().regex(/^[A-Z][A-Z0-9_]*$/u);
const sha256Digest = z.string().regex(/^sha256:[a-f0-9]{64}$/u);
const evidenceHmac = z.string().regex(/^hmac-sha256:evidence:[a-f0-9]{64}$/u);

export const qualificationConfigSchema = z
  .object({
    schema: z.literal(QUALIFICATION_CONFIG_SCHEMA),
    classification: z.literal("shadow-qualification"),
    protocolDigest: sha256Digest,
    qualification: z
      .object({
        seed: z.string().min(1).max(256),
        maxCases: z.number().int().min(1).max(MAX_QUALIFICATION_CASES),
        maxDatasetBytes: z
          .number()
          .int()
          .min(2)
          .max(MAX_QUALIFICATION_DATASET_BYTES),
        maxEvidenceBytes: z
          .number()
          .int()
          .min(2)
          .max(MAX_QUALIFICATION_EVIDENCE_BYTES),
        maxRecordBytes: z
          .number()
          .int()
          .min(2)
          .max(MAX_QUALIFICATION_RECORD_BYTES),
        maxArtifactBytes: z
          .number()
          .int()
          .min(2)
          .max(MAX_QUALIFICATION_ARTIFACT_BYTES),
      })
      .strict()
      .refine(
        (value) => value.maxRecordBytes <= value.maxEvidenceBytes,
        "Record budget must fit within the evidence budget",
      ),
    evidence: z
      .object({
        hmacSecretEnv: environmentName,
        keyId: identifier,
      })
      .strict(),
    authority: z
      .object({
        kind: z.literal("semwitness-intent-cache-promotion"),
        expectedEvaluator: z
          .object({
            id: z.literal("semwitness-intent-cache-promotion-evaluator"),
            version: z.literal("1"),
          })
          .strict(),
      })
      .strict(),
  })
  .strict();

const qualificationCaseMetadataSchema = z
  .object({
    id: identifier,
    balanceCellId: identifier,
    cohort: z.enum(["population", "adversarial"]),
    difficulty: z.enum(["simple", "medium", "complex", "adversarial"]),
    cacheRegime: z.enum(["cold", "warm"]),
  })
  .strict();

export const qualificationDatasetSchema = z
  .object({
    schema: z.literal(QUALIFICATION_DATASET_SCHEMA),
    classification: z.literal("private-held-out"),
    split: z.literal("held-out"),
    id: identifier,
    protocolDigest: sha256Digest,
    cases: z
      .array(qualificationCaseMetadataSchema)
      .min(1)
      .max(MAX_QUALIFICATION_CASES),
  })
  .strict()
  .superRefine((value, context) => {
    const seen = new Set<string>();
    let adversarialSeen = false;
    for (const [index, entry] of value.cases.entries()) {
      if (seen.has(entry.id)) {
        context.addIssue({
          code: "custom",
          path: ["cases", index, "id"],
          message: "Case identifiers must be unique",
        });
      }
      seen.add(entry.id);
      if (entry.cohort === "adversarial") adversarialSeen = true;
      if (entry.cohort === "population" && adversarialSeen) {
        context.addIssue({
          code: "custom",
          path: ["cases", index, "cohort"],
          message: "Population cases must precede adversarial cases",
        });
      }
    }
  });

export type StrictJson =
  | null
  | boolean
  | number
  | string
  | readonly StrictJson[]
  | { readonly [key: string]: StrictJson };

export type StrictJsonObject = { readonly [key: string]: StrictJson };

const strictJson = z.custom<StrictJson>(isStrictJson);
const strictJsonObject = z.custom<StrictJsonObject>(
  (value) => isPlainRecord(value) && isStrictJson(value),
);

export const qualificationEvidenceSchema = z
  .object({
    schema: z.literal(QUALIFICATION_EVIDENCE_SCHEMA),
    classification: z.literal("private-held-out"),
    planRef: evidenceHmac,
    attestation: strictJsonObject,
    records: z.array(strictJson).max(MAX_QUALIFICATION_CASES),
  })
  .strict();

export type QualificationConfig = z.infer<typeof qualificationConfigSchema>;
export type QualificationDataset = z.infer<typeof qualificationDatasetSchema>;
export type QualificationEvidence = z.infer<typeof qualificationEvidenceSchema>;

export function parseQualificationConfig(value: unknown): QualificationConfig {
  return qualificationConfigSchema.parse(value);
}

export function parseQualificationDataset(
  value: unknown,
): QualificationDataset {
  return qualificationDatasetSchema.parse(value);
}

export function parseQualificationEvidence(
  value: unknown,
): QualificationEvidence {
  return qualificationEvidenceSchema.parse(value);
}

export function assertQualificationDatasetBudget(
  config: QualificationConfig,
  dataset: QualificationDataset,
  encodedBytes: number,
): void {
  if (
    dataset.protocolDigest !== config.protocolDigest ||
    dataset.cases.length > config.qualification.maxCases ||
    !Number.isSafeInteger(encodedBytes) ||
    encodedBytes < 0 ||
    encodedBytes > config.qualification.maxDatasetBytes
  ) {
    throw new TypeError("Qualification dataset does not match its budget");
  }
}

export function assertQualificationEvidenceBudget(
  config: QualificationConfig,
  dataset: QualificationDataset,
  evidence: QualificationEvidence,
  encodedBytes: number,
): void {
  if (
    !Number.isSafeInteger(encodedBytes) ||
    encodedBytes < 0 ||
    encodedBytes > config.qualification.maxEvidenceBytes ||
    evidence.records.length !== dataset.cases.length ||
    evidence.records.length > config.qualification.maxCases
  ) {
    throw new TypeError("Qualification evidence does not match its budget");
  }
  for (const record of evidence.records) {
    const bytes = Buffer.byteLength(JSON.stringify(record), "utf8");
    if (bytes > config.qualification.maxRecordBytes) {
      throw new TypeError("Qualification record exceeds its byte budget");
    }
  }
}

function isStrictJson(value: unknown): value is StrictJson {
  const pending: { readonly value: unknown; readonly depth: number }[] = [
    { value, depth: 0 },
  ];
  const seen = new Set<object>();
  let visited = 0;
  while (pending.length > 0) {
    const current = pending.pop()!;
    visited += 1;
    if (visited > 2_000_000 || current.depth > 64) return false;
    if (
      current.value === null ||
      typeof current.value === "string" ||
      typeof current.value === "boolean"
    ) {
      continue;
    }
    if (typeof current.value === "number") {
      if (!Number.isFinite(current.value)) return false;
      continue;
    }
    if (typeof current.value !== "object" || isProxy(current.value)) {
      return false;
    }
    if (seen.has(current.value)) return false;
    seen.add(current.value);
    if (Array.isArray(current.value)) {
      if (Object.getPrototypeOf(current.value) !== Array.prototype)
        return false;
      const descriptors = Object.getOwnPropertyDescriptors(
        current.value,
      ) as Record<string, PropertyDescriptor>;
      const keys = Reflect.ownKeys(descriptors);
      const lengthDescriptor = descriptors["length"];
      if (
        lengthDescriptor === undefined ||
        !("value" in lengthDescriptor) ||
        typeof lengthDescriptor.value !== "number" ||
        !Number.isSafeInteger(lengthDescriptor.value) ||
        lengthDescriptor.value < 0
      ) {
        return false;
      }
      const length = lengthDescriptor.value as number;
      if (
        keys.length !== length + 1 ||
        keys.some(
          (key) =>
            key !== "length" &&
            (typeof key !== "string" || !/^(?:0|[1-9][0-9]*)$/u.test(key)),
        )
      ) {
        return false;
      }
      for (let index = 0; index < length; index += 1) {
        const descriptor = descriptors[String(index)];
        if (
          descriptor === undefined ||
          descriptor.enumerable !== true ||
          !("value" in descriptor)
        ) {
          return false;
        }
        pending.push({ value: descriptor.value, depth: current.depth + 1 });
      }
    } else {
      if (!isPlainRecord(current.value)) return false;
      const descriptors = Object.getOwnPropertyDescriptors(current.value);
      const keys = Reflect.ownKeys(descriptors);
      if (keys.some((key) => typeof key !== "string")) return false;
      for (const key of keys) {
        const descriptor = descriptors[key as string];
        if (
          descriptor === undefined ||
          descriptor.enumerable !== true ||
          !("value" in descriptor)
        ) {
          return false;
        }
        pending.push({ value: descriptor.value, depth: current.depth + 1 });
      }
    }
  }
  return true;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  if (isProxy(value)) return false;
  const prototype = Object.getPrototypeOf(value) as object | null;
  return prototype === Object.prototype || prototype === null;
}
