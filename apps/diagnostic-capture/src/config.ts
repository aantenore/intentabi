import { isProxy } from "node:util/types";

import { z } from "zod";

export const DIAGNOSTIC_CAPTURE_CONFIG_SCHEMA =
  "io.github.aantenore.intentabi/diagnostic-capture-config/v1alpha1" as const;
export const DIAGNOSTIC_CAPTURE_DATASET_SCHEMA =
  "io.github.aantenore.intentabi/diagnostic-capture-dataset/v1alpha1" as const;
export const DIAGNOSTIC_CAPTURE_CLASSIFICATION =
  "diagnostic-held-out-pilot" as const;

export const MAX_DIAGNOSTIC_CONFIG_BYTES = 1024 * 1024;
export const MAX_DIAGNOSTIC_DATASET_BYTES = 32 * 1024 * 1024;
export const MAX_DIAGNOSTIC_CASES = 10_000;
export const MAX_DIAGNOSTIC_RECORD_BYTES = 1024 * 1024;
export const MAX_DIAGNOSTIC_WORKLOAD_BYTES = 64 * 1024 * 1024;
export const MAX_DIAGNOSTIC_MANIFEST_BYTES = 16 * 1024 * 1024;

const identifier = z.string().regex(/^[a-z0-9][a-z0-9._-]{0,127}$/u);
const sha256Digest = z.string().regex(/^sha256:[a-f0-9]{64}$/u);
const environmentName = z.string().regex(/^[A-Z][A-Z0-9_]*$/u);
const locale = z.string().regex(/^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,4}$/u);
const scalarText = z
  .string()
  .min(1)
  .max(65_536)
  .refine(
    (value) => !/[\uD800-\uDFFF]/u.test(value),
    "Text must contain only Unicode scalar values",
  );
const tokenCounter = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);

export type StrictJson =
  | null
  | boolean
  | number
  | string
  | readonly StrictJson[]
  | { readonly [key: string]: StrictJson };

const strictJson = z.custom<StrictJson>(isStrictJson);

export const diagnosticCaptureConfigSchema = z
  .object({
    schema: z.literal(DIAGNOSTIC_CAPTURE_CONFIG_SCHEMA),
    classification: z.literal(DIAGNOSTIC_CAPTURE_CLASSIFICATION),
    provider: z
      .object({
        kind: z.literal("openai-compatible-chat-completions"),
        name: identifier,
        baseUrl: z.string().min(1).max(2_048).refine(isAllowedBaseUrl),
        model: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u),
        deploymentRevisionDigest: sha256Digest,
        credentialKeyId: identifier,
        authentication: z.discriminatedUnion("kind", [
          z.object({ kind: z.literal("none") }).strict(),
          z
            .object({
              kind: z.literal("bearer-env"),
              apiKeyEnv: environmentName,
            })
            .strict(),
        ]),
        instructions: scalarText,
        temperature: z.literal(0),
        reasoningEffort: z.enum(["none", "low", "medium", "high"]).optional(),
        maxOutputTokens: z.number().int().min(16).max(4_096),
        requestTimeoutMs: z.number().int().min(100).max(300_000),
        maxRequestBytes: z
          .number()
          .int()
          .min(1_024)
          .max(2 * 1024 * 1024),
        maxResponseBytes: z
          .number()
          .int()
          .min(1_024)
          .max(16 * 1024 * 1024),
      })
      .strict(),
    capture: z
      .object({
        maxCases: z.number().int().min(1).max(MAX_DIAGNOSTIC_CASES),
        maxDatasetBytes: z
          .number()
          .int()
          .min(2)
          .max(MAX_DIAGNOSTIC_DATASET_BYTES),
        maxRecordBytes: z
          .number()
          .int()
          .min(1_024)
          .max(MAX_DIAGNOSTIC_RECORD_BYTES),
        maxWorkloadBytes: z
          .number()
          .int()
          .min(1_024)
          .max(MAX_DIAGNOSTIC_WORKLOAD_BYTES),
        maxManifestBytes: z
          .number()
          .int()
          .min(1_024)
          .max(MAX_DIAGNOSTIC_MANIFEST_BYTES),
        normalizationUsage: z
          .object({
            inputTokens: tokenCounter,
            outputTokens: tokenCounter,
          })
          .strict(),
      })
      .strict(),
  })
  .strict();

const diagnosticCaseSchema = z
  .object({
    id: identifier,
    source: scalarText,
    locale,
    routeInput: strictJson,
    oracleValue: strictJson,
  })
  .strict();

export const diagnosticCaptureDatasetSchema = z
  .object({
    schema: z.literal(DIAGNOSTIC_CAPTURE_DATASET_SCHEMA),
    classification: z.literal(DIAGNOSTIC_CAPTURE_CLASSIFICATION),
    split: z.literal("held-out"),
    id: identifier,
    cases: z.array(diagnosticCaseSchema).min(1).max(MAX_DIAGNOSTIC_CASES),
  })
  .strict()
  .superRefine((value, context) => {
    const seen = new Set<string>();
    for (const [index, entry] of value.cases.entries()) {
      if (seen.has(entry.id)) {
        context.addIssue({
          code: "custom",
          path: ["cases", index, "id"],
          message: "Case identifiers must be unique",
        });
      }
      seen.add(entry.id);
    }
  });

export type DiagnosticCaptureConfig = z.infer<
  typeof diagnosticCaptureConfigSchema
>;
export type DiagnosticCaptureDataset = z.infer<
  typeof diagnosticCaptureDatasetSchema
>;
export type DiagnosticCaptureCase = z.infer<typeof diagnosticCaseSchema>;

export function parseDiagnosticCaptureConfig(
  value: unknown,
): DiagnosticCaptureConfig {
  return diagnosticCaptureConfigSchema.parse(value);
}

export function parseDiagnosticCaptureDataset(
  value: unknown,
): DiagnosticCaptureDataset {
  return diagnosticCaptureDatasetSchema.parse(value);
}

export function parseStrictJsonValue(value: unknown): StrictJson {
  return strictJson.parse(value);
}

export function normalizeProviderBaseUrl(value: string): string {
  let end = value.length;
  while (end > 0 && value.charCodeAt(end - 1) === 0x2f) end -= 1;
  return value.slice(0, end);
}

export function assertDiagnosticDatasetBudget(
  config: DiagnosticCaptureConfig,
  dataset: DiagnosticCaptureDataset,
  encodedBytes: number,
): void {
  if (
    dataset.cases.length > config.capture.maxCases ||
    !Number.isSafeInteger(encodedBytes) ||
    encodedBytes < 0 ||
    encodedBytes > config.capture.maxDatasetBytes
  ) {
    throw new TypeError("Diagnostic dataset exceeds its configured budget");
  }
}

function isAllowedBaseUrl(value: string): boolean {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  const loopback =
    url.hostname === "localhost" ||
    url.hostname === "[::1]" ||
    /^127(?:\.[0-9]{1,3}){3}$/u.test(url.hostname);
  return (
    (url.protocol === "https:" || (url.protocol === "http:" && loopback)) &&
    url.username === "" &&
    url.password === "" &&
    url.search === "" &&
    url.hash === "" &&
    !url.pathname.includes("\\") &&
    !url.pathname.includes("%") &&
    !/(?:^|\/)\.{1,2}(?:\/|$)/u.test(url.pathname)
  );
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
    if (visited > 100_000 || current.depth > 64) return false;
    if (
      current.value === null ||
      typeof current.value === "boolean" ||
      typeof current.value === "string"
    ) {
      if (
        typeof current.value === "string" &&
        /[\uD800-\uDFFF]/u.test(current.value)
      ) {
        return false;
      }
      continue;
    }
    if (typeof current.value === "number") {
      if (!Number.isFinite(current.value)) return false;
      continue;
    }
    if (
      typeof current.value !== "object" ||
      isProxy(current.value) ||
      seen.has(current.value)
    ) {
      return false;
    }
    seen.add(current.value);
    if (Array.isArray(current.value)) {
      if (Object.getPrototypeOf(current.value) !== Array.prototype)
        return false;
      pending.push(
        ...current.value.map((entry) => ({
          value: entry,
          depth: current.depth + 1,
        })),
      );
      continue;
    }
    const prototype = Object.getPrototypeOf(current.value);
    if (prototype !== Object.prototype && prototype !== null) return false;
    for (const [key, entry] of Object.entries(current.value)) {
      if (/[\uD800-\uDFFF]/u.test(key)) return false;
      pending.push({ value: entry, depth: current.depth + 1 });
    }
  }
  return true;
}
