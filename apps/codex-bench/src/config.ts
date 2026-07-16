import { z } from "zod";

import { VERIFIED_CODEX_SDK_VERSION } from "@intentabi/adapter-codex-sdk";

const identifier = z.string().regex(/^[a-z0-9][a-z0-9._-]{0,127}$/u);
const environmentName = z.string().regex(/^[A-Z][A-Z0-9_]*$/u);
const sha256Digest = z.string().regex(/^sha256:[a-f0-9]{64}$/u);
const modelIdentifier = z
  .string()
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u);
const scalarInput = z
  .string()
  .min(1)
  .max(1_000_000)
  .refine(
    (value) => !/[\uD800-\uDFFF]/u.test(value),
    "Input must contain only Unicode scalar values",
  );

export const codexBenchConfigSchema = z
  .object({
    schema: z.literal(
      "io.github.aantenore.intentabi/codex-bench-config/v1alpha1",
    ),
    classification: z.literal("research-conformance"),
    codex: z
      .object({
        codexPathOverride: z.string().min(1).max(4_096),
        expectedCliVersion: z.literal(VERIFIED_CODEX_SDK_VERSION),
        expectedExecutableDigest: sha256Digest,
        authentication: z
          .object({
            apiKeyEnv: environmentName,
          })
          .strict(),
        thread: z
          .object({
            model: modelIdentifier,
            sandboxMode: z.literal("read-only"),
            skipGitRepoCheck: z.literal(false),
            modelReasoningEffort: z.enum([
              "minimal",
              "low",
              "medium",
              "high",
              "xhigh",
            ]),
            networkAccessEnabled: z.literal(false),
            webSearchMode: z.literal("disabled"),
            webSearchEnabled: z.literal(false),
            approvalPolicy: z.literal("never"),
          })
          .strict(),
        turnTimeoutMs: z.number().int().min(1_000).max(120_000),
      })
      .strict(),
    benchmark: z
      .object({
        seed: z.string().min(1).max(256),
        maxCases: z.number().int().min(1).max(100),
        maxProviderCalls: z.number().int().min(2).max(200),
        maxInputBytes: z.number().int().min(1).max(1_000_000),
        maxDatasetBytes: z.number().int().min(2).max(10_000_000),
        maxOutputTokensPerCall: z.number().int().min(16).max(4_096),
        maxTotalOutputTokens: z.number().int().min(32).max(819_200),
        maxRunDurationMs: z.number().int().min(2_000).max(3_600_000),
        maxGatewayResponseBytes: z.number().int().min(65_536).max(16_777_216),
      })
      .strict()
      .refine(
        (value) => value.maxDatasetBytes >= value.maxInputBytes * 2,
        "Dataset budget must allow at least one maximum-sized pair",
      )
      .refine(
        (value) =>
          value.maxTotalOutputTokens >= value.maxProviderCalls * 16 &&
          value.maxTotalOutputTokens <=
            value.maxProviderCalls * value.maxOutputTokensPerCall,
        "Total output budget must be feasible for the provider-call budget",
      ),
    evidence: z
      .object({
        hmacSecretEnv: environmentName,
        keyId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u),
      })
      .strict(),
  })
  .strict()
  .superRefine((value, context) => {
    const apiKeyEnv = value.codex.authentication.apiKeyEnv;
    const hmacSecretEnv = value.evidence.hmacSecretEnv;
    if (apiKeyEnv === hmacSecretEnv) {
      context.addIssue({
        code: "custom",
        path: ["codex", "authentication", "apiKeyEnv"],
        message: "Codex authentication and evidence keys must be distinct",
      });
    }
    for (const [path, name] of [
      [["codex", "authentication", "apiKeyEnv"], apiKeyEnv],
      [["evidence", "hmacSecretEnv"], hmacSecretEnv],
    ] as const) {
      if (name === "SYSTEMROOT" || name === "WINDIR") {
        context.addIssue({
          code: "custom",
          path: [...path],
          message: "A secret cannot use an allow-listed platform variable",
        });
      }
    }
  });

const benchmarkCaseSchema = z
  .object({
    id: identifier,
    stratum: z.enum(["simple", "medium", "complex", "adversarial"]),
    cacheRegime: z.enum(["cold", "warm"]),
    original: scalarInput,
    candidate: scalarInput,
  })
  .strict()
  .refine((value) => value.original !== value.candidate, {
    message: "Candidate must differ from the baseline input",
  });

export const codexBenchDatasetSchema = z
  .object({
    schema: z.literal(
      "io.github.aantenore.intentabi/codex-bench-dataset/v1alpha1",
    ),
    classification: z.literal("research-conformance"),
    id: identifier,
    split: z.enum(["conformance", "development"]),
    cases: z.array(benchmarkCaseSchema).min(1).max(100),
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

export type CodexBenchConfig = z.infer<typeof codexBenchConfigSchema>;
export type CodexBenchDataset = z.infer<typeof codexBenchDatasetSchema>;

export function parseCodexBenchConfig(value: unknown): CodexBenchConfig {
  return codexBenchConfigSchema.parse(value);
}

export function parseCodexBenchDataset(value: unknown): CodexBenchDataset {
  return codexBenchDatasetSchema.parse(value);
}

export function assertCodexBenchDatasetBudget(
  config: CodexBenchConfig,
  dataset: CodexBenchDataset,
): void {
  if (dataset.cases.length > config.benchmark.maxCases) {
    throw new TypeError("Dataset exceeds the configured case budget");
  }
  if (dataset.cases.length * 2 > config.benchmark.maxProviderCalls) {
    throw new TypeError("Dataset exceeds the configured provider-call budget");
  }
  let totalBytes = 0;
  for (const entry of dataset.cases) {
    for (const content of [entry.original, entry.candidate]) {
      const inputBytes = Buffer.byteLength(content, "utf8");
      if (inputBytes > config.benchmark.maxInputBytes) {
        throw new TypeError("Dataset input exceeds the configured byte budget");
      }
      totalBytes += inputBytes;
      if (totalBytes > config.benchmark.maxDatasetBytes) {
        throw new TypeError("Dataset exceeds the configured total byte budget");
      }
    }
  }
}
