import { z } from "zod";
import { OPENAI_COMPATIBLE_REASONING_EFFORTS } from "semwitness/intent/openai-compatible";

import { CLINC150_REVIEWED_READ_LABELS } from "./clinc150.js";

export const NORMALIZER_PILOT_CONFIG_SCHEMA =
  "io.github.aantenore.intentabi/normalizer-pilot-config/v1alpha2" as const;
export const NORMALIZER_PILOT_CLASSIFICATION =
  "external-normalizer-diagnostic" as const;

export const CLINC150_REVISION =
  "828f8093932c8fe6ca7936c3d2e52903b1c523de" as const;
export const CLINC150_SOURCE_SHA256 =
  "36923c3705a59e08fe9c3883d8bc2dd966ef93e22cb78ac41171782a698d56e0" as const;
export const EXAMPLE_DEPLOYMENT_REVISION_DIGEST =
  "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" as const;

const digest = z.string().regex(/^sha256:[a-f0-9]{64}$/u);
const identifier = z.string().regex(/^[a-z0-9][a-z0-9._-]{0,127}$/u);
const environmentName = z.string().regex(/^SEMWITNESS_[A-Z0-9_]{1,116}$/u);

export const normalizerPilotConfigSchema = z
  .object({
    schema: z.literal(NORMALIZER_PILOT_CONFIG_SCHEMA),
    classification: z.literal(NORMALIZER_PILOT_CLASSIFICATION),
    source: z
      .object({
        kind: z.literal("clinc150"),
        revision: z.literal(CLINC150_REVISION),
        sha256: z.literal(CLINC150_SOURCE_SHA256),
        seed: identifier,
        locale: z.literal("en-US"),
        labels: z
          .array(z.enum(CLINC150_REVIEWED_READ_LABELS))
          .min(4)
          .max(CLINC150_REVIEWED_READ_LABELS.length),
        trainingAliasesPerIntent: z.number().int().min(1).max(20),
        heldOutPerIntent: z.number().int().min(2).max(30),
        outOfScopeCases: z.number().int().min(1).max(1_000),
      })
      .strict()
      .superRefine((value, context) => {
        if (new Set(value.labels).size !== value.labels.length) {
          context.addIssue({
            code: "custom",
            path: ["labels"],
            message: "Intent labels must be unique",
          });
        }
      }),
    compiler: z
      .object({
        kind: z.literal("openai-compatible"),
        deploymentRevisionDigest: digest,
        credentialKeyId: identifier,
        provider: z
          .object({
            name: identifier,
            baseUrl: z.string().min(1).max(2_048),
            model: z.string().min(1).max(256),
            environmentRef: environmentName.optional(),
          })
          .strict(),
        policy: z
          .object({
            requestTimeoutMs: z.number().int().min(1).max(300_000),
            maxResponseBytes: z
              .number()
              .int()
              .min(256)
              .max(8 * 1024 * 1024),
            maxOutputTokens: z.number().int().min(16).max(4_096),
            maxPromptBytes: z
              .number()
              .int()
              .min(1_024)
              .max(1024 * 1024),
            reasoningEffort: z
              .enum(OPENAI_COMPATIBLE_REASONING_EFFORTS)
              .optional(),
          })
          .strict(),
      })
      .strict(),
    evaluation: z
      .object({
        attemptsPerCase: z.number().int().min(2).max(20),
        maxRequests: z.number().int().min(1).max(100_000),
        maxArtifactBytes: z
          .number()
          .int()
          .min(1_024)
          .max(128 * 1024 * 1024),
        maxCheckpointBytes: z
          .number()
          .int()
          .min(1_024)
          .max(8 * 1024 * 1024),
      })
      .strict(),
  })
  .strict();

export type NormalizerPilotConfig = z.infer<typeof normalizerPilotConfigSchema>;

export function parseNormalizerPilotConfig(
  value: unknown,
): NormalizerPilotConfig {
  return normalizerPilotConfigSchema.parse(value);
}
