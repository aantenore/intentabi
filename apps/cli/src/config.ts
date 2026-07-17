import { z } from "zod";

const digest = z.string().regex(/^sha256:[a-f0-9]{64}$/u);
const CHILD_ENVIRONMENT_KEYS = new Set([
  "PATH",
  "SystemRoot",
  "WINDIR",
  "TEMP",
  "TMP",
  "TMPDIR",
]);

export const strictJsonValueSchema: z.ZodType<unknown> = z.lazy(() =>
  z.union([
    z.null(),
    z.boolean(),
    z.number().finite(),
    z.string(),
    z.array(strictJsonValueSchema),
    z.record(z.string(), strictJsonValueSchema),
  ]),
);

export const semWitnessConfigSchema = z
  .object({
    registryPath: z.string().min(1),
    policyDigest: digest,
    hmacSecretEnv: z
      .string()
      .regex(/^[A-Z][A-Z0-9_]*$/u)
      .refine((value) => !CHILD_ENVIRONMENT_KEYS.has(value), {
        message: "HMAC secret environment name collides with child allowlist",
      }),
    scopeEpoch: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u),
    expectedScope: z
      .object({
        tenant: z.string().min(1).max(256),
        authorization: z.string().min(1).max(256),
      })
      .strict(),
    routeBindings: z
      .record(z.string().min(1).max(128), strictJsonValueSchema)
      .refine((value) => Object.keys(value).length > 0),
  })
  .strict();

export const intentAbiConfigSchema = z
  .object({
    schema: z.literal("io.github.aantenore.intentabi/config/v1alpha1"),
    mode: z.literal("shadow"),
    semwitness: semWitnessConfigSchema,
    agenticSdlc: z.discriminatedUnion("kind", [
      z
        .object({
          kind: z.literal("fixture"),
          fixturePath: z.string().min(1),
        })
        .strict(),
      z
        .object({
          kind: z.literal("cli"),
          entrypointPath: z.string().min(1),
          rootPath: z.string().min(1),
          deploymentRevisionDigest: digest,
          timeoutMs: z.number().int().min(1).max(120_000),
          maxOutputBytes: z
            .number()
            .int()
            .min(1_024)
            .max(16 * 1024 * 1024),
        })
        .strict(),
    ]),
    store: z
      .object({
        kind: z.literal("memory"),
        faultMode: z.enum(["none", "probe", "observe"]).default("none"),
      })
      .strict(),
    timeouts: z
      .object({
        inspectionMs: z.number().int().min(1).max(30_000),
        storeMs: z.number().int().min(1).max(30_000),
        evidenceSinkMs: z.number().int().min(1).max(30_000),
      })
      .strict(),
    evidence: z
      .object({
        sink: z.literal("stderr"),
        keyId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u),
      })
      .strict(),
  })
  .strict();

export type IntentAbiConfig = z.infer<typeof intentAbiConfigSchema>;

export function parseIntentAbiConfig(input: unknown): IntentAbiConfig {
  return intentAbiConfigSchema.parse(input);
}
