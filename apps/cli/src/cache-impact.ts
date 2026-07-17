import { dirname, resolve } from "node:path";

import { SemWitnessIntentInspector } from "@intentabi/adapter-semwitness";
import {
  runCacheImpactStudy,
  type CacheImpactCase,
} from "@intentabi/benchmark-core";
import { readBoundedRegularFile } from "@intentabi/cli-io";
import { createHmacOpaqueDigester } from "@intentabi/core";
import { z } from "zod";

import { semWitnessConfigSchema, strictJsonValueSchema } from "./config.js";

const CONFIG_BYTES = 1024 * 1024;
const WORKLOAD_BYTES = 16 * 1024 * 1024;
const REGISTRY_BYTES = 8 * 1024 * 1024;
const digestSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/u);
const routeIdSchema = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u);
const tokenCounterSchema = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);

const cacheImpactConfigSchema = z
  .object({
    schema: z.literal(
      "io.github.aantenore.intentabi/cache-impact-config/v1alpha1",
    ),
    mode: z.literal("shadow"),
    semwitness: semWitnessConfigSchema,
    study: z
      .object({
        keyId: routeIdSchema,
        inspectionTimeoutMs: z.number().int().min(1).max(30_000),
        route: z
          .object({ id: routeIdSchema, revisionDigest: digestSchema })
          .strict(),
      })
      .strict(),
  })
  .strict();

const usageSchema = z
  .object({
    modelInputTokens: tokenCounterSchema,
    modelOutputTokens: tokenCounterSchema,
    normalizationInputTokens: tokenCounterSchema,
    normalizationOutputTokens: tokenCounterSchema,
  })
  .strict();

const cacheImpactWorkloadSchema = z
  .object({
    schema: z.literal(
      "io.github.aantenore.intentabi/cache-impact-workload/v1alpha1",
    ),
    datasetId: routeIdSchema,
    cases: z
      .array(
        z
          .object({
            source: z.string().min(1).max(16_384),
            locale: z
              .string()
              .regex(/^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,4}$/u),
            routeInput: strictJsonValueSchema,
            expectedValueDigest: digestSchema,
            usage: usageSchema,
          })
          .strict(),
      )
      .min(1)
      .max(10_000),
  })
  .strict();

export interface CacheImpactCliIo {
  stdout(value: string): void;
  stderr(value: string): void;
}

export async function runCacheImpactCli(
  argv: readonly string[],
  environment: Readonly<Record<string, string | undefined>>,
  io: CacheImpactCliIo,
): Promise<number> {
  try {
    const options = parseArguments(argv);
    const configPath = resolve(options.configPath);
    const config = cacheImpactConfigSchema.parse(
      await readJson(configPath, CONFIG_BYTES),
    );
    const workload = cacheImpactWorkloadSchema.parse(
      await readJson(resolve(options.workloadPath), WORKLOAD_BYTES),
    );
    const secret = environment[config.semwitness.hmacSecretEnv];
    if (secret === undefined || Buffer.byteLength(secret) < 32) {
      throw new CacheImpactCliError(
        "The configured cache-impact HMAC secret is missing or too short",
      );
    }

    const registrySource = await readText(
      resolve(dirname(configPath), config.semwitness.registryPath),
      REGISTRY_BYTES,
    );
    const inspector = new SemWitnessIntentInspector({
      registrySource,
      policyDigest: config.semwitness.policyDigest as `sha256:${string}`,
      hmacSecret: secret,
      expectedScope: config.semwitness.expectedScope,
      routeBindings: config.semwitness.routeBindings,
    });
    const digester = createHmacOpaqueDigester(secret, config.study.keyId);
    const datasetDigest = digester.digestJson({
      schema: "io.github.aantenore.intentabi/cache-impact-dataset-binding/v1",
      workload,
      policyDigest: config.semwitness.policyDigest,
      scope: config.semwitness.expectedScope,
      scopeEpoch: config.semwitness.scopeEpoch,
      route: config.study.route,
    });
    const cases: readonly CacheImpactCase[] = workload.cases.map(
      (item, ordinal) => ({
        caseRef: digester.digestJson({
          schema: "io.github.aantenore.intentabi/cache-impact-case-ref/v1",
          datasetDigest,
          ordinal,
        }),
        rawKey: digester.digestJson({
          schema: "io.github.aantenore.intentabi/cache-impact-raw-key/v1",
          source: item.source,
          locale: item.locale,
          scope: config.semwitness.expectedScope,
          scopeEpoch: config.semwitness.scopeEpoch,
          route: config.study.route,
          routeInput: item.routeInput,
        }),
        expectedValueDigest: item.expectedValueDigest as `sha256:${string}`,
        request: {
          source: item.source,
          locale: item.locale,
          scope: config.semwitness.expectedScope,
          scopeEpoch: config.semwitness.scopeEpoch,
          route: {
            id: config.study.route.id,
            revisionDigest: config.study.route
              .revisionDigest as `sha256:${string}`,
          },
          routeInput: item.routeInput,
        },
        usage: item.usage,
      }),
    );
    const report = await runCacheImpactStudy({
      cases,
      inspector,
      keyId: config.study.keyId,
      datasetDigest,
      inspectionTimeoutMs: config.study.inspectionTimeoutMs,
      authenticateReport: (unsigned) =>
        digester.digestJson({
          schema: "io.github.aantenore.intentabi/cache-impact-report-mac/v1",
          report: unsigned,
        }),
    });
    io.stdout(
      `${JSON.stringify({ event: "intentabi.cache-impact.report", report })}\n`,
    );
    return report.summary.gate.passed ? 0 : 2;
  } catch (error) {
    io.stderr(
      `${JSON.stringify({
        event: "intentabi.error",
        message:
          error instanceof CacheImpactCliError
            ? error.message
            : "IntentABI cache impact evaluation failed",
      })}\n`,
    );
    return 1;
  }
}

function parseArguments(argv: readonly string[]): {
  readonly configPath: string;
  readonly workloadPath: string;
} {
  if (
    argv[0] !== "cache-impact" ||
    argv[1] !== "evaluate" ||
    argv.length !== 6
  ) {
    throw new CacheImpactCliError(cacheImpactUsage());
  }
  const values = new Map<string, string>();
  for (let index = 2; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (
      (name !== "--config" && name !== "--workload") ||
      value === undefined ||
      value.startsWith("--") ||
      values.has(name)
    ) {
      throw new CacheImpactCliError(cacheImpactUsage());
    }
    values.set(name, value);
  }
  const configPath = values.get("--config");
  const workloadPath = values.get("--workload");
  if (configPath === undefined || workloadPath === undefined) {
    throw new CacheImpactCliError(cacheImpactUsage());
  }
  return { configPath, workloadPath };
}

async function readJson(path: string, maximumBytes: number): Promise<unknown> {
  try {
    return JSON.parse(await readText(path, maximumBytes));
  } catch {
    throw new CacheImpactCliError(
      "Cache-impact input is invalid or unavailable",
    );
  }
}

async function readText(path: string, maximumBytes: number): Promise<string> {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(
      await readBoundedRegularFile(path, maximumBytes),
    );
  } catch {
    throw new CacheImpactCliError(
      "Cache-impact input is invalid or unavailable",
    );
  }
}

export function cacheImpactUsage(): string {
  return "Usage: intentabi cache-impact evaluate --config <path> --workload <path>";
}

class CacheImpactCliError extends Error {}
