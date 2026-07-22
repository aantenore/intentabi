import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { readBoundedRegularFile } from "@intentabi/cli-io";

import { parseNormalizerPilotConfig } from "./config.js";
import {
  createNormalizerPilotCompiler,
  executeNormalizerPilot,
  normalizerPilotCompilerConfig,
  normalizerPilotExecutionReady,
  normalizerPilotRunBindingDigest,
  prepareNormalizerPilot,
  type NormalizerPilotArtifact,
  type NormalizerPilotDependencies,
  type NormalizerPilotExecutionResult,
} from "./pilot.js";

const MAX_CONFIG_BYTES = 1024 * 1024;
const MAX_SOURCE_BYTES = 32 * 1024 * 1024;

export interface NormalizerPilotCliIo {
  stdout(value: string): void;
  stderr(value: string): void;
}

export interface NormalizerPilotCliDependencies {
  execute(input: {
    readonly config: ReturnType<typeof parseNormalizerPilotConfig>;
    readonly source: Uint8Array;
    readonly runDirectory: string;
    readonly limit?: number;
    readonly environment: Readonly<Record<string, string | undefined>>;
    readonly dependencies?: Partial<NormalizerPilotDependencies>;
  }): Promise<NormalizerPilotExecutionResult>;
  prepare?: typeof prepareNormalizerPilot;
  createCompiler?: typeof createNormalizerPilotCompiler;
  pilotDependencies?: Partial<NormalizerPilotDependencies>;
}

const defaultDependencies: NormalizerPilotCliDependencies = Object.freeze({
  execute: executeNormalizerPilot,
});

export async function runNormalizerPilotCli(
  argv: readonly string[],
  environment: Readonly<Record<string, string | undefined>>,
  io: NormalizerPilotCliIo,
  overrides: Partial<NormalizerPilotCliDependencies> = {},
): Promise<number> {
  try {
    if (argv.length === 1 && argv[0] === "--help") {
      io.stdout(`${normalizerPilotUsage()}\n`);
      return 0;
    }
    if (argv.length === 1 && argv[0] === "--version") {
      const manifest = await readJson(
        new URL("../package.json", import.meta.url),
        MAX_CONFIG_BYTES,
      );
      if (!isRecord(manifest) || typeof manifest.version !== "string") {
        throw new Error();
      }
      io.stdout(`${manifest.version}\n`);
      return 0;
    }

    const arguments_ = parseArguments(argv);
    const config = parseNormalizerPilotConfig(
      await readJson(resolve(arguments_.configPath), MAX_CONFIG_BYTES),
    );
    if (
      arguments_.command === "run" &&
      !normalizerPilotExecutionReady(config)
    ) {
      throw new NormalizerPilotCliError(
        "Replace the example deploymentRevisionDigest before run",
      );
    }
    const source = await readBoundedRegularFile(
      resolve(arguments_.sourcePath),
      MAX_SOURCE_BYTES,
    );

    if (arguments_.command === "validate") {
      const preparation = (overrides.prepare ?? prepareNormalizerPilot)(
        config,
        source,
      );
      const compiler = (
        overrides.createCompiler ?? createNormalizerPilotCompiler
      )({
        registrySource: preparation.prepared.registrySource,
        config: normalizerPilotCompilerConfig(config),
        environment: Object.freeze({}),
      });
      io.stdout(
        `${JSON.stringify({
          event: "intentabi.normalizer-pilot.validated",
          classification: "external-normalizer-diagnostic",
          source: { kind: "clinc150", revision: config.source.revision },
          cases: preparation.prepared.cases,
          comparisons: preparation.prepared.comparisons,
          plannedRequests: preparation.plannedRequests,
          pilotRunBindingDigest: normalizerPilotRunBindingDigest(
            config,
            preparation,
            compiler.manifest,
          ),
          compilerCalls: 0,
          executionReady: normalizerPilotExecutionReady(config),
          statisticalQualification: false,
          economicQualification: false,
          activationAuthorized: false,
        })}\n`,
      );
      return 0;
    }

    const dependencies: NormalizerPilotCliDependencies = {
      execute: overrides.execute ?? defaultDependencies.execute,
      ...(overrides.pilotDependencies === undefined
        ? {}
        : { pilotDependencies: overrides.pilotDependencies }),
    };
    const result = await dependencies.execute({
      config,
      source,
      runDirectory: resolve(arguments_.runDirectory),
      ...(arguments_.limit === undefined ? {} : { limit: arguments_.limit }),
      environment,
      ...(dependencies.pilotDependencies === undefined
        ? {}
        : { dependencies: dependencies.pilotDependencies }),
    });
    if (result.status === "incomplete") {
      io.stdout(
        `${JSON.stringify(progressEvent("incomplete", result.progress))}\n`,
      );
      return 0;
    }
    if (result.status === "indeterminate") {
      io.stderr(
        `${JSON.stringify({
          ...progressEvent("indeterminate", result.progress),
          checkpointRef: result.checkpointRef,
        })}\n`,
      );
      return 1;
    }
    io.stdout(`${JSON.stringify(completedEvent(result.artifact))}\n`);
    return result.artifact.evaluation.gate.passed ? 0 : 2;
  } catch (error) {
    io.stderr(
      `${JSON.stringify({
        event: "intentabi.normalizer-pilot.error",
        message:
          error instanceof NormalizerPilotCliError
            ? error.message
            : "Normalizer pilot failed",
      })}\n`,
    );
    return 1;
  }
}

type ParsedArguments =
  | Readonly<{
      command: "validate";
      configPath: string;
      sourcePath: string;
    }>
  | Readonly<{
      command: "run";
      configPath: string;
      sourcePath: string;
      runDirectory: string;
      limit?: number;
    }>;

function parseArguments(argv: readonly string[]): ParsedArguments {
  const command = argv[0];
  if (command !== "validate" && command !== "run") {
    throw new NormalizerPilotCliError(normalizerPilotUsage());
  }
  const values = new Map<string, string>();
  let execute = false;
  let allowNetwork = false;
  for (let index = 1; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "--execute" || token === "--allow-network") {
      if (
        (token === "--execute" && execute) ||
        (token === "--allow-network" && allowNetwork)
      ) {
        throw new NormalizerPilotCliError(normalizerPilotUsage());
      }
      if (token === "--execute") execute = true;
      if (token === "--allow-network") allowNetwork = true;
      continue;
    }
    if (
      token !== "--config" &&
      token !== "--source" &&
      token !== "--run-dir" &&
      token !== "--limit"
    ) {
      throw new NormalizerPilotCliError(normalizerPilotUsage());
    }
    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--") || values.has(token)) {
      throw new NormalizerPilotCliError(normalizerPilotUsage());
    }
    values.set(token, value);
    index += 1;
  }
  const configPath = values.get("--config");
  const sourcePath = values.get("--source");
  if (configPath === undefined || sourcePath === undefined) {
    throw new NormalizerPilotCliError(normalizerPilotUsage());
  }
  if (command === "validate") {
    if (
      execute ||
      allowNetwork ||
      values.has("--run-dir") ||
      values.has("--limit")
    ) {
      throw new NormalizerPilotCliError(normalizerPilotUsage());
    }
    return { command, configPath, sourcePath };
  }
  const runDirectory = values.get("--run-dir");
  if (runDirectory === undefined || !execute || !allowNetwork) {
    throw new NormalizerPilotCliError(
      "Run requires --run-dir, --execute, and explicit --allow-network",
    );
  }
  const rawLimit = values.get("--limit");
  const limit = rawLimit === undefined ? undefined : parseLimit(rawLimit);
  return {
    command,
    configPath,
    sourcePath,
    runDirectory,
    ...(limit === undefined ? {} : { limit }),
  };
}

function parseLimit(value: string): number {
  if (!/^(?:0|[1-9][0-9]*)$/u.test(value)) {
    throw new NormalizerPilotCliError(normalizerPilotUsage());
  }
  const limit = Number(value);
  if (!Number.isSafeInteger(limit)) {
    throw new NormalizerPilotCliError(normalizerPilotUsage());
  }
  return limit;
}

function completedEvent(artifact: NormalizerPilotArtifact) {
  const evaluation = artifact.evaluation;
  return Object.freeze({
    event: "intentabi.normalizer-pilot.completed",
    classification: artifact.classification,
    decision: evaluation.gate.passed ? "passed" : "failed",
    corpusDigest: artifact.source.corpusDigest,
    pilotRunBindingDigest: artifact.pilotRunBindingDigest,
    semwitnessNormalizerBindingDigest: evaluation.normalizerBindingDigest,
    cases: evaluation.caseMetrics.total,
    exactIntentAccuracyPpm: evaluation.caseMetrics.exactIntentAccuracyPpm,
    bypassAccuracyPpm: evaluation.caseMetrics.bypassAccuracyPpm,
    convergenceRecallPpm: evaluation.comparisonMetrics.convergenceRecallPpm,
    falseMerges: evaluation.comparisonMetrics.falseMerges,
    unsafeAccepts: evaluation.caseMetrics.unsafeAccepts,
    expectedBypass: evaluation.caseMetrics.expectedBypass,
    correctBypasses: evaluation.caseMetrics.correctBypasses,
    inScopeCases: artifact.source.inScopeCases,
    outOfScopeCases: artifact.source.outOfScopeCases,
    repeatabilityFailures: evaluation.caseMetrics.repeatabilityFailures,
    statisticalQualification: false,
    economicQualification: false,
    activationAuthorized: false,
    qualificationStatus: artifact.qualificationStatus,
    artifact: "published",
  });
}

function progressEvent(
  status: "incomplete" | "indeterminate",
  progress: NormalizerPilotExecutionResult["progress"],
) {
  return Object.freeze({
    event: `intentabi.normalizer-pilot.${status}`,
    classification: "external-normalizer-diagnostic",
    status,
    evaluationBindingDigest: progress.evaluationBindingDigest,
    totalObservations: progress.totalObservations,
    completedObservations: progress.completedObservations,
    observedThisRun: progress.observedThisRun,
    resumedObservations: progress.resumedObservations,
    remainingObservations: progress.remainingObservations,
    statisticalQualification: false,
    economicQualification: false,
    activationAuthorized: false,
    artifact: "not-published",
  });
}

async function readJson(path: string | URL, maximumBytes: number) {
  try {
    const bytes =
      typeof path === "string"
        ? await readBoundedRegularFile(path, maximumBytes)
        : new Uint8Array(await readFile(path));
    if (bytes.byteLength > maximumBytes) throw new Error();
    return JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(bytes),
    ) as unknown;
  } catch {
    throw new NormalizerPilotCliError(
      "Normalizer pilot input is invalid or unavailable",
    );
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function normalizerPilotUsage(): string {
  return [
    "Usage: intentabi-normalizer-pilot validate --config <path> --source <path>",
    "       intentabi-normalizer-pilot run --config <path> --source <path> --run-dir <path> [--limit <new-observations>] --execute --allow-network",
  ].join("\n");
}

class NormalizerPilotCliError extends Error {}
