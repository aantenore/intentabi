import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { readBoundedRegularFile } from "@intentabi/cli-io";

import { parseNormalizerPilotConfig } from "./config.js";
import {
  createNormalizerPilotCompiler,
  executeNormalizerPilot,
  normalizerPilotExecutionReady,
  normalizerPilotRunBindingDigest,
  prepareNormalizerPilot,
  type NormalizerPilotArtifact,
  type NormalizerPilotDependencies,
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
    readonly outputPath: string;
    readonly environment: Readonly<Record<string, string | undefined>>;
    readonly dependencies?: Partial<NormalizerPilotDependencies>;
  }): Promise<NormalizerPilotArtifact>;
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
        config: {
          provider: {
            name: config.compiler.provider.name,
            baseUrl: config.compiler.provider.baseUrl,
            model: config.compiler.provider.model,
            ...(config.compiler.provider.environmentRef === undefined
              ? {}
              : {
                  environmentRef: config.compiler.provider.environmentRef,
                }),
          },
          policy: { ...config.compiler.policy },
        },
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
    const artifact = await dependencies.execute({
      config,
      source,
      outputPath: resolve(arguments_.outputPath),
      environment,
      ...(dependencies.pilotDependencies === undefined
        ? {}
        : { dependencies: dependencies.pilotDependencies }),
    });
    io.stdout(`${JSON.stringify(completedEvent(artifact))}\n`);
    return artifact.evaluation.gate.passed ? 0 : 2;
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
      outputPath: string;
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
    if (token !== "--config" && token !== "--source" && token !== "--out") {
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
    if (execute || allowNetwork || values.has("--out")) {
      throw new NormalizerPilotCliError(normalizerPilotUsage());
    }
    return { command, configPath, sourcePath };
  }
  const outputPath = values.get("--out");
  if (outputPath === undefined || !execute || !allowNetwork) {
    throw new NormalizerPilotCliError(
      "Run requires --out, --execute, and explicit --allow-network",
    );
  }
  return { command, configPath, sourcePath, outputPath };
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
    "       intentabi-normalizer-pilot run --config <path> --source <path> --out <path> --execute --allow-network",
  ].join("\n");
}

class NormalizerPilotCliError extends Error {}
