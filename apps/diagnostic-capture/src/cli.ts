import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { readBoundedRegularFile } from "@intentabi/cli-io";

import {
  assertDiagnosticDatasetBudget,
  MAX_DIAGNOSTIC_CONFIG_BYTES,
  MAX_DIAGNOSTIC_DATASET_BYTES,
  parseDiagnosticCaptureConfig,
  parseDiagnosticCaptureDataset,
  type DiagnosticCaptureConfig,
  type DiagnosticCaptureDataset,
} from "./config.js";
import {
  assertDiagnosticArtifactBudgets,
  captureDiagnosticPilot,
  type DiagnosticCaptureResult,
} from "./capture.js";
import {
  createOpenAICompatibleDiagnosticRunner,
  DiagnosticProviderError,
  type DiagnosticProviderRunner,
} from "./provider.js";

export interface DiagnosticCaptureCliIo {
  stdout(value: string): void;
  stderr(value: string): void;
}

export interface DiagnosticCaptureCliDependencies {
  createRunner(
    config: DiagnosticCaptureConfig,
    environment: Readonly<Record<string, string | undefined>>,
  ): DiagnosticProviderRunner;
  capture(input: {
    readonly config: DiagnosticCaptureConfig;
    readonly dataset: DiagnosticCaptureDataset;
    readonly runDirectory: string;
    readonly runner: DiagnosticProviderRunner;
    readonly limit?: number;
  }): Promise<DiagnosticCaptureResult>;
}

const defaultDependencies: DiagnosticCaptureCliDependencies = Object.freeze({
  createRunner: createOpenAICompatibleDiagnosticRunner,
  capture: captureDiagnosticPilot,
});

export async function runDiagnosticCaptureCli(
  argv: readonly string[],
  environment: Readonly<Record<string, string | undefined>>,
  io: DiagnosticCaptureCliIo,
  overrides: Partial<DiagnosticCaptureCliDependencies> = {},
): Promise<number> {
  try {
    if (argv.length === 1 && argv[0] === "--help") {
      io.stdout(`${usage()}\n`);
      return 0;
    }
    if (argv.length === 1 && argv[0] === "--version") {
      const manifest = JSON.parse(
        await readFile(new URL("../package.json", import.meta.url), "utf8"),
      ) as { version?: unknown };
      if (typeof manifest.version !== "string") throw new Error();
      io.stdout(`${manifest.version}\n`);
      return 0;
    }

    const arguments_ = parseArguments(argv);
    const configInput = await readJson(
      resolve(arguments_.configPath),
      MAX_DIAGNOSTIC_CONFIG_BYTES,
    );
    const datasetInput = await readJson(
      resolve(arguments_.datasetPath),
      MAX_DIAGNOSTIC_DATASET_BYTES,
    );
    const config = parseDiagnosticCaptureConfig(configInput.value);
    const dataset = parseDiagnosticCaptureDataset(datasetInput.value);
    assertDiagnosticDatasetBudget(config, dataset, datasetInput.bytes);

    if (arguments_.command === "validate") {
      assertDiagnosticArtifactBudgets(config, dataset);
      io.stdout(
        `${JSON.stringify({
          event: "intentabi.diagnostic-capture.validated",
          classification: "diagnostic-held-out-pilot",
          statisticalQualification: false,
          activationAuthorized: false,
          providerCalls: 0,
          cases: dataset.cases.length,
        })}\n`,
      );
      return 0;
    }

    const dependencies: DiagnosticCaptureCliDependencies = {
      createRunner: overrides.createRunner ?? defaultDependencies.createRunner,
      capture: overrides.capture ?? defaultDependencies.capture,
    };
    const runner = dependencies.createRunner(config, environment);
    const result = await dependencies.capture({
      config,
      dataset,
      runDirectory: resolve(arguments_.runDirectory),
      runner,
      ...(arguments_.limit === undefined ? {} : { limit: arguments_.limit }),
    });
    io.stdout(
      `${JSON.stringify({
        event: "intentabi.diagnostic-capture.completed",
        ...result,
      })}\n`,
    );
    return result.complete && !result.workloadProduced ? 2 : 0;
  } catch (error) {
    io.stderr(
      `${JSON.stringify({
        event: "intentabi.diagnostic-capture.error",
        message: "Diagnostic capture failed",
        reason:
          error instanceof DiagnosticProviderError
            ? error.code
            : "CAPTURE_FAILED",
      })}\n`,
    );
    return 1;
  }
}

type ParsedArguments =
  | Readonly<{
      command: "validate";
      configPath: string;
      datasetPath: string;
    }>
  | Readonly<{
      command: "run";
      configPath: string;
      datasetPath: string;
      runDirectory: string;
      limit?: number;
    }>;

function parseArguments(argv: readonly string[]): ParsedArguments {
  const command = argv[0];
  if (command !== "validate" && command !== "run") {
    throw new Error();
  }
  const values = new Map<string, string>();
  let execute = false;
  for (let index = 1; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "--execute") {
      if (execute) throw new Error();
      execute = true;
      continue;
    }
    if (
      token !== "--config" &&
      token !== "--dataset" &&
      token !== "--run-dir" &&
      token !== "--limit"
    ) {
      throw new Error();
    }
    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--") || values.has(token)) {
      throw new Error();
    }
    values.set(token, value);
    index += 1;
  }
  const configPath = values.get("--config");
  const datasetPath = values.get("--dataset");
  if (configPath === undefined || datasetPath === undefined) throw new Error();
  if (command === "validate") {
    if (execute || values.has("--run-dir") || values.has("--limit")) {
      throw new Error();
    }
    return { command, configPath, datasetPath };
  }
  const runDirectory = values.get("--run-dir");
  if (runDirectory === undefined || !execute) throw new Error();
  const limitSource = values.get("--limit");
  const limit = limitSource === undefined ? undefined : Number(limitSource);
  if (
    limit !== undefined &&
    (!/^[1-9][0-9]*$/u.test(limitSource!) ||
      !Number.isSafeInteger(limit) ||
      limit < 1)
  ) {
    throw new Error();
  }
  return {
    command,
    configPath,
    datasetPath,
    runDirectory,
    ...(limit === undefined ? {} : { limit }),
  };
}

async function readJson(
  path: string,
  maximumBytes: number,
): Promise<{ readonly value: unknown; readonly bytes: number }> {
  const bytes = await readBoundedRegularFile(path, maximumBytes);
  return {
    value: JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(bytes),
    ) as unknown,
    bytes: bytes.byteLength,
  };
}

export function diagnosticCaptureUsage(): string {
  return [
    "Usage: intentabi-diagnostic-capture validate --config <path> --dataset <path>",
    "Usage: intentabi-diagnostic-capture run --config <path> --dataset <path> --run-dir <private-directory> [--limit <cases>] --execute",
  ].join("\n");
}

function usage(): string {
  return diagnosticCaptureUsage();
}
