import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

import type {
  BenchmarkArmRunner,
  BenchmarkReceipt,
} from "@intentabi/benchmark-core";
import { readBoundedRegularFile } from "@intentabi/cli-io";

import {
  createBenchmarkPlan,
  executeCodexBenchmark,
  preflightCodexExecutable,
  projectPlatformRuntimeEnvironment,
  reserveBenchmarkReceipt,
  resolveCodexBenchConfig,
  type BenchmarkReceiptReservation,
  type PreparedExecutable,
  type ResolvedCodexBenchConfig,
} from "./composition.js";
import {
  assertCodexBenchDatasetBudget,
  parseCodexBenchConfig,
  parseCodexBenchDataset,
  type CodexBenchDataset,
} from "./config.js";

export interface CliIo {
  stdout(value: string): void;
  stderr(value: string): void;
}

export interface CodexBenchCliDependencies {
  preflight(
    path: string,
    expectedVersion: string,
    expectedDigest: string,
    platformEnvironment: Readonly<Record<string, string>>,
  ): Promise<PreparedExecutable>;
  execute(input: {
    readonly config: ResolvedCodexBenchConfig;
    readonly dataset: CodexBenchDataset;
    readonly secret: string;
    readonly apiKey: string;
    readonly platformEnvironment: Readonly<Record<string, string>>;
    readonly executable: PreparedExecutable;
    readonly runner?: BenchmarkArmRunner;
  }): Promise<BenchmarkReceipt>;
  reserveReceipt(path: string): Promise<BenchmarkReceiptReservation>;
}

const defaultDependencies: CodexBenchCliDependencies = {
  preflight: preflightCodexExecutable,
  execute: executeCodexBenchmark,
  reserveReceipt: reserveBenchmarkReceipt,
};
const MAX_BENCHMARK_JSON_BYTES = 16 * 1024 * 1024;

export async function runCodexBenchCli(
  argv: readonly string[],
  environment: Readonly<Record<string, string | undefined>>,
  io: CliIo,
  dependencies: CodexBenchCliDependencies = defaultDependencies,
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

    const parsed = parseArguments(argv);
    const configPath = resolve(parsed.configPath);
    const config = parseCodexBenchConfig(await readJson(configPath));
    const dataset = parseCodexBenchDataset(
      await readJson(resolve(parsed.datasetPath)),
    );
    try {
      assertCodexBenchDatasetBudget(config, dataset);
    } catch (error) {
      throw new PublicCliError(
        error instanceof Error
          ? error.message
          : "Dataset exceeds the configured benchmark budget",
      );
    }
    const resolvedConfig = resolveCodexBenchConfig(config, dirname(configPath));

    if (parsed.command === "validate") {
      io.stdout(
        `${JSON.stringify({
          event: "intentabi.codex-bench.validated",
          classification: "research-conformance",
          providerCalls: 0,
          cases: dataset.cases.length,
          split: dataset.split,
          promotionEligible: false,
        })}\n`,
      );
      return 0;
    }

    const secret = environment[config.evidence.hmacSecretEnv];
    if (secret === undefined || Buffer.byteLength(secret) < 32) {
      throw new PublicCliError(
        "The configured benchmark HMAC secret is missing or too short",
      );
    }
    const materialized = createBenchmarkPlan({
      config: resolvedConfig,
      dataset,
      secret,
    });
    if (parsed.command === "plan") {
      io.stdout(
        `${JSON.stringify({
          event: "intentabi.codex-bench.plan",
          providerCalls: 0,
          plan: materialized.plan,
        })}\n`,
      );
      return 0;
    }
    if (parsed.command !== "run") {
      throw new PublicCliError(usage());
    }

    const apiKey = environment[config.codex.authentication.apiKeyEnv];
    if (apiKey === undefined || Buffer.byteLength(apiKey) < 16) {
      throw new PublicCliError(
        "The configured Codex API key is missing or too short",
      );
    }
    const platformEnvironment = projectPlatformRuntimeEnvironment(environment);
    const reservation = await dependencies.reserveReceipt(
      resolve(parsed.outPath),
    );
    let receipt: BenchmarkReceipt;
    try {
      const executable = await dependencies.preflight(
        resolvedConfig.codexPathOverride,
        config.codex.expectedCliVersion,
        config.codex.expectedExecutableDigest,
        platformEnvironment,
      );
      try {
        receipt = await dependencies.execute({
          config: resolvedConfig,
          dataset,
          secret,
          apiKey,
          platformEnvironment,
          executable,
        });
      } finally {
        await executable.release();
      }
      await reservation.commit(receipt);
    } catch (error) {
      await reservation.abort();
      throw error;
    }
    io.stdout(
      `${JSON.stringify({
        event: "intentabi.codex-bench.completed",
        classification: receipt.classification,
        promotionEligible: false,
        promotionManifest: "not-produced",
        summary: receipt.summary,
      })}\n`,
    );
    return receipt.summary.completePairs === receipt.summary.totalCases ? 0 : 2;
  } catch (error) {
    io.stderr(
      `${JSON.stringify({
        event: "intentabi.codex-bench.error",
        message:
          error instanceof PublicCliError
            ? error.message
            : "Codex benchmark command failed",
      })}\n`,
    );
    return 1;
  }
}

type ParsedArguments =
  | Readonly<{
      command: "validate" | "plan";
      configPath: string;
      datasetPath: string;
    }>
  | Readonly<{
      command: "run";
      configPath: string;
      datasetPath: string;
      outPath: string;
    }>;

function parseArguments(argv: readonly string[]): ParsedArguments {
  const command = argv[0];
  if (command !== "validate" && command !== "plan" && command !== "run") {
    throw new PublicCliError(usage());
  }
  const values = new Map<string, string>();
  const flags = new Set<string>();
  for (let index = 1; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "--execute" || token === "--allow-candidate-submission") {
      if (flags.has(token)) throw new PublicCliError(usage());
      flags.add(token);
      continue;
    }
    if (token !== "--config" && token !== "--dataset" && token !== "--out") {
      throw new PublicCliError(usage());
    }
    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--") || values.has(token)) {
      throw new PublicCliError(usage());
    }
    values.set(token, value);
    index += 1;
  }
  const configPath = values.get("--config");
  const datasetPath = values.get("--dataset");
  if (configPath === undefined || datasetPath === undefined) {
    throw new PublicCliError(usage());
  }
  if (command === "run") {
    const outPath = values.get("--out");
    if (
      outPath === undefined ||
      !flags.has("--execute") ||
      !flags.has("--allow-candidate-submission")
    ) {
      throw new PublicCliError(
        "Run requires --execute and --allow-candidate-submission",
      );
    }
    return { command, configPath, datasetPath, outPath };
  }
  if (values.has("--out") || flags.size > 0) {
    throw new PublicCliError(usage());
  }
  return { command, configPath, datasetPath };
}

async function readJson(path: string): Promise<unknown> {
  try {
    const source = await readBoundedRegularFile(path, MAX_BENCHMARK_JSON_BYTES);
    return JSON.parse(Buffer.from(source).toString("utf8"));
  } catch {
    throw new PublicCliError("Benchmark input could not be read");
  }
}

function usage(): string {
  return [
    "Usage:",
    "  intentabi-codex-bench validate --config <path> --dataset <path>",
    "  intentabi-codex-bench plan --config <path> --dataset <path>",
    "  intentabi-codex-bench run --config <path> --dataset <path> --out <path> --execute --allow-candidate-submission",
  ].join("\n");
}

class PublicCliError extends Error {}
