import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import {
  readBoundedRegularFile,
  type PrivateArtifactReservation,
} from "@intentabi/cli-io";

import {
  assertQualificationEvidenceBinding,
  createQualificationArtifact,
  executeQualification,
  materializeQualificationPlan,
  reserveQualificationArtifact,
  serializeQualificationArtifact,
  type ExecuteQualificationInput,
  type QualificationExecutionResult,
} from "./composition.js";
import {
  MAX_QUALIFICATION_CONFIG_BYTES,
  MAX_QUALIFICATION_DATASET_BYTES,
  MAX_QUALIFICATION_EVIDENCE_BYTES,
  assertQualificationDatasetBudget,
  assertQualificationEvidenceBudget,
  parseQualificationConfig,
  parseQualificationDataset,
  parseQualificationEvidence,
  type QualificationConfig,
  type QualificationDataset,
} from "./config.js";

export interface QualificationCliIo {
  stdout(value: string): void;
  stderr(value: string): void;
}

export interface QualificationCliDependencies {
  execute(
    input: ExecuteQualificationInput,
  ): Promise<QualificationExecutionResult>;
  reserveArtifact(
    path: string,
    maximumBytes: number,
  ): Promise<PrivateArtifactReservation>;
}

const defaultDependencies: QualificationCliDependencies = Object.freeze({
  execute: executeQualification,
  reserveArtifact: reserveQualificationArtifact,
});

export async function runQualificationCli(
  argv: readonly string[],
  environment: Readonly<Record<string, string | undefined>>,
  io: QualificationCliIo,
  dependencyOverrides: Partial<QualificationCliDependencies> = {},
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

    const dependencies: QualificationCliDependencies = {
      execute: dependencyOverrides.execute ?? defaultDependencies.execute,
      reserveArtifact:
        dependencyOverrides.reserveArtifact ??
        defaultDependencies.reserveArtifact,
    };
    const arguments_ = parseArguments(argv);
    const configInput = await readJsonInput(
      resolve(arguments_.configPath),
      MAX_QUALIFICATION_CONFIG_BYTES,
      "Qualification configuration could not be read",
    );
    const config = parsePublicInput(
      parseQualificationConfig,
      configInput.value,
      "Qualification configuration is invalid",
    );
    const datasetInput = await readJsonInput(
      resolve(arguments_.datasetPath),
      MAX_QUALIFICATION_DATASET_BYTES,
      "Qualification dataset could not be read",
    );
    const dataset = parsePublicInput(
      parseQualificationDataset,
      datasetInput.value,
      "Qualification dataset is invalid",
    );
    assertDatasetBudget(config, dataset, datasetInput.bytes);

    if (arguments_.command === "validate") {
      io.stdout(
        `${JSON.stringify({
          event: "intentabi.qualification.validated",
          classification: "shadow-qualification",
          activationCeiling: "shadow-only",
          authorityCalls: 0,
          executions: 0,
          cases: dataset.cases.length,
          promotionEligible: false,
        })}\n`,
      );
      return 0;
    }

    const secret = environment[config.evidence.hmacSecretEnv];
    if (secret === undefined || Buffer.byteLength(secret, "utf8") < 32) {
      throw new PublicCliError(
        "The configured qualification HMAC secret is missing or too short",
      );
    }
    const materialization = materializeQualificationPlan({
      config,
      dataset,
      secret,
    });

    if (arguments_.command === "plan") {
      io.stdout(
        `${JSON.stringify({
          event: "intentabi.qualification.plan",
          classification: "shadow-qualification",
          activationCeiling: "shadow-only",
          authorityCalls: 0,
          executions: 0,
          planRef: materialization.planRef,
          plan: materialization.plan,
        })}\n`,
      );
      return 0;
    }

    const evidenceInput = await readJsonInput(
      resolve(arguments_.evidencePath),
      MAX_QUALIFICATION_EVIDENCE_BYTES,
      "Qualification evidence could not be read",
    );
    const evidence = parsePublicInput(
      parseQualificationEvidence,
      evidenceInput.value,
      "Qualification evidence is invalid",
    );
    assertEvidenceBudget(config, dataset, evidence, evidenceInput.bytes);
    try {
      assertQualificationEvidenceBinding(materialization, evidence);
    } catch {
      throw new PublicCliError(
        "Qualification evidence is not bound to this plan",
      );
    }

    let reservation: PrivateArtifactReservation;
    try {
      reservation = await dependencies.reserveArtifact(
        resolve(arguments_.outPath),
        config.qualification.maxArtifactBytes,
      );
    } catch {
      throw new PublicCliError("Qualification output could not be reserved");
    }

    let result: QualificationExecutionResult;
    try {
      result = await dependencies.execute({
        config,
        dataset,
        evidence,
        secret,
        materialization,
      });
      const artifact = createQualificationArtifact(result);
      const bytes = serializeQualificationArtifact(
        artifact,
        config.qualification.maxArtifactBytes,
      );
      await reservation.commit(bytes);
    } catch {
      await reservation.abort();
      throw new PublicCliError("Qualification execution failed");
    }

    io.stdout(
      `${JSON.stringify({
        event: "intentabi.qualification.completed",
        classification: "shadow-qualification",
        activationCeiling: "shadow-only",
        activationAuthorized: false,
        decision: result.receipt.authority.decision,
        runId: result.receipt.runId,
        authority: {
          id: result.receipt.authority.authority.id,
          version: result.receipt.authority.authority.version,
          reportDigest: result.receipt.authority.reportDigest,
        },
        artifact: "published",
      })}\n`,
    );
    return result.receipt.authority.decision === "qualified" ? 0 : 2;
  } catch (error) {
    io.stderr(
      `${JSON.stringify({
        event: "intentabi.qualification.error",
        message:
          error instanceof PublicCliError
            ? error.message
            : "Qualification command failed",
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
      command: "plan";
      configPath: string;
      datasetPath: string;
    }>
  | Readonly<{
      command: "run";
      configPath: string;
      datasetPath: string;
      evidencePath: string;
      outPath: string;
    }>;

function parseArguments(argv: readonly string[]): ParsedArguments {
  const command = argv[0];
  if (command !== "validate" && command !== "plan" && command !== "run") {
    throw new PublicCliError(usage());
  }
  const values = new Map<string, string>();
  let execute = false;
  for (let index = 1; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "--execute") {
      if (execute) throw new PublicCliError(usage());
      execute = true;
      continue;
    }
    if (
      token !== "--config" &&
      token !== "--dataset" &&
      token !== "--evidence" &&
      token !== "--out"
    ) {
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
  if (command !== "run") {
    if (execute || values.has("--evidence") || values.has("--out")) {
      throw new PublicCliError(usage());
    }
    return { command, configPath, datasetPath };
  }

  const evidencePath = values.get("--evidence");
  const outPath = values.get("--out");
  if (evidencePath === undefined || outPath === undefined || !execute) {
    throw new PublicCliError(
      "Run requires --evidence, --out, and explicit --execute",
    );
  }
  return { command, configPath, datasetPath, evidencePath, outPath };
}

async function readJsonInput(
  path: string,
  maximumBytes: number,
  publicMessage: string,
): Promise<{ readonly value: unknown; readonly bytes: number }> {
  try {
    const bytes = await readBoundedRegularFile(path, maximumBytes);
    const source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return { value: JSON.parse(source) as unknown, bytes: bytes.byteLength };
  } catch {
    throw new PublicCliError(publicMessage);
  }
}

function parsePublicInput<T>(
  parser: (value: unknown) => T,
  value: unknown,
  publicMessage: string,
): T {
  try {
    return parser(value);
  } catch {
    throw new PublicCliError(publicMessage);
  }
}

function assertDatasetBudget(
  config: QualificationConfig,
  dataset: QualificationDataset,
  encodedBytes: number,
): void {
  try {
    assertQualificationDatasetBudget(config, dataset, encodedBytes);
  } catch {
    throw new PublicCliError("Qualification dataset exceeds its budget");
  }
}

function assertEvidenceBudget(
  config: QualificationConfig,
  dataset: QualificationDataset,
  evidence: ReturnType<typeof parseQualificationEvidence>,
  encodedBytes: number,
): void {
  try {
    assertQualificationEvidenceBudget(config, dataset, evidence, encodedBytes);
  } catch {
    throw new PublicCliError("Qualification evidence exceeds its budget");
  }
}

function usage(): string {
  return [
    "Usage:",
    "  intentabi-qualify validate --config <path> --dataset <path>",
    "  intentabi-qualify plan --config <path> --dataset <path>",
    "  intentabi-qualify run --config <path> --dataset <path> --evidence <path> --out <path> --execute",
  ].join("\n");
}

class PublicCliError extends Error {}
