import {
  access,
  lstat,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import type { SemWitnessQualificationArtifact } from "@intentabi/adapter-semwitness";
import { QUALIFICATION_RECEIPT_SCHEMA } from "@intentabi/qualification-core";
import { afterEach, describe, expect, it, vi } from "vitest";

import { runQualificationCli } from "../src/cli.js";
import {
  materializeQualificationPlan,
  type ExecuteQualificationInput,
  type QualificationExecutionResult,
} from "../src/composition.js";
import {
  QUALIFICATION_EVIDENCE_SCHEMA,
  parseQualificationConfig,
  parseQualificationDataset,
} from "../src/config.js";

const configPath = fileURLToPath(
  new URL("./fixtures/config.json", import.meta.url),
);
const datasetPath = fileURLToPath(
  new URL("./fixtures/dataset.json", import.meta.url),
);
const secret = "qualification-secret-32-bytes-minimum-value";
const digest = (character: string) => `sha256:${character.repeat(64)}` as const;
const hmac = (character: string) =>
  `hmac-sha256:evidence:${character.repeat(64)}` as const;
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function temporaryDirectory(): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), "intentabi-qualification-test-"));
  temporaryDirectories.push(path);
  return path;
}

async function fixtureMaterialization() {
  const [configSource, datasetSource] = await Promise.all([
    readFile(configPath, "utf8"),
    readFile(datasetPath, "utf8"),
  ]);
  const config = parseQualificationConfig(JSON.parse(configSource));
  const dataset = parseQualificationDataset(JSON.parse(datasetSource));
  const materialization = materializeQualificationPlan({
    config,
    dataset,
    secret,
  });
  return { config, dataset, materialization };
}

async function evidenceFile(directory: string): Promise<string> {
  const { materialization } = await fixtureMaterialization();
  const path = join(directory, "private-evidence.json");
  await writeFile(
    path,
    JSON.stringify({
      schema: QUALIFICATION_EVIDENCE_SCHEMA,
      classification: "private-held-out",
      planRef: materialization.planRef,
      attestation: { sealed: "PRIVATE_ATTESTATION_CANARY" },
      records: [
        { sealed: "PRIVATE_RECORD_ALPHA_CANARY" },
        { sealed: "PRIVATE_RECORD_BETA_CANARY" },
      ],
    }),
    { mode: 0o600 },
  );
  return path;
}

function exactSemWitnessArtifact(): SemWitnessQualificationArtifact {
  return Object.freeze({
    evidenceJsonl: "PRIVATE_EXACT_SEMWITNESS_EVIDENCE_CANARY\n",
    workbench: Object.freeze({
      privateWorkbench: "PRIVATE_EXACT_WORKBENCH_CANARY",
    }),
  }) as unknown as SemWitnessQualificationArtifact;
}

function executionResult(
  input: ExecuteQualificationInput,
  decision: "qualified" | "unqualified",
): QualificationExecutionResult {
  const authority = {
    authority: {
      id: "semwitness-intent-cache-promotion-evaluator",
      version: "1",
    },
    activationCeiling: "shadow-only" as const,
    decision,
    evidenceDigest: digest("a"),
    bindingDigest: digest("b"),
    reportDigest: digest("c"),
    ...(decision === "qualified" ? { qualificationDigest: digest("d") } : {}),
  };
  return Object.freeze({
    planRef: input.materialization.planRef,
    receipt: Object.freeze({
      schema: QUALIFICATION_RECEIPT_SCHEMA,
      classification: "shadow-qualification" as const,
      activationCeiling: "shadow-only" as const,
      activationAuthorized: false as const,
      runId: "00000000-0000-4000-8000-000000000001",
      keyId: input.materialization.plan.keyId,
      datasetDigest: input.materialization.plan.datasetDigest,
      protocolDigest: input.materialization.plan.protocolDigest,
      executableDigest: digest("e"),
      authority: Object.freeze(authority),
      cases: Object.freeze(
        input.materialization.plan.cases.map((item, ordinal) =>
          Object.freeze({
            ordinal,
            caseRef: item.caseRef,
            recordDigest: digest(String(ordinal + 1)),
          }),
        ),
      ),
      receiptMac: hmac("f"),
    }),
    semwitness: exactSemWitnessArtifact(),
  });
}

function captureIo() {
  const stdout: string[] = [];
  const stderr: string[] = [];
  return {
    stdout,
    stderr,
    io: {
      stdout: (value: string) => stdout.push(value),
      stderr: (value: string) => stderr.push(value),
    },
  };
}

describe("intentabi-qualify CLI", () => {
  it("validates without reading secrets and emits a content-free HMAC plan", async () => {
    const validated = captureIo();
    let environmentReads = 0;
    const hostileEnvironment = new Proxy(
      {},
      {
        get: () => {
          environmentReads += 1;
          throw new Error("PRIVATE_ENVIRONMENT_CANARY");
        },
      },
    );
    const validateCode = await runQualificationCli(
      ["validate", "--config", configPath, "--dataset", datasetPath],
      hostileEnvironment,
      validated.io,
    );
    expect(validateCode).toBe(0);
    expect(environmentReads).toBe(0);
    expect(validated.stderr).toEqual([]);
    expect(validated.stdout.join("")).toContain('"executions":0');

    const planned = captureIo();
    const planCode = await runQualificationCli(
      ["plan", "--config", configPath, "--dataset", datasetPath],
      { QUALIFICATION_HMAC_SECRET: secret },
      planned.io,
    );
    const output = planned.stdout.join("");
    expect(planCode).toBe(0);
    expect(planned.stderr).toEqual([]);
    expect(output).toMatch(/hmac-sha256:evidence:[a-f0-9]{64}/u);
    expect(output).not.toContain("PRIVATE_DATASET_CANARY");
    expect(output).not.toContain("PRIVATE_CASE_ALPHA_CANARY");
    expect(output).not.toContain("PRIVATE_BALANCE_CELL_CANARY");
    expect(output).not.toContain(secret);
  });

  it("requires explicit execution authority and rejects arbitrary CLI surfaces", async () => {
    const execute = vi.fn();
    const captured = captureIo();
    const code = await runQualificationCli(
      [
        "run",
        "--config",
        configPath,
        "--dataset",
        datasetPath,
        "--evidence",
        "PRIVATE_EVIDENCE_PATH_CANARY",
        "--out",
        "PRIVATE_OUTPUT_PATH_CANARY",
      ],
      { QUALIFICATION_HMAC_SECRET: secret },
      captured.io,
      { execute },
    );
    expect(code).toBe(1);
    expect(execute).not.toHaveBeenCalled();
    expect(captured.stderr.join("")).toContain("explicit --execute");
    expect(captured.stderr.join("")).not.toContain("PRIVATE_");

    const arbitrary = captureIo();
    const arbitraryCode = await runQualificationCli(
      [
        "plan",
        "--config",
        configPath,
        "--dataset",
        datasetPath,
        "--module",
        "PRIVATE_MODULE_CANARY",
      ],
      { QUALIFICATION_HMAC_SECRET: secret },
      arbitrary.io,
    );
    expect(arbitraryCode).toBe(1);
    expect(arbitrary.stderr.join("")).not.toContain("PRIVATE_MODULE_CANARY");
  });

  it("reserves before authority work and atomically publishes exact 0600 evidence", async () => {
    const directory = await temporaryDirectory();
    const evidencePath = await evidenceFile(directory);
    const outPath = join(directory, "qualification-artifact.json");
    const captured = captureIo();
    let startExecution!: () => void;
    let releaseExecution!: () => void;
    const started = new Promise<void>((resolve) => {
      startExecution = resolve;
    });
    const release = new Promise<void>((resolve) => {
      releaseExecution = resolve;
    });

    const running = runQualificationCli(
      [
        "run",
        "--config",
        configPath,
        "--dataset",
        datasetPath,
        "--evidence",
        evidencePath,
        "--out",
        outPath,
        "--execute",
      ],
      { QUALIFICATION_HMAC_SECRET: secret },
      captured.io,
      {
        execute: async (input) => {
          startExecution();
          await release;
          return executionResult(input, "unqualified");
        },
      },
    );

    await started;
    await expect(access(outPath)).rejects.toMatchObject({ code: "ENOENT" });
    releaseExecution();
    const code = await running;

    expect(code).toBe(2);
    expect(captured.stderr).toEqual([]);
    expect(captured.stdout.join("")).toContain('"decision":"unqualified"');
    expect(captured.stdout.join("")).not.toContain("PRIVATE_");
    if (process.platform !== "win32") {
      expect((await stat(outPath)).mode & 0o777).toBe(0o600);
    }
    const published = JSON.parse(await readFile(outPath, "utf8")) as {
      semwitness: unknown;
      activationAuthorized: boolean;
    };
    expect(published.semwitness).toEqual(exactSemWitnessArtifact());
    expect(published.activationAuthorized).toBe(false);
    expect((await readdir(directory)).sort()).toEqual([
      "private-evidence.json",
      "qualification-artifact.json",
    ]);
  });

  it("returns zero only for qualified shadow evidence and masks private failures", async () => {
    const directory = await temporaryDirectory();
    const evidencePath = await evidenceFile(directory);
    const qualifiedPath = join(directory, "qualified.json");
    const qualified = captureIo();
    const qualifiedCode = await runQualificationCli(
      [
        "run",
        "--config",
        configPath,
        "--dataset",
        datasetPath,
        "--evidence",
        evidencePath,
        "--out",
        qualifiedPath,
        "--execute",
      ],
      { QUALIFICATION_HMAC_SECRET: secret },
      qualified.io,
      { execute: async (input) => executionResult(input, "qualified") },
    );
    expect(qualifiedCode).toBe(0);
    expect(qualified.stdout.join("")).toContain('"decision":"qualified"');
    expect(qualified.stdout.join("")).toContain('"activationAuthorized":false');

    const failedPath = join(directory, "failed.json");
    const failed = captureIo();
    const failedCode = await runQualificationCli(
      [
        "run",
        "--config",
        configPath,
        "--dataset",
        datasetPath,
        "--evidence",
        evidencePath,
        "--out",
        failedPath,
        "--execute",
      ],
      { QUALIFICATION_HMAC_SECRET: secret },
      failed.io,
      {
        execute: async () => {
          throw new Error("PRIVATE_AUTHORITY_FAILURE_CANARY");
        },
      },
    );
    expect(failedCode).toBe(1);
    expect(failed.stdout).toEqual([]);
    expect(failed.stderr.join("")).toContain("Qualification execution failed");
    expect(failed.stderr.join("")).not.toContain("PRIVATE_");
    await expect(lstat(failedPath)).rejects.toMatchObject({ code: "ENOENT" });
  });
});
