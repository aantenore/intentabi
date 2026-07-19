import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import { runNormalizerPilotCli } from "../src/cli.js";
import { EXAMPLE_DEPLOYMENT_REVISION_DIGEST } from "../src/config.js";
import {
  compiler,
  digest,
  fixturePreparation,
  pilotArtifact,
  pilotConfig,
} from "./support.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function inputs() {
  const directory = await mkdtemp(join(tmpdir(), "intentabi-pilot-test-"));
  temporaryDirectories.push(directory);
  const configPath = join(directory, "config.json");
  const sourcePath = join(directory, "source.json");
  await Promise.all([
    writeFile(configPath, JSON.stringify(pilotConfig())),
    writeFile(sourcePath, "{}"),
  ]);
  return { directory, configPath, sourcePath };
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

describe("normalizer pilot CLI", () => {
  it("validates preparation with zero compiler calls", async () => {
    const { configPath, sourcePath } = await inputs();
    const captured = captureIo();
    const execute = vi.fn();
    const prepare = vi.fn(() => fixturePreparation());
    const compile = vi.fn(() => ({
      status: "bypass" as const,
      reason: "INTENT_NO_MATCH" as const,
    }));
    const selectedCompiler = compiler();
    const createCompiler = vi.fn(() => ({ ...selectedCompiler, compile }));

    const code = await runNormalizerPilotCli(
      ["validate", "--config", configPath, "--source", sourcePath],
      {},
      captured.io,
      { execute, prepare, createCompiler },
    );

    expect(code).toBe(0);
    expect(execute).not.toHaveBeenCalled();
    expect(prepare).toHaveBeenCalledTimes(1);
    expect(createCompiler).toHaveBeenCalledTimes(1);
    expect(compile).not.toHaveBeenCalled();
    expect(JSON.parse(captured.stdout.join(""))).toMatchObject({
      event: "intentabi.normalizer-pilot.validated",
      cases: 2,
      plannedRequests: 6,
      pilotRunBindingDigest: expect.stringMatching(/^sha256:[a-f0-9]{64}$/u),
      compilerCalls: 0,
      executionReady: true,
      statisticalQualification: false,
      economicQualification: false,
      activationAuthorized: false,
    });
  });

  it("requires explicit execution and network authority", async () => {
    const { configPath, sourcePath } = await inputs();
    const captured = captureIo();
    const execute = vi.fn();

    const code = await runNormalizerPilotCli(
      [
        "run",
        "--config",
        configPath,
        "--source",
        sourcePath,
        "--run-dir",
        "pilot-run",
        "--execute",
      ],
      {},
      captured.io,
      { execute },
    );

    expect(code).toBe(1);
    expect(execute).not.toHaveBeenCalled();
    expect(captured.stderr.join("")).toContain("explicit --allow-network");
  });

  it("rejects invalid limits before execution", async () => {
    const { configPath, sourcePath } = await inputs();
    for (const limit of ["-1", "1.5", "01", "9007199254740992"]) {
      const captured = captureIo();
      const execute = vi.fn();
      const code = await runNormalizerPilotCli(
        [
          "run",
          "--config",
          configPath,
          "--source",
          sourcePath,
          "--run-dir",
          "pilot-run",
          "--limit",
          limit,
          "--execute",
          "--allow-network",
        ],
        {},
        captured.io,
        { execute },
      );
      expect(code).toBe(1);
      expect(execute).not.toHaveBeenCalled();
    }
  });

  it("explains why the checked-in deployment placeholder cannot run", async () => {
    const { directory, configPath, sourcePath } = await inputs();
    const config = pilotConfig();
    await writeFile(
      configPath,
      JSON.stringify({
        ...config,
        compiler: {
          ...config.compiler,
          deploymentRevisionDigest: EXAMPLE_DEPLOYMENT_REVISION_DIGEST,
        },
      }),
    );
    const captured = captureIo();
    const execute = vi.fn();

    const code = await runNormalizerPilotCli(
      [
        "run",
        "--config",
        configPath,
        "--source",
        sourcePath,
        "--run-dir",
        join(directory, "run"),
        "--execute",
        "--allow-network",
      ],
      {},
      captured.io,
      { execute },
    );

    expect(code).toBe(1);
    expect(execute).not.toHaveBeenCalled();
    expect(captured.stderr.join("")).toContain(
      "Replace the example deploymentRevisionDigest",
    );
  });

  it("reports resumable progress without claiming a final artifact", async () => {
    const { directory, configPath, sourcePath } = await inputs();
    for (const status of ["incomplete", "indeterminate"] as const) {
      const captured = captureIo();
      const execute = vi.fn(async () => ({
        status,
        progress: progress(2, 6),
        ...(status === "indeterminate"
          ? { checkpointRef: digest("unknown-outcome") }
          : {}),
      }));
      const code = await runNormalizerPilotCli(
        [
          "run",
          "--config",
          configPath,
          "--source",
          sourcePath,
          "--run-dir",
          join(directory, `run-${status}`),
          "--limit",
          "2",
          "--execute",
          "--allow-network",
        ],
        {},
        captured.io,
        { execute },
      );

      expect(code).toBe(status === "incomplete" ? 0 : 1);
      expect(execute).toHaveBeenCalledWith(
        expect.objectContaining({
          runDirectory: join(directory, `run-${status}`),
          limit: 2,
        }),
      );
      const event = JSON.parse(
        (status === "incomplete" ? captured.stdout : captured.stderr).join(""),
      ) as Record<string, unknown>;
      expect(event).toMatchObject({
        event: `intentabi.normalizer-pilot.${status}`,
        status,
        completedObservations: 2,
        remainingObservations: 4,
        artifact: "not-published",
        statisticalQualification: false,
        activationAuthorized: false,
      });
    }
  });

  it("returns distinct success and valid-gate-failure exit codes", async () => {
    const { directory, configPath, sourcePath } = await inputs();
    for (const [passed, expectedCode] of [
      [true, 0],
      [false, 2],
    ] as const) {
      const captured = captureIo();
      const execute = vi.fn(async () => ({
        status: "complete" as const,
        progress: progress(6, 6),
        artifact: pilotArtifact(passed),
      }));
      const code = await runNormalizerPilotCli(
        [
          "run",
          "--config",
          configPath,
          "--source",
          sourcePath,
          "--run-dir",
          join(directory, `run-${String(passed)}`),
          "--limit",
          "0",
          "--execute",
          "--allow-network",
        ],
        {},
        captured.io,
        { execute },
      );

      expect(code).toBe(expectedCode);
      expect(execute).toHaveBeenCalledTimes(1);
      expect(JSON.parse(captured.stdout.join(""))).toMatchObject({
        event: "intentabi.normalizer-pilot.completed",
        decision: passed ? "passed" : "failed",
        statisticalQualification: false,
        economicQualification: false,
        activationAuthorized: false,
        qualificationStatus: "external-evidence-required",
        pilotRunBindingDigest: expect.stringMatching(/^sha256:[a-f0-9]{64}$/u),
        artifact: "published",
      });
      expect(captured.stdout.join("")).not.toContain(
        "Give me the project state",
      );
    }
  });
});

function progress(completed: number, total: number) {
  return Object.freeze({
    evaluationBindingDigest: digest("evaluation-binding"),
    totalObservations: total,
    completedObservations: completed,
    resumedObservations: 0,
    observedThisRun: completed,
    remainingObservations: total - completed,
  });
}
