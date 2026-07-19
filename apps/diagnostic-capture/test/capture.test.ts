import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  parseDiagnosticCaptureConfig,
  parseDiagnosticCaptureDataset,
} from "../src/config.js";
import {
  assertDiagnosticArtifactBudgets,
  captureDiagnosticPilot,
} from "../src/capture.js";
import type {
  DiagnosticProviderObservation,
  DiagnosticProviderRunner,
} from "../src/provider.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

describe("diagnostic capture", () => {
  it("resumes append-only records and deterministically assembles the existing workload", async () => {
    const directory = privateTemporaryDirectory();
    const runDirectory = resolve(directory, "run");
    const { config, dataset } = fixtures();
    let calls = 0;
    const runner = matchingRunner(() => {
      calls += 1;
    });
    try {
      const first = await captureDiagnosticPilot({
        config,
        dataset,
        runDirectory,
        runner,
        limit: 1,
      });
      expect(first).toMatchObject({
        complete: false,
        capturedThisRun: 1,
        resumedCases: 0,
        remainingCases: 3,
        statisticalQualification: false,
        activationAuthorized: false,
      });
      expect(
        existsSync(resolve(runDirectory, "cache-impact-workload.json")),
      ).toBe(false);

      const second = await captureDiagnosticPilot({
        config,
        dataset,
        runDirectory,
        runner,
      });
      expect(second).toMatchObject({
        complete: true,
        workloadProduced: true,
        capturedThisRun: 3,
        resumedCases: 1,
        remainingCases: 0,
        oracleMismatches: 0,
      });
      expect(calls).toBe(4);

      const workloadPath = resolve(runDirectory, "cache-impact-workload.json");
      const workloadBytes = readFileSync(workloadPath);
      const workload = JSON.parse(workloadBytes.toString("utf8"));
      expect(workload).toMatchObject({
        schema: "io.github.aantenore.intentabi/cache-impact-workload/v1alpha1",
        datasetId: "project-status-provider-smoke-v1",
      });
      expect(workload.cases).toHaveLength(4);
      expect(workload.cases[0]).toMatchObject({
        usage: {
          modelInputTokens: 17,
          modelOutputTokens: 9,
          normalizationInputTokens: 0,
          normalizationOutputTokens: 0,
        },
      });

      const records = readdirSync(resolve(runDirectory, "records")).sort();
      expect(records).toHaveLength(4);
      const recordSource = readFileSync(
        resolve(runDirectory, "records", records[0]!),
        "utf8",
      );
      expect(recordSource).not.toContain("Show the current project status");
      expect(recordSource).not.toContain("private chain");
      expect(JSON.parse(recordSource)).toMatchObject({
        classification: "diagnostic-held-out-pilot",
        statisticalQualification: false,
        activationAuthorized: false,
        provider: {
          deploymentRevisionDigest:
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
          credentialKeyId: "local-smoke-no-credential",
          response: {
            reasoningPresent: true,
            reasoningDigest: expect.stringMatching(/^sha256:/u),
          },
        },
        oracle: { matched: true },
      });
      if (process.platform !== "win32") {
        expect(
          statSync(resolve(runDirectory, "records", records[0]!)).mode & 0o777,
        ).toBe(0o600);
      }

      const resumed = await captureDiagnosticPilot({
        config,
        dataset,
        runDirectory,
        runner: {
          run: async () => {
            throw new Error("provider must not be called during resume");
          },
        },
      });
      expect(resumed).toMatchObject({
        complete: true,
        capturedThisRun: 0,
        resumedCases: 4,
        workloadProduced: true,
      });
      expect(readFileSync(workloadPath)).toEqual(workloadBytes);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("records an oracle mismatch but refuses to assemble a workload", async () => {
    const directory = privateTemporaryDirectory();
    const { config, dataset } = fixtures();
    const runDirectory = resolve(directory, "run");
    try {
      const result = await captureDiagnosticPilot({
        config,
        dataset: { ...dataset, cases: [dataset.cases[0]!] },
        runDirectory,
        runner: matchingRunner(undefined, { status: "different" }),
      });

      expect(result).toMatchObject({
        complete: true,
        workloadProduced: false,
        oracleMismatches: 1,
      });
      expect(
        existsSync(resolve(runDirectory, "cache-impact-workload.json")),
      ).toBe(false);
      const manifest = JSON.parse(
        readFileSync(
          resolve(runDirectory, "diagnostic-capture-manifest.json"),
          "utf8",
        ),
      );
      expect(manifest).toMatchObject({
        statisticalQualification: false,
        activationAuthorized: false,
        workload: { status: "not-produced", digest: null },
        summary: { oracleMismatches: 1 },
      });
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("rejects insufficient output budgets before creating a run or calling the provider", async () => {
    const directory = privateTemporaryDirectory();
    const { config, dataset } = fixtures();
    let calls = 0;
    try {
      for (const field of [
        "maxRecordBytes",
        "maxWorkloadBytes",
        "maxManifestBytes",
      ] as const) {
        const runDirectory = resolve(directory, field);
        const constrained = parseDiagnosticCaptureConfig({
          ...config,
          capture: { ...config.capture, [field]: 1_024 },
        });
        await expect(
          captureDiagnosticPilot({
            config: constrained,
            dataset,
            runDirectory,
            runner: matchingRunner(() => {
              calls += 1;
            }),
          }),
        ).rejects.toThrow("Diagnostic capture failed");
        expect(existsSync(runDirectory)).toBe(false);
      }
      expect(calls).toBe(0);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("keeps the minimum accepted manifest budget safe for skewed usage without reasoning", async () => {
    const directory = privateTemporaryDirectory();
    const runDirectory = resolve(directory, "run");
    const { config, dataset } = fixtures();
    const twoCases = { ...dataset, cases: dataset.cases.slice(0, 2) };
    const withManifestBudget = (maxManifestBytes: number) =>
      parseDiagnosticCaptureConfig({
        ...config,
        capture: { ...config.capture, maxManifestBytes },
      });
    let lower = 1_024;
    let upper = config.capture.maxManifestBytes;
    while (lower < upper) {
      const candidate = Math.floor((lower + upper) / 2);
      try {
        assertDiagnosticArtifactBudgets(
          withManifestBudget(candidate),
          twoCases,
        );
        upper = candidate;
      } catch {
        lower = candidate + 1;
      }
    }
    expect(lower).toBeGreaterThan(1_024);
    expect(() =>
      assertDiagnosticArtifactBudgets(withManifestBudget(lower - 1), twoCases),
    ).toThrow("Diagnostic capture failed");

    let calls = 0;
    try {
      const result = await captureDiagnosticPilot({
        config: withManifestBudget(lower),
        dataset: twoCases,
        runDirectory,
        runner: {
          run: async () => {
            calls += 1;
            const output = {
              operation: "read-project-status",
              status: "available",
            };
            return {
              output,
              rawText: JSON.stringify(output),
              reasoningText: null,
              warningCount: 0,
              usage: {
                inputTokens: 500_000_000_000_000,
                outputTokens: 8_507_199_254_740_991,
                totalTokens: Number.MAX_SAFE_INTEGER,
                reasoningOutputTokens: null,
              },
            };
          },
        },
      });
      expect(result).toMatchObject({
        complete: true,
        workloadProduced: true,
      });
      expect(calls).toBe(2);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("refuses to mix records after the host changes provider deployment identity", async () => {
    const directory = privateTemporaryDirectory();
    const runDirectory = resolve(directory, "run");
    const { config, dataset } = fixtures();
    const oneCase = { ...dataset, cases: [dataset.cases[0]!] };
    let resumedCalls = 0;
    try {
      await captureDiagnosticPilot({
        config,
        dataset: oneCase,
        runDirectory,
        runner: matchingRunner(),
      });
      const changedDeployment = parseDiagnosticCaptureConfig({
        ...config,
        provider: {
          ...config.provider,
          deploymentRevisionDigest: `sha256:${"e".repeat(64)}`,
        },
      });

      await expect(
        captureDiagnosticPilot({
          config: changedDeployment,
          dataset: oneCase,
          runDirectory,
          runner: matchingRunner(() => {
            resumedCalls += 1;
          }),
        }),
      ).rejects.toThrow("Diagnostic capture failed");
      expect(resumedCalls).toBe(0);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it.runIf(process.platform !== "win32")(
    "rejects a final-component run-directory symlink before provider work",
    async () => {
      const directory = privateTemporaryDirectory();
      const runDirectory = resolve(directory, "run");
      const redirectedDirectory = resolve(directory, "redirected-run");
      const { config, dataset } = fixtures();
      let calls = 0;
      try {
        mkdirSync(redirectedDirectory, { mode: 0o700 });
        symlinkSync(redirectedDirectory, runDirectory, "dir");

        await expect(
          captureDiagnosticPilot({
            config,
            dataset,
            runDirectory,
            runner: matchingRunner(() => {
              calls += 1;
            }),
          }),
        ).rejects.toThrow("Diagnostic capture failed");
        expect(calls).toBe(0);
        expect(readdirSync(redirectedDirectory)).toHaveLength(0);
      } finally {
        rmSync(directory, { recursive: true, force: true });
      }
    },
  );

  it.runIf(process.platform !== "win32")(
    "rejects a final-component records-directory symlink before provider work",
    async () => {
      const directory = privateTemporaryDirectory();
      const runDirectory = resolve(directory, "run");
      const redirectedDirectory = resolve(directory, "redirected-records");
      const { config, dataset } = fixtures();
      let calls = 0;
      try {
        mkdirSync(runDirectory, { mode: 0o700 });
        mkdirSync(redirectedDirectory, { mode: 0o700 });
        symlinkSync(
          redirectedDirectory,
          resolve(runDirectory, "records"),
          "dir",
        );

        await expect(
          captureDiagnosticPilot({
            config,
            dataset,
            runDirectory,
            runner: matchingRunner(() => {
              calls += 1;
            }),
          }),
        ).rejects.toThrow("Diagnostic capture failed");
        expect(calls).toBe(0);
        expect(readdirSync(redirectedDirectory)).toHaveLength(0);
      } finally {
        rmSync(directory, { recursive: true, force: true });
      }
    },
  );

  it.runIf(process.platform !== "win32")(
    "rejects a records-directory identity change during provider work",
    async () => {
      const directory = privateTemporaryDirectory();
      const runDirectory = resolve(directory, "run");
      const displacedRecords = resolve(directory, "displaced-records");
      const { config, dataset } = fixtures();
      let calls = 0;
      try {
        await expect(
          captureDiagnosticPilot({
            config,
            dataset,
            runDirectory,
            runner: matchingRunner(() => {
              calls += 1;
              renameSync(resolve(runDirectory, "records"), displacedRecords);
              mkdirSync(resolve(runDirectory, "records"), { mode: 0o700 });
            }),
          }),
        ).rejects.toThrow("Diagnostic capture failed");
        expect(calls).toBe(1);
        expect(readdirSync(displacedRecords)).toHaveLength(0);
        expect(readdirSync(resolve(runDirectory, "records"))).toHaveLength(0);
      } finally {
        rmSync(directory, { recursive: true, force: true });
      }
    },
  );

  it.runIf(process.platform !== "win32")(
    "rejects a run-directory identity change during provider work",
    async () => {
      const directory = privateTemporaryDirectory();
      const runDirectory = resolve(directory, "run");
      const displacedRun = resolve(directory, "displaced-run");
      const { config, dataset } = fixtures();
      let calls = 0;
      try {
        await expect(
          captureDiagnosticPilot({
            config,
            dataset,
            runDirectory,
            runner: matchingRunner(() => {
              calls += 1;
              renameSync(runDirectory, displacedRun);
              mkdirSync(resolve(runDirectory, "records"), {
                recursive: true,
                mode: 0o700,
              });
            }),
          }),
        ).rejects.toThrow("Diagnostic capture failed");
        expect(calls).toBe(1);
        expect(readdirSync(resolve(displacedRun, "records"))).toHaveLength(0);
        expect(readdirSync(resolve(runDirectory, "records"))).toHaveLength(0);
      } finally {
        rmSync(directory, { recursive: true, force: true });
      }
    },
  );
});

function fixtures() {
  return {
    config: parseDiagnosticCaptureConfig(
      JSON.parse(
        readFileSync(
          resolve(root, "config/diagnostic-capture.ollama.example.json"),
          "utf8",
        ),
      ),
    ),
    dataset: parseDiagnosticCaptureDataset(
      JSON.parse(
        readFileSync(
          resolve(root, "fixtures/diagnostic-capture-smoke.json"),
          "utf8",
        ),
      ),
    ),
  };
}

function matchingRunner(
  onRun?: () => void,
  output: Record<string, string> = {
    operation: "read-project-status",
    status: "available",
  },
): DiagnosticProviderRunner {
  return {
    run: async (): Promise<DiagnosticProviderObservation> => {
      onRun?.();
      return {
        output,
        rawText: JSON.stringify(output),
        reasoningText: "private chain that must never be stored raw",
        warningCount: 0,
        usage: {
          inputTokens: 17,
          outputTokens: 9,
          totalTokens: 26,
          reasoningOutputTokens: 3,
        },
      };
    },
  };
}

function privateTemporaryDirectory(): string {
  const directory = mkdtempSync(resolve(tmpdir(), "intentabi-capture-"));
  chmodSync(directory, 0o700);
  return directory;
}
