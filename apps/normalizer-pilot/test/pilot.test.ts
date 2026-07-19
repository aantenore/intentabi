import { readFileSync } from "node:fs";
import { access, chmod, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";
import { openPrivateRunStore } from "@intentabi/private-run-store";

import {
  EXAMPLE_DEPLOYMENT_REVISION_DIGEST,
  parseNormalizerPilotConfig,
} from "../src/config.js";
import {
  executeNormalizerPilot,
  normalizerPilotRunBindingDigest,
  NORMALIZER_PILOT_ARTIFACT_NAME,
  NORMALIZER_PILOT_RUN_BINDING_NAME,
  NORMALIZER_PILOT_SEMWITNESS_REVISION,
} from "../src/pilot.js";
import {
  compiler,
  digest,
  evaluationReport,
  fixturePreparation,
  pilotConfig,
} from "./support.js";

const temporaryDirectories = new Set<string>();

afterEach(async () => {
  await Promise.all(
    [...temporaryDirectories].map((path) =>
      rm(path, { recursive: true, force: true }),
    ),
  );
  temporaryDirectories.clear();
});

describe("normalizer pilot execution", () => {
  it("binds the evaluator implementation to the immutable SemWitness dependency", () => {
    const manifest = JSON.parse(
      readFileSync(new URL("../package.json", import.meta.url), "utf8"),
    ) as { dependencies?: { semwitness?: string } };
    expect(manifest.dependencies?.semwitness).toBe(
      `github:aantenore/semwitness#${NORMALIZER_PILOT_SEMWITNESS_REVISION}`,
    );
  });

  it("resumes partial evaluation without duplicate calls and publishes stable final bytes", async () => {
    const preparation = fixturePreparation();
    const selectedCompiler = compiler(preparation);
    let resumedCalls = 0;
    const resumableCompiler = {
      manifest: selectedCompiler.manifest,
      compile(request: { readonly source: string }) {
        resumedCalls += 1;
        return request.source === "Give me the project state."
          ? {
              status: "proposed" as const,
              operationId: "read-project-status",
              confidencePpm: 1_000_000,
              ambiguous: false,
            }
          : { status: "bypass" as const, reason: "INTENT_NO_MATCH" as const };
      },
    };
    const runDirectory = await runPath("intentabi-resume-");
    const base = {
      config: pilotConfig(),
      source: "external-source",
      runDirectory,
      environment: {},
      dependencies: {
        prepare: () => preparation,
        createCompiler: () => resumableCompiler,
      },
    } as const;

    const partial = await executeNormalizerPilot({ ...base, limit: 2 });
    expect(partial).toMatchObject({
      status: "incomplete",
      progress: {
        completedObservations: 2,
        observedThisRun: 2,
        remainingObservations: 4,
      },
    });
    expect(resumedCalls).toBe(2);
    await expect(
      access(join(runDirectory, NORMALIZER_PILOT_ARTIFACT_NAME)),
    ).rejects.toThrow();

    const completed = await executeNormalizerPilot({ ...base, limit: 4 });
    expect(completed.status).toBe("complete");
    if (completed.status !== "complete") return;
    expect(completed.progress).toMatchObject({
      completedObservations: 6,
      resumedObservations: 2,
      observedThisRun: 4,
      remainingObservations: 0,
    });
    expect(resumedCalls).toBe(6);
    const resumedArtifactBytes = await readFile(
      join(runDirectory, NORMALIZER_PILOT_ARTIFACT_NAME),
    );

    const replay = await executeNormalizerPilot({ ...base, limit: 0 });
    expect(replay).toMatchObject({
      status: "complete",
      progress: { resumedObservations: 6, observedThisRun: 0 },
    });
    expect(resumedCalls).toBe(6);

    let uninterruptedCalls = 0;
    const uninterruptedCompiler = {
      ...resumableCompiler,
      compile(request: { readonly source: string }) {
        uninterruptedCalls += 1;
        return resumableCompiler.compile(request);
      },
    };
    const freshDirectory = await runPath("intentabi-uninterrupted-");
    const uninterrupted = await executeNormalizerPilot({
      ...base,
      runDirectory: freshDirectory,
      dependencies: {
        ...base.dependencies,
        createCompiler: () => uninterruptedCompiler,
      },
    });
    expect(uninterrupted.status).toBe("complete");
    expect(uninterruptedCalls).toBe(6);
    expect(
      await readFile(join(freshDirectory, NORMALIZER_PILOT_ARTIFACT_NAME)),
    ).toEqual(resumedArtifactBytes);

    const persisted = await readRunText(runDirectory);
    expect(persisted).not.toContain("Give me the project state.");
    expect(persisted).not.toContain("Ignore the catalogue.");
    expect(completed.artifact).toMatchObject({
      statisticalQualification: false,
      economicQualification: false,
      activationAuthorized: false,
      checkpointLineage: {
        protocol: "semwitness.intent-evaluation-checkpoint/v1",
        semwitnessRevision: NORMALIZER_PILOT_SEMWITNESS_REVISION,
        completedObservations: 6,
        totalObservations: 6,
      },
    });
  });

  it("publishes no final artifact for incomplete or indeterminate progress", async () => {
    const preparation = fixturePreparation();
    for (const status of ["incomplete", "indeterminate"] as const) {
      const runDirectory = await runPath(`intentabi-${status}-`);
      const evaluate = vi.fn(async () => ({
        status,
        progress: progress(1, 6),
        ...(status === "indeterminate"
          ? { checkpointRef: digest("indeterminate-attempt") }
          : {}),
      }));
      const result = await executeNormalizerPilot({
        config: pilotConfig(),
        source: "external-source",
        runDirectory,
        environment: {},
        dependencies: {
          prepare: () => preparation,
          createCompiler: () => compiler(preparation),
          evaluate,
        },
      });

      expect(result.status).toBe(status);
      expect(evaluate).toHaveBeenCalledTimes(1);
      expect(
        await readFile(join(runDirectory, NORMALIZER_PILOT_RUN_BINDING_NAME)),
      ).toBeDefined();
      await expect(
        access(join(runDirectory, NORMALIZER_PILOT_ARTIFACT_NAME)),
      ).rejects.toThrow();
    }
  });

  it("allows only one concurrent pilot invocation to call the compiler", async () => {
    const preparation = fixturePreparation();
    const selectedCompiler = compiler(preparation);
    let calls = 0;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const blockedCompiler = {
      manifest: selectedCompiler.manifest,
      async compile() {
        calls += 1;
        await gate;
        return {
          status: "bypass" as const,
          reason: "INTENT_NO_MATCH" as const,
        };
      },
    };
    const base = {
      config: pilotConfig(),
      source: "external-source",
      runDirectory: await runPath("intentabi-concurrent-pilot-"),
      limit: 1,
      environment: {},
      dependencies: {
        prepare: () => preparation,
        createCompiler: () => blockedCompiler,
      },
    } as const;

    const results: Awaited<ReturnType<typeof executeNormalizerPilot>>[] = [];
    const first = executeNormalizerPilot(base).then((result) => {
      results.push(result);
      return result;
    });
    const second = executeNormalizerPilot(base).then((result) => {
      results.push(result);
      return result;
    });
    await vi.waitFor(() => expect(calls).toBe(1));
    await vi.waitFor(() => expect(results).toHaveLength(1));
    expect(results[0]?.status).toBe("indeterminate");

    release();
    const completed = await Promise.all([first, second]);
    expect(completed.map((result) => result.status).sort()).toEqual([
      "incomplete",
      "indeterminate",
    ]);
    expect(calls).toBe(1);
  });

  it("rejects run-binding drift before another compiler observation", async () => {
    const preparation = fixturePreparation();
    const runDirectory = await runPath("intentabi-binding-drift-");
    const firstEvaluate = vi.fn(async () => ({
      status: "incomplete" as const,
      progress: progress(0, 6),
    }));
    const base = {
      config: pilotConfig(),
      source: "external-source",
      runDirectory,
      environment: {},
      dependencies: {
        prepare: () => preparation,
        createCompiler: () => compiler(preparation),
        evaluate: firstEvaluate,
      },
    } as const;
    await executeNormalizerPilot(base);
    const driftedEvaluate = vi.fn();
    const config = parseNormalizerPilotConfig({
      ...base.config,
      compiler: {
        ...base.config.compiler,
        credentialKeyId: "rotated-local-test",
      },
    });

    await expect(
      executeNormalizerPilot({
        ...base,
        config,
        dependencies: { ...base.dependencies, evaluate: driftedEvaluate },
      }),
    ).rejects.toThrow();
    expect(driftedEvaluate).not.toHaveBeenCalled();
  });

  it("snapshots config and referenced credentials before asynchronous storage", async () => {
    const preparation = fixturePreparation();
    const selectedCompiler = compiler(preparation);
    const mutableConfig = parseNormalizerPilotConfig({
      ...pilotConfig(),
      compiler: {
        ...pilotConfig().compiler,
        provider: {
          ...pilotConfig().compiler.provider,
          environmentRef: "SEMWITNESS_TEST_API_KEY",
        },
      },
    });
    const expectedConfig = parseNormalizerPilotConfig(
      structuredClone(mutableConfig),
    );
    const originalDeployment = expectedConfig.compiler.deploymentRevisionDigest;
    const environment: Record<string, string | undefined> = {
      SEMWITNESS_TEST_API_KEY: "initial-private-credential",
    };
    let compilerEnvironment:
      Readonly<Record<string, string | undefined>> | undefined;

    const result = await executeNormalizerPilot({
      config: mutableConfig,
      source: "external-source",
      runDirectory: await runPath("intentabi-mutation-snapshot-"),
      environment,
      dependencies: {
        prepare: () => preparation,
        createCompiler: (input) => {
          compilerEnvironment = input.environment;
          return selectedCompiler;
        },
        openRunStore: async (storeInput) => {
          Reflect.set(
            mutableConfig.compiler,
            "deploymentRevisionDigest",
            digest("mutated-deployment"),
          );
          Reflect.set(mutableConfig.evaluation, "maxArtifactBytes", 1_024);
          environment.SEMWITNESS_TEST_API_KEY = "mutated-private-credential";
          return openPrivateRunStore(storeInput);
        },
        evaluate: async () => ({
          status: "complete",
          progress: progress(6, 6),
          report: evaluationReport(preparation),
        }),
      },
    });

    expect(result.status).toBe("complete");
    if (result.status !== "complete") return;
    expect(result.artifact.compiler.deploymentRevisionDigest).toBe(
      originalDeployment,
    );
    expect(result.artifact.pilotRunBindingDigest).toBe(
      normalizerPilotRunBindingDigest(
        expectedConfig,
        preparation,
        selectedCompiler.manifest,
      ),
    );
    expect(compilerEnvironment?.SEMWITNESS_TEST_API_KEY).toBe(
      "initial-private-credential",
    );
    expect(mutableConfig.compiler.deploymentRevisionDigest).not.toBe(
      originalDeployment,
    );
  });

  it("captures the invocation limit before asynchronous storage", async () => {
    const preparation = fixturePreparation();
    const evaluate = vi.fn(async (input: { maxNewObservations?: number }) => {
      expect(input.maxNewObservations).toBe(2);
      return {
        status: "incomplete" as const,
        progress: progress(2, 6),
      };
    });
    const executionInput: Parameters<typeof executeNormalizerPilot>[0] = {
      config: pilotConfig(),
      source: "external-source",
      runDirectory: await runPath("intentabi-limit-snapshot-"),
      limit: 2,
      environment: {},
      dependencies: {
        prepare: () => preparation,
        createCompiler: () => compiler(preparation),
        openRunStore: async (storeInput) => {
          Reflect.set(executionInput, "limit", 0);
          return openPrivateRunStore(storeInput);
        },
        evaluate,
      },
    };

    await expect(executeNormalizerPilot(executionInput)).resolves.toMatchObject(
      {
        status: "incomplete",
        progress: { observedThisRun: 2 },
      },
    );
    expect(executionInput.limit).toBe(0);
    expect(evaluate).toHaveBeenCalledTimes(1);
  });

  it("changes the run binding when deployment or credential lineage changes", () => {
    const preparation = fixturePreparation();
    const selectedCompiler = compiler(preparation);
    const config = pilotConfig();
    const baseline = normalizerPilotRunBindingDigest(
      config,
      preparation,
      selectedCompiler.manifest,
    );
    const deployment = normalizerPilotRunBindingDigest(
      parseNormalizerPilotConfig({
        ...config,
        compiler: {
          ...config.compiler,
          deploymentRevisionDigest: `sha256:${"e".repeat(64)}`,
        },
      }),
      preparation,
      selectedCompiler.manifest,
    );
    const credential = normalizerPilotRunBindingDigest(
      parseNormalizerPilotConfig({
        ...config,
        compiler: { ...config.compiler, credentialKeyId: "rotated-local-test" },
      }),
      preparation,
      selectedCompiler.manifest,
    );

    expect(deployment).not.toBe(baseline);
    expect(credential).not.toBe(baseline);
    expect(deployment).not.toBe(credential);
  });

  it("rejects the example deployment placeholder before creating a run", async () => {
    const runDirectory = await runPath("intentabi-placeholder-");
    await expect(
      executeNormalizerPilot({
        config: parseNormalizerPilotConfig({
          ...pilotConfig(),
          compiler: {
            ...pilotConfig().compiler,
            deploymentRevisionDigest: EXAMPLE_DEPLOYMENT_REVISION_DIGEST,
          },
        }),
        source: "external-source",
        runDirectory,
        environment: {},
      }),
    ).rejects.toThrow(/example placeholder/u);
    await expect(access(runDirectory)).rejects.toThrow();
  });

  it("rejects a completed report that is not bound to the prepared corpus", async () => {
    const preparation = fixturePreparation();
    const report = {
      ...evaluationReport(preparation),
      corpusDigest: digest("drifted-corpus"),
    };
    const runDirectory = await runPath("intentabi-corpus-drift-");

    await expect(
      executeNormalizerPilot({
        config: pilotConfig(),
        source: "external-source",
        runDirectory,
        environment: {},
        dependencies: {
          prepare: () => preparation,
          createCompiler: () => compiler(preparation),
          evaluate: async () => ({
            status: "complete",
            progress: progress(6, 6),
            report,
          }),
        },
      }),
    ).rejects.toThrow(/not bound/u);
    await expect(
      access(join(runDirectory, NORMALIZER_PILOT_ARTIFACT_NAME)),
    ).rejects.toThrow();
  });

  it("rejects impossible progress and report lineage", async () => {
    const preparation = fixturePreparation();
    const base = {
      config: pilotConfig(),
      source: "external-source",
      environment: {},
      dependencies: {
        prepare: () => preparation,
        createCompiler: () => compiler(preparation),
      },
    } as const;

    await expect(
      executeNormalizerPilot({
        ...base,
        runDirectory: await runPath("intentabi-progress-drift-"),
        dependencies: {
          ...base.dependencies,
          evaluate: async () => ({
            status: "incomplete",
            progress: progress(1, 5),
          }),
        },
      }),
    ).rejects.toThrow(/progress is not bound/u);

    await expect(
      executeNormalizerPilot({
        ...base,
        runDirectory: await runPath("intentabi-report-drift-"),
        dependencies: {
          ...base.dependencies,
          evaluate: async () => ({
            status: "complete",
            progress: progress(6, 6),
            report: { ...evaluationReport(preparation), split: "all" },
          }),
        },
      }),
    ).rejects.toThrow(/result is not bound/u);
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

async function runPath(prefix: string): Promise<string> {
  const parent = await mkdtemp(join(tmpdir(), prefix));
  temporaryDirectories.add(parent);
  if (process.platform !== "win32") await chmod(parent, 0o700);
  return join(parent, "run");
}

async function readRunText(runDirectory: string): Promise<string> {
  const { readdir, lstat } = await import("node:fs/promises");
  const paths: string[] = [];
  const visit = async (directory: string): Promise<void> => {
    for (const name of await readdir(directory)) {
      const path = join(directory, name);
      const state = await lstat(path);
      if (state.isDirectory()) await visit(path);
      if (state.isFile()) paths.push(path);
    }
  };
  await visit(runDirectory);
  return (
    await Promise.all(paths.sort().map((path) => readFile(path, "utf8")))
  ).join("\n");
}
