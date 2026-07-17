import { readFile, rm, symlink, truncate, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { mkdtemp } from "node:fs/promises";
import { describe, expect, it, vi } from "vitest";

import {
  executeCodexBenchmark,
  reserveBenchmarkReceipt,
  runCodexBenchCli,
  type CodexBenchCliDependencies,
} from "../src/index.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const configPath = resolve(root, "config/codex-bench.example.json");
const datasetPath = resolve(root, "fixtures/codex-bench-conformance.json");
const secret = "x".repeat(32);
const expectedPlatformEnvironment =
  process.platform === "win32"
    ? { SystemRoot: "/safe/system-root" }
    : ({} as const);

describe("Codex benchmark CLI", () => {
  it("validates and plans offline without touching the executable or provider", async () => {
    const preflight = vi.fn();
    const execute = vi.fn();
    const reserveReceipt = vi.fn();
    const dependencies = { preflight, execute, reserveReceipt } as never;

    const validated = await invoke(
      ["validate", "--config", configPath, "--dataset", datasetPath],
      {},
      dependencies,
    );
    const planned = await invoke(
      ["plan", "--config", configPath, "--dataset", datasetPath],
      { INTENTABI_BENCH_HMAC_SECRET: secret },
      dependencies,
    );

    expect(validated.exitCode).toBe(0);
    expect(JSON.parse(validated.stdout[0] ?? "{}")).toMatchObject({
      providerCalls: 0,
      promotionEligible: false,
    });
    expect(planned.exitCode).toBe(0);
    expect(JSON.parse(planned.stdout[0] ?? "{}")).toMatchObject({
      providerCalls: 0,
      plan: { classification: "research-conformance" },
    });
    expect(planned.stdout.join("")).not.toContain(
      "Return exactly the word READY",
    );
    expect(preflight).not.toHaveBeenCalled();
    expect(execute).not.toHaveBeenCalled();
    expect(reserveReceipt).not.toHaveBeenCalled();
  });

  it("requires both explicit execution consents", async () => {
    const dependencies = {
      preflight: vi.fn(),
      execute: vi.fn(),
      reserveReceipt: vi.fn(),
    } as never;
    const result = await invoke(
      [
        "run",
        "--config",
        configPath,
        "--dataset",
        datasetPath,
        "--out",
        "receipt.json",
        "--execute",
      ],
      { INTENTABI_BENCH_HMAC_SECRET: secret },
      dependencies,
    );

    expect(result.exitCode).toBe(1);
    expect(result.stderr.join("")).toContain("--allow-candidate-submission");
    expect(dependencies.preflight).not.toHaveBeenCalled();
  });

  it("rejects oversized JSON before parsing or provider access", async () => {
    const directory = await mkdtemp(resolve(tmpdir(), "intentabi-json-cap-"));
    const oversized = resolve(directory, "oversized.json");
    const dependencies = {
      preflight: vi.fn(),
      execute: vi.fn(),
      reserveReceipt: vi.fn(),
    } as never;
    try {
      await writeFile(oversized, "{");
      await truncate(oversized, 16 * 1024 * 1024 + 1);
      const result = await invoke(
        ["validate", "--config", oversized, "--dataset", datasetPath],
        {},
        dependencies,
      );
      expect(result.exitCode).toBe(1);
      expect(result.stderr.join("")).toContain(
        "Benchmark input could not be read",
      );
      expect(dependencies.preflight).not.toHaveBeenCalled();
      expect(dependencies.execute).not.toHaveBeenCalled();
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("rejects a symlinked benchmark input before provider access", async () => {
    if (process.platform === "win32") return;
    const directory = await mkdtemp(resolve(tmpdir(), "intentabi-json-link-"));
    const alias = resolve(directory, "dataset.json");
    const dependencies = {
      preflight: vi.fn(),
      execute: vi.fn(),
      reserveReceipt: vi.fn(),
    } as never;
    try {
      await symlink(datasetPath, alias);
      const result = await invoke(
        ["validate", "--config", configPath, "--dataset", alias],
        {},
        dependencies,
      );

      expect(result.exitCode).toBe(1);
      expect(result.stderr.join("")).toContain(
        "Benchmark input could not be read",
      );
      expect(result.stderr.join("")).not.toContain(alias);
      expect(dependencies.preflight).not.toHaveBeenCalled();
      expect(dependencies.execute).not.toHaveBeenCalled();
      expect(dependencies.reserveReceipt).not.toHaveBeenCalled();
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("runs through an injected provider boundary and writes no content", async () => {
    const directory = await mkdtemp(
      resolve(tmpdir(), "intentabi-codex-bench-"),
    );
    const outPath = resolve(directory, "receipt.json");
    const submitted: string[] = [];
    const verifyIntegrity = vi.fn(async () => undefined);
    const release = vi.fn(async () => undefined);
    const preflight = vi.fn(async () => ({
      path: "/mock/codex",
      version: "0.144.4",
      digest: `sha256:${"0".repeat(64)}` as const,
      verifyIntegrity,
      release,
    }));
    const dependencies: CodexBenchCliDependencies = {
      preflight,
      execute: async (input) =>
        executeCodexBenchmark({
          ...input,
          runId: "00000000-0000-4000-8000-000000000001",
          runner: {
            run: vi.fn(async (content) => {
              submitted.push(content);
              return {
                usage: {
                  provenance: "host-observed-codex-sdk-run-result",
                  inputTokens: content.includes("exactly") ? 100 : 60,
                  cachedInputTokens: 0,
                  outputTokens: 5,
                  reasoningOutputTokens: 0,
                },
                latencyMicros: 100,
              };
            }),
          },
        }),
      reserveReceipt: reserveBenchmarkReceipt,
    };
    try {
      const result = await invoke(
        [
          "run",
          "--config",
          configPath,
          "--dataset",
          datasetPath,
          "--out",
          outPath,
          "--execute",
          "--allow-candidate-submission",
        ],
        {
          INTENTABI_BENCH_HMAC_SECRET: secret,
          INTENTABI_CODEX_API_KEY: "codex-api-key-for-test",
          GH_TOKEN: "must-not-pass",
          AWS_SECRET_ACCESS_KEY: "must-not-pass",
          SystemRoot: "/safe/system-root",
        },
        dependencies,
      );

      expect(result.exitCode).toBe(0);
      expect(submitted).toHaveLength(8);
      expect(verifyIntegrity).toHaveBeenCalledTimes(16);
      expect(release).toHaveBeenCalledTimes(1);
      expect(preflight).toHaveBeenCalledWith(
        expect.any(String),
        "0.144.4",
        `sha256:${"0".repeat(64)}`,
        expectedPlatformEnvironment,
      );
      const serialized = await readFile(outPath, "utf8");
      expect(serialized).toContain('"promotionEligible": false');
      expect(serialized).toContain('"promotionManifest": "not-produced"');
      expect(serialized).toContain('"executionMode": "injected-test-boundary"');
      expect(serialized).not.toContain("Return exactly");
      expect(serialized).not.toContain("Output only");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("releases the staged executable before reporting an execution failure", async () => {
    const release = vi.fn(async () => undefined);
    const commit = vi.fn(async () => undefined);
    const abort = vi.fn(async () => undefined);
    const dependencies: CodexBenchCliDependencies = {
      preflight: vi.fn(async () => ({
        path: "/mock/codex",
        version: "0.144.4",
        digest: `sha256:${"0".repeat(64)}`,
        verifyIntegrity: vi.fn(async () => undefined),
        release,
      })),
      execute: vi.fn(async () => {
        throw new Error("private provider failure");
      }),
      reserveReceipt: vi.fn(async () => ({ commit, abort })),
    };

    const result = await invoke(
      [
        "run",
        "--config",
        configPath,
        "--dataset",
        datasetPath,
        "--out",
        "receipt.json",
        "--execute",
        "--allow-candidate-submission",
      ],
      {
        INTENTABI_BENCH_HMAC_SECRET: secret,
        INTENTABI_CODEX_API_KEY: "codex-api-key-for-test",
      },
      dependencies,
    );

    expect(result.exitCode).toBe(1);
    expect(release).toHaveBeenCalledTimes(1);
    expect(commit).not.toHaveBeenCalled();
    expect(abort).toHaveBeenCalledTimes(1);
    expect(result.stderr.join("")).not.toContain("private provider failure");
  });

  it("reserves the output before executable or provider access", async () => {
    const directory = await mkdtemp(
      resolve(tmpdir(), "intentabi-codex-reservation-"),
    );
    const outPath = resolve(directory, "existing.json");
    await writeFile(outPath, "owned-by-user", { mode: 0o600 });
    const dependencies = {
      preflight: vi.fn(),
      execute: vi.fn(),
      reserveReceipt: reserveBenchmarkReceipt,
    } as CodexBenchCliDependencies;
    try {
      const result = await invoke(
        [
          "run",
          "--config",
          configPath,
          "--dataset",
          datasetPath,
          "--out",
          outPath,
          "--execute",
          "--allow-candidate-submission",
        ],
        {
          INTENTABI_BENCH_HMAC_SECRET: secret,
          INTENTABI_CODEX_API_KEY: "codex-api-key-for-test",
        },
        dependencies,
      );

      expect(result.exitCode).toBe(1);
      expect(dependencies.preflight).not.toHaveBeenCalled();
      expect(dependencies.execute).not.toHaveBeenCalled();
      expect(await readFile(outPath, "utf8")).toBe("owned-by-user");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});

async function invoke(
  argv: readonly string[],
  environment: Readonly<Record<string, string | undefined>>,
  dependencies: CodexBenchCliDependencies,
) {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const exitCode = await runCodexBenchCli(
    argv,
    environment,
    {
      stdout: (value) => stdout.push(value),
      stderr: (value) => stderr.push(value),
    },
    dependencies,
  );
  return { exitCode, stdout, stderr };
}
