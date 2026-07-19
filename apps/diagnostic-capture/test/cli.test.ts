import { chmodSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it, vi } from "vitest";

import { runDiagnosticCaptureCli } from "../src/cli.js";
import { DiagnosticProviderError } from "../src/provider.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const config = resolve(root, "config/diagnostic-capture.ollama.example.json");
const dataset = resolve(root, "fixtures/diagnostic-capture-smoke.json");

describe("diagnostic capture CLI", () => {
  it("validates without constructing a provider", async () => {
    const stdout: string[] = [];
    const createRunner = vi.fn(() => {
      throw new Error();
    });
    const exitCode = await runDiagnosticCaptureCli(
      ["validate", "--config", config, "--dataset", dataset],
      {},
      {
        stdout: (value) => stdout.push(value),
        stderr: () => undefined,
      },
      { createRunner },
    );

    expect(exitCode).toBe(0);
    expect(createRunner).not.toHaveBeenCalled();
    expect(JSON.parse(stdout[0] ?? "{}")).toMatchObject({
      event: "intentabi.diagnostic-capture.validated",
      statisticalQualification: false,
      activationAuthorized: false,
      providerCalls: 0,
      cases: 4,
    });
  });

  it("requires explicit execution and emits stable provider failure reasons", async () => {
    const stderr: string[] = [];
    const io = {
      stdout: () => undefined,
      stderr: (value: string) => stderr.push(value),
    };
    expect(
      await runDiagnosticCaptureCli(
        [
          "run",
          "--config",
          config,
          "--dataset",
          dataset,
          "--run-dir",
          "ignored",
        ],
        {},
        io,
      ),
    ).toBe(1);
    expect(JSON.parse(stderr[0] ?? "{}")).toMatchObject({
      reason: "CAPTURE_FAILED",
    });
  });

  it("reports a resumable partial capture without claiming qualification", async () => {
    const directory = mkdtempSync(resolve(tmpdir(), "intentabi-cli-"));
    chmodSync(directory, 0o700);
    const stdout: string[] = [];
    try {
      const exitCode = await runDiagnosticCaptureCli(
        [
          "run",
          "--config",
          config,
          "--dataset",
          dataset,
          "--run-dir",
          resolve(directory, "run"),
          "--limit",
          "1",
          "--execute",
        ],
        {},
        {
          stdout: (value) => stdout.push(value),
          stderr: () => undefined,
        },
        {
          createRunner: () => ({
            run: async () => ({
              output: {
                operation: "read-project-status",
                status: "available",
              },
              rawText:
                '{"operation":"read-project-status","status":"available"}',
              reasoningText: null,
              warningCount: 0,
              usage: {
                inputTokens: 10,
                outputTokens: 5,
                totalTokens: 15,
                reasoningOutputTokens: null,
              },
            }),
          }),
        },
      );

      expect(exitCode).toBe(0);
      expect(JSON.parse(stdout[0] ?? "{}")).toMatchObject({
        event: "intentabi.diagnostic-capture.completed",
        classification: "diagnostic-held-out-pilot",
        statisticalQualification: false,
        activationAuthorized: false,
        complete: false,
        capturedThisRun: 1,
        remainingCases: 3,
      });
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("keeps reasoning-budget exhaustion machine-readable at the CLI boundary", async () => {
    const directory = mkdtempSync(
      resolve(tmpdir(), "intentabi-cli-reasoning-"),
    );
    chmodSync(directory, 0o700);
    const stderr: string[] = [];
    try {
      const exitCode = await runDiagnosticCaptureCli(
        [
          "run",
          "--config",
          config,
          "--dataset",
          dataset,
          "--run-dir",
          resolve(directory, "run"),
          "--limit",
          "1",
          "--execute",
        ],
        {},
        {
          stdout: () => undefined,
          stderr: (value) => stderr.push(value),
        },
        {
          createRunner: () => ({
            run: async () => {
              throw new DiagnosticProviderError(
                "OUTPUT_BUDGET_EXHAUSTED_WITH_REASONING",
              );
            },
          }),
        },
      );

      expect(exitCode).toBe(1);
      expect(JSON.parse(stderr[0] ?? "{}")).toMatchObject({
        event: "intentabi.diagnostic-capture.error",
        reason: "OUTPUT_BUDGET_EXHAUSTED_WITH_REASONING",
      });
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});
