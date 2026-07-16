import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { runCli } from "../src/index.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

describe("intentabi shadow run", () => {
  it("separates authenticated content-free evidence from ordinary output", async () => {
    const stdout: string[] = [];
    const stderr: string[] = [];
    const exitCode = await runCli(
      [
        "shadow",
        "run",
        "--config",
        resolve(root, "config/intentabi.example.json"),
        "--request",
        resolve(root, "fixtures/shadow-request.json"),
      ],
      { INTENTABI_HMAC_SECRET: "x".repeat(32) },
      {
        stdout: (value) => stdout.push(value),
        stderr: (value) => stderr.push(value),
      },
    );

    expect(exitCode).toBe(0);
    expect(stdout).toHaveLength(1);
    expect(stderr).toHaveLength(1);
    const result = JSON.parse(stdout[0] ?? "{}");
    const evidence = JSON.parse(stderr[0] ?? "{}");
    expect(evidence).toMatchObject({
      event: "intentabi.shadow.evidence",
      envelope: {
        keyId: "demo-v1",
        evidence: {
          mode: "shadow",
          execution: { status: "succeeded" },
          candidate: { outcome: "miss-observed", applied: false },
        },
      },
    });
    expect(JSON.stringify(evidence)).not.toContain(
      "Show the current Agentic SDLC project status.",
    );
    expect(result).toMatchObject({
      event: "intentabi.shadow.result",
      output: { phase: "implementation", source: "ordinary-route" },
      evidenceDelivery: "emitted",
    });
  });

  it("rejects duplicate and unknown command options", async () => {
    const stderr: string[] = [];
    const io = {
      stdout: () => undefined,
      stderr: (value: string) => stderr.push(value),
    };

    expect(
      await runCli(["shadow", "run", "--config", "a", "--config", "b"], {}, io),
    ).toBe(1);
    expect(
      await runCli(
        ["shadow", "run", "--config", "a", "--execute", "b"],
        {},
        io,
      ),
    ).toBe(1);
  });

  it("supports help and version without configuration", async () => {
    const output: string[] = [];
    const io = {
      stdout: (value: string) => output.push(value),
      stderr: () => undefined,
    };

    await expect(runCli(["--help"], {}, io)).resolves.toBe(0);
    await expect(runCli(["--version"], {}, io)).resolves.toBe(0);
    expect(output[0]).toContain("intentabi shadow run");
    expect(output[1]).toBe("0.1.0-alpha.1\n");
  });

  it("executes the ordinary route but bypasses a mismatched semantic binding", async () => {
    const directory = mkdtempSync(resolve(tmpdir(), "intentabi-mismatch-"));
    const configPath = resolve(directory, "config.json");
    const baseConfig = JSON.parse(
      readFileSync(resolve(root, "config/intentabi.example.json"), "utf8"),
    );
    baseConfig.semwitness.registryPath = resolve(
      root,
      "fixtures/intent-registry.json",
    );
    baseConfig.semwitness.routeBindings["read-project-status"] = {
      command: "different",
      project: "demo",
    };
    baseConfig.agenticSdlc.fixturePath = resolve(
      root,
      "fixtures/agentic-sdlc-route.json",
    );
    writeFileSync(configPath, JSON.stringify(baseConfig));
    const stdout: string[] = [];
    const stderr: string[] = [];
    try {
      const exitCode = await runCli(
        [
          "shadow",
          "run",
          "--config",
          configPath,
          "--request",
          resolve(root, "fixtures/shadow-request.json"),
        ],
        { INTENTABI_HMAC_SECRET: "x".repeat(32) },
        {
          stdout: (value) => stdout.push(value),
          stderr: (value) => stderr.push(value),
        },
      );

      expect(exitCode).toBe(0);
      expect(JSON.parse(stdout[0] ?? "{}")).toMatchObject({
        output: { phase: "implementation", source: "ordinary-route" },
      });
      expect(JSON.parse(stderr[0] ?? "{}")).toMatchObject({
        envelope: {
          evidence: {
            candidate: {
              outcome: "bypass",
              reasons: ["ROUTE_INPUT_MISMATCH"],
            },
          },
        },
      });
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});
