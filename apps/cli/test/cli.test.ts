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
    expect(output[1]).toBe("0.2.0-alpha.1\n");
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

describe("intentabi cache-impact evaluate", () => {
  it("runs the real SemWitness adapter and emits a content-free value report", async () => {
    const stdout: string[] = [];
    const stderr: string[] = [];
    const exitCode = await runCli(
      [
        "cache-impact",
        "evaluate",
        "--config",
        resolve(root, "config/cache-impact.example.json"),
        "--workload",
        resolve(root, "fixtures/cache-impact-workload.json"),
      ],
      { INTENTABI_HMAC_SECRET: "x".repeat(32) },
      {
        stdout: (value) => stdout.push(value),
        stderr: (value) => stderr.push(value),
      },
    );

    expect(exitCode).toBe(0);
    expect(stderr).toEqual([]);
    const event = JSON.parse(stdout[0] ?? "{}");
    expect(event).toMatchObject({
      event: "intentabi.cache-impact.report",
      report: {
        mode: "shadow",
        activationAuthorized: false,
        measurementProvenance: {
          workload: "host-supplied-unattested",
          usage: "host-declared-unverified",
          freshness: "not-modeled",
        },
        summary: {
          requests: 4,
          raw: { safeHits: 1, unsafeHits: 0 },
          normalized: { safeHits: 3, unsafeHits: 0 },
          safeHitLift: 2,
          tokens: {
            rawModelInput: "63",
            normalizedModelInput: "20",
            netInputDeltaVersusRaw: "43",
            netOutputDeltaVersusRaw: "20",
            netTotalDeltaVersusRaw: "63",
          },
          gate: { passed: true, reasons: [] },
        },
      },
    });
    const serialized = JSON.stringify(event);
    expect(serialized).not.toContain(
      "Show the current Agentic SDLC project status.",
    );
    expect(serialized).not.toContain(
      "What is the status of this SDLC project?",
    );
    expect(serialized).not.toContain(
      "Delete the current Agentic SDLC project.",
    );
  });

  it("changes the dataset binding when the normalization registry changes", async () => {
    const directory = mkdtempSync(resolve(tmpdir(), "intentabi-provenance-"));
    const configPath = resolve(directory, "config.json");
    const registryPath = resolve(directory, "registry.json");
    const baseConfig = JSON.parse(
      readFileSync(resolve(root, "config/cache-impact.example.json"), "utf8"),
    );
    const registry = JSON.parse(
      readFileSync(resolve(root, "fixtures/intent-registry.json"), "utf8"),
    );
    baseConfig.semwitness.registryPath = registryPath;
    writeFileSync(configPath, JSON.stringify(baseConfig));

    const evaluate = async () => {
      const stdout: string[] = [];
      const exitCode = await runCli(
        [
          "cache-impact",
          "evaluate",
          "--config",
          configPath,
          "--workload",
          resolve(root, "fixtures/cache-impact-workload.json"),
        ],
        { INTENTABI_HMAC_SECRET: "x".repeat(32) },
        {
          stdout: (value) => stdout.push(value),
          stderr: () => undefined,
        },
      );
      return {
        exitCode,
        report: JSON.parse(stdout[0] ?? "{}").report,
      };
    };

    try {
      writeFileSync(registryPath, JSON.stringify(registry));
      const original = await evaluate();
      registry.operations[0].aliases.forEach(
        (alias: { text: string }, index: number) => {
          alias.text = `Different unobserved alias ${index}`;
        },
      );
      writeFileSync(registryPath, JSON.stringify(registry));
      const changed = await evaluate();
      baseConfig.semwitness.routeBindings["read-project-status"] = {
        command: "different",
        project: "demo",
      };
      writeFileSync(configPath, JSON.stringify(baseConfig));
      const routeMapChanged = await evaluate();

      expect(original.exitCode).toBe(0);
      expect(changed.exitCode).toBe(2);
      expect(changed.report.datasetDigest).not.toBe(
        original.report.datasetDigest,
      );
      expect(changed.report.normalizationBindingDigest).not.toBe(
        original.report.normalizationBindingDigest,
      );
      expect(routeMapChanged.report.datasetDigest).not.toBe(
        changed.report.datasetDigest,
      );
      expect(routeMapChanged.report.normalizationBindingDigest).not.toBe(
        changed.report.normalizationBindingDigest,
      );
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("returns two for a complete diagnostic run that fails its safety/value gate", async () => {
    const directory = mkdtempSync(resolve(tmpdir(), "intentabi-impact-"));
    const workloadPath = resolve(directory, "workload.json");
    const workload = JSON.parse(
      readFileSync(
        resolve(root, "fixtures/cache-impact-workload.json"),
        "utf8",
      ),
    );
    workload.cases[1].expectedValueDigest =
      "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    writeFileSync(workloadPath, JSON.stringify(workload));
    const stdout: string[] = [];
    const stderr: string[] = [];
    try {
      const exitCode = await runCli(
        [
          "cache-impact",
          "evaluate",
          "--config",
          resolve(root, "config/cache-impact.example.json"),
          "--workload",
          workloadPath,
        ],
        { INTENTABI_HMAC_SECRET: "x".repeat(32) },
        {
          stdout: (value) => stdout.push(value),
          stderr: (value) => stderr.push(value),
        },
      );

      expect(exitCode).toBe(2);
      expect(stderr).toEqual([]);
      expect(JSON.parse(stdout[0] ?? "{}")).toMatchObject({
        report: {
          summary: {
            normalized: { unsafeHits: 1 },
            gate: {
              passed: false,
              reasons: expect.arrayContaining(["NORMALIZED_UNSAFE_HITS"]),
            },
          },
        },
      });
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("fails closed on missing key material and malformed options", async () => {
    const stderr: string[] = [];
    const io = {
      stdout: () => undefined,
      stderr: (value: string) => stderr.push(value),
    };
    const args = [
      "cache-impact",
      "evaluate",
      "--config",
      resolve(root, "config/cache-impact.example.json"),
      "--workload",
      resolve(root, "fixtures/cache-impact-workload.json"),
    ];

    await expect(runCli(args, {}, io)).resolves.toBe(1);
    await expect(
      runCli(
        ["cache-impact", "evaluate", "--config", "a", "--config", "b"],
        {},
        io,
      ),
    ).resolves.toBe(1);
    expect(stderr.join("\n")).not.toContain("x".repeat(32));
  });
});
