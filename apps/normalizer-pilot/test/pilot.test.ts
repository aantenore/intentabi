import { readFileSync } from "node:fs";

import { describe, expect, it, vi } from "vitest";

import {
  EXAMPLE_DEPLOYMENT_REVISION_DIGEST,
  parseNormalizerPilotConfig,
} from "../src/config.js";
import {
  executeNormalizerPilot,
  normalizerPilotRunBindingDigest,
  NORMALIZER_PILOT_SEMWITNESS_REVISION,
  type NormalizerPilotArtifact,
} from "../src/pilot.js";
import {
  compiler,
  evaluationReport,
  fixturePreparation,
  pilotConfig,
} from "./support.js";

describe("normalizer pilot execution", () => {
  it("binds the evaluator implementation to the immutable SemWitness dependency", () => {
    const manifest = JSON.parse(
      readFileSync(new URL("../package.json", import.meta.url), "utf8"),
    ) as { dependencies?: { semwitness?: string } };
    expect(manifest.dependencies?.semwitness).toBe(
      `github:aantenore/semwitness#${NORMALIZER_PILOT_SEMWITNESS_REVISION}`,
    );
  });

  it("binds external evidence without granting statistical, economic, or activation authority", async () => {
    const preparation = fixturePreparation();
    const createdCompiler = compiler(preparation);
    const committed: Uint8Array[] = [];
    const abort = vi.fn(async () => undefined);
    const evaluate = vi.fn(async () => evaluationReport(preparation));
    const createCompiler = vi.fn(() => createdCompiler);
    const reserveArtifact = vi.fn(async () => ({
      commit: async (bytes: Uint8Array) => committed.push(bytes),
      abort,
    }));

    const artifact = await executeNormalizerPilot({
      config: pilotConfig(),
      source: new TextEncoder().encode("external-source"),
      outputPath: "/private/report.json",
      environment: {},
      dependencies: {
        prepare: () => preparation,
        createCompiler,
        evaluate,
        reserveArtifact,
      },
    });

    expect(reserveArtifact).toHaveBeenCalledBefore(createCompiler);
    expect(evaluate).toHaveBeenCalledTimes(1);
    expect(evaluate).toHaveBeenCalledWith({
      compiler: createdCompiler,
      registry: preparation.registry,
      fixture: preparation.fixture,
      split: "held-out",
      attempts: 3,
    });
    expect(abort).not.toHaveBeenCalled();
    expect(committed).toHaveLength(1);
    const persisted = JSON.parse(
      new TextDecoder().decode(committed[0]),
    ) as NormalizerPilotArtifact;
    expect(persisted).toMatchObject({
      classification: "external-normalizer-diagnostic",
      statisticalQualification: false,
      economicQualification: false,
      activationAuthorized: false,
      promotionManifest: "not-produced",
      qualificationStatus: "external-evidence-required",
      pilotRunBindingDigest: expect.stringMatching(/^sha256:[a-f0-9]{64}$/u),
      source: { corpusDigest: preparation.prepared.corpusDigest },
    });
    expect(artifact).toEqual(persisted);
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

  it("rejects the example deployment placeholder before reserving output", async () => {
    const config = pilotConfig();
    const reserveArtifact = vi.fn();
    await expect(
      executeNormalizerPilot({
        config: parseNormalizerPilotConfig({
          ...config,
          compiler: {
            ...config.compiler,
            deploymentRevisionDigest: EXAMPLE_DEPLOYMENT_REVISION_DIGEST,
          },
        }),
        source: "external-source",
        outputPath: "/private/report.json",
        environment: {},
        dependencies: { reserveArtifact },
      }),
    ).rejects.toThrow(/example placeholder/u);
    expect(reserveArtifact).not.toHaveBeenCalled();
  });

  it("aborts the private reservation when evaluation or corpus binding fails", async () => {
    const preparation = fixturePreparation();
    const abort = vi.fn(async () => undefined);
    const commit = vi.fn(async () => undefined);
    const base = {
      config: pilotConfig(),
      source: "external-source",
      outputPath: "/private/report.json",
      environment: {},
      dependencies: {
        prepare: () => preparation,
        createCompiler: () => compiler(preparation),
        reserveArtifact: async () => ({ commit, abort }),
      },
    } as const;

    await expect(
      executeNormalizerPilot({
        ...base,
        dependencies: {
          ...base.dependencies,
          evaluate: async () => {
            throw new Error("evaluation failed");
          },
        },
      }),
    ).rejects.toThrow("evaluation failed");
    expect(abort).toHaveBeenCalledTimes(1);
    expect(commit).not.toHaveBeenCalled();

    const drifted = {
      ...evaluationReport(preparation),
      corpusDigest: `sha256:${"f".repeat(64)}` as const,
    };
    await expect(
      executeNormalizerPilot({
        ...base,
        dependencies: {
          ...base.dependencies,
          evaluate: async () => drifted,
        },
      }),
    ).rejects.toThrow(/not bound/u);
    expect(abort).toHaveBeenCalledTimes(2);
    expect(commit).not.toHaveBeenCalled();
  });
});
