import { describe, expect, it } from "vitest";

import {
  CLINC150_REVISION,
  CLINC150_SOURCE_SHA256,
  NORMALIZER_PILOT_CLASSIFICATION,
  NORMALIZER_PILOT_CONFIG_SCHEMA,
  parseNormalizerPilotConfig,
} from "../src/config.js";

const valid = {
  schema: NORMALIZER_PILOT_CONFIG_SCHEMA,
  classification: NORMALIZER_PILOT_CLASSIFICATION,
  source: {
    kind: "clinc150",
    revision: CLINC150_REVISION,
    sha256: CLINC150_SOURCE_SHA256,
    seed: "clinc150-test-v1",
    locale: "en-US",
    labels: ["bill_balance", "bill_due", "credit_score", "exchange_rate"],
    trainingAliasesPerIntent: 2,
    heldOutPerIntent: 4,
    outOfScopeCases: 8,
  },
  compiler: {
    kind: "openai-compatible",
    deploymentRevisionDigest: `sha256:${"d".repeat(64)}`,
    credentialKeyId: "local-test",
    provider: {
      name: "local-openai-compatible",
      baseUrl: "http://127.0.0.1:11434/v1",
      model: "test-model",
    },
    policy: {
      requestTimeoutMs: 30_000,
      maxResponseBytes: 1_048_576,
      maxOutputTokens: 128,
      maxPromptBytes: 65_536,
      reasoningEffort: "none",
    },
  },
  evaluation: {
    attemptsPerCase: 3,
    maxRequests: 1_000,
    maxArtifactBytes: 4_194_304,
    maxCheckpointBytes: 65_536,
  },
} as const;

describe("normalizer pilot configuration", () => {
  it("accepts the pinned external diagnostic contract", () => {
    expect(parseNormalizerPilotConfig(valid)).toEqual(valid);
  });

  it("rejects source drift, duplicate labels, and unknown fields", () => {
    expect(() =>
      parseNormalizerPilotConfig({
        ...valid,
        source: { ...valid.source, sha256: `sha256:${"0".repeat(64)}` },
      }),
    ).toThrow();
    expect(() =>
      parseNormalizerPilotConfig({
        ...valid,
        source: {
          ...valid.source,
          labels: [
            "bill_balance",
            "bill_balance",
            "credit_score",
            "exchange_rate",
          ],
        },
      }),
    ).toThrow();
    expect(() =>
      parseNormalizerPilotConfig({ ...valid, activeCache: true }),
    ).toThrow();
    expect(() =>
      parseNormalizerPilotConfig({
        ...valid,
        source: {
          ...valid.source,
          labels: [
            "bill_balance",
            "bill_due",
            "credit_score",
            "activate_cash_withdrawal",
          ],
        },
      }),
    ).toThrow();
  });

  it("requires explicit bounded repeatability and artifact budgets", () => {
    expect(() =>
      parseNormalizerPilotConfig({
        ...valid,
        evaluation: { ...valid.evaluation, attemptsPerCase: 1 },
      }),
    ).toThrow();
    expect(() =>
      parseNormalizerPilotConfig({
        ...valid,
        compiler: {
          ...valid.compiler,
          provider: {
            ...valid.compiler.provider,
            environmentRef: "UNTRUSTED_KEY_NAME",
          },
        },
      }),
    ).toThrow();
  });

  it("accepts only SemWitness-supported reasoning effort values", () => {
    expect(
      parseNormalizerPilotConfig({
        ...valid,
        compiler: {
          ...valid.compiler,
          policy: { ...valid.compiler.policy, reasoningEffort: "xhigh" },
        },
      }).compiler.policy.reasoningEffort,
    ).toBe("xhigh");
    expect(() =>
      parseNormalizerPilotConfig({
        ...valid,
        compiler: {
          ...valid.compiler,
          policy: { ...valid.compiler.policy, reasoningEffort: "unbounded" },
        },
      }),
    ).toThrow();
  });
});
