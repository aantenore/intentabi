import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

import {
  QUALIFICATION_EVIDENCE_SCHEMA,
  assertQualificationDatasetBudget,
  assertQualificationEvidenceBudget,
  parseQualificationConfig,
  parseQualificationDataset,
  parseQualificationEvidence,
} from "../src/config.js";

const hmac = (character: string) =>
  `hmac-sha256:evidence:${character.repeat(64)}` as const;

async function fixtures() {
  const [configSource, datasetSource] = await Promise.all([
    readFile(new URL("./fixtures/config.json", import.meta.url), "utf8"),
    readFile(new URL("./fixtures/dataset.json", import.meta.url), "utf8"),
  ]);
  return {
    config: parseQualificationConfig(JSON.parse(configSource)),
    dataset: parseQualificationDataset(JSON.parse(datasetSource)),
    datasetBytes: Buffer.byteLength(datasetSource, "utf8"),
  };
}

describe("qualification input contracts", () => {
  it("accepts the fixed schemas and enforces configured byte budgets", async () => {
    const { config, dataset, datasetBytes } = await fixtures();
    const evidence = parseQualificationEvidence({
      schema: QUALIFICATION_EVIDENCE_SCHEMA,
      classification: "private-held-out",
      planRef: hmac("1"),
      attestation: { sealed: "PRIVATE_ATTESTATION_CANARY" },
      records: [{ sealed: "PRIVATE_RECORD_ALPHA_CANARY" }, { sealed: true }],
    });

    expect(() =>
      assertQualificationDatasetBudget(config, dataset, datasetBytes),
    ).not.toThrow();
    expect(() =>
      assertQualificationEvidenceBudget(
        config,
        dataset,
        evidence,
        Buffer.byteLength(JSON.stringify(evidence), "utf8"),
      ),
    ).not.toThrow();
    expect(() =>
      assertQualificationDatasetBudget(
        config,
        dataset,
        config.qualification.maxDatasetBytes + 1,
      ),
    ).toThrow(/budget/u);
    expect(() =>
      assertQualificationEvidenceBudget(
        config,
        dataset,
        evidence,
        config.qualification.maxEvidenceBytes + 1,
      ),
    ).toThrow(/budget/u);
  });

  it("rejects unknown fields at every app-owned boundary", async () => {
    const { config, dataset } = await fixtures();
    expect(() =>
      parseQualificationConfig({ ...config, module: "PRIVATE_MODULE_CANARY" }),
    ).toThrow();
    expect(() =>
      parseQualificationDataset({
        ...dataset,
        cases: [{ ...dataset.cases[0], command: "PRIVATE_COMMAND_CANARY" }],
      }),
    ).toThrow();
    expect(() =>
      parseQualificationEvidence({
        schema: QUALIFICATION_EVIDENCE_SCHEMA,
        classification: "private-held-out",
        planRef: hmac("1"),
        attestation: {},
        records: [],
        plugin: "PRIVATE_PLUGIN_CANARY",
      }),
    ).toThrow();
  });

  it("rejects noncontiguous cohorts, count mismatches, and oversized records", async () => {
    const { config, dataset } = await fixtures();
    expect(() =>
      parseQualificationDataset({
        ...dataset,
        cases: [
          { ...dataset.cases[0], cohort: "adversarial" },
          dataset.cases[1],
        ],
      }),
    ).toThrow(/Population cases must precede/u);

    const missing = parseQualificationEvidence({
      schema: QUALIFICATION_EVIDENCE_SCHEMA,
      classification: "private-held-out",
      planRef: hmac("1"),
      attestation: {},
      records: [],
    });
    expect(() =>
      assertQualificationEvidenceBudget(config, dataset, missing, 2),
    ).toThrow(/budget/u);

    const smallBudget = {
      ...config,
      qualification: { ...config.qualification, maxRecordBytes: 2 },
    };
    const oversized = parseQualificationEvidence({
      schema: QUALIFICATION_EVIDENCE_SCHEMA,
      classification: "private-held-out",
      planRef: hmac("1"),
      attestation: {},
      records: [{ private: "PRIVATE_RECORD_CANARY" }, { private: "x" }],
    });
    expect(() =>
      assertQualificationEvidenceBudget(
        smallBudget,
        dataset,
        oversized,
        Buffer.byteLength(JSON.stringify(oversized), "utf8"),
      ),
    ).toThrow(/record/u);
  });

  it("rejects proxies and cyclic or aliased opaque JSON without executing traps", () => {
    let trapCalls = 0;
    const hostile = new Proxy(
      {},
      {
        getPrototypeOf: () => {
          trapCalls += 1;
          return Object.prototype;
        },
        ownKeys: () => {
          trapCalls += 1;
          return [];
        },
      },
    );
    expect(() =>
      parseQualificationEvidence({
        schema: QUALIFICATION_EVIDENCE_SCHEMA,
        classification: "private-held-out",
        planRef: hmac("1"),
        attestation: hostile,
        records: [],
      }),
    ).toThrow();
    expect(trapCalls).toBe(0);

    const shared = { private: "PRIVATE_ALIAS_CANARY" };
    expect(() =>
      parseQualificationEvidence({
        schema: QUALIFICATION_EVIDENCE_SCHEMA,
        classification: "private-held-out",
        planRef: hmac("1"),
        attestation: { left: shared, right: shared },
        records: [],
      }),
    ).toThrow();
  });
});
