import { readFile } from "node:fs/promises";

import type { SemWitnessQualificationArtifact } from "@intentabi/adapter-semwitness";
import type { QualificationPlan } from "@intentabi/qualification-core";
import { describe, expect, it } from "vitest";

import {
  QUALIFICATION_ARTIFACT_SCHEMA,
  createQualificationArtifact,
  executeQualification,
  materializeQualificationPlan,
  serializeQualificationArtifact,
  type QualificationAuthorityPort,
} from "../src/composition.js";
import {
  QUALIFICATION_EVIDENCE_SCHEMA,
  parseQualificationConfig,
  parseQualificationDataset,
  parseQualificationEvidence,
} from "../src/config.js";

const secret = "qualification-secret-32-bytes-minimum-value";
const digest = (character: string) => `sha256:${character.repeat(64)}` as const;

async function fixtureInput() {
  const [configSource, datasetSource] = await Promise.all([
    readFile(new URL("./fixtures/config.json", import.meta.url), "utf8"),
    readFile(new URL("./fixtures/dataset.json", import.meta.url), "utf8"),
  ]);
  const config = parseQualificationConfig(JSON.parse(configSource));
  const dataset = parseQualificationDataset(JSON.parse(datasetSource));
  const materialization = materializeQualificationPlan({
    config,
    dataset,
    secret,
  });
  const evidence = parseQualificationEvidence({
    schema: QUALIFICATION_EVIDENCE_SCHEMA,
    classification: "private-held-out",
    planRef: materialization.planRef,
    attestation: { sealed: "PRIVATE_ATTESTATION_CANARY" },
    records: [
      { sealed: "PRIVATE_RECORD_ALPHA_CANARY" },
      { sealed: "PRIVATE_RECORD_BETA_CANARY" },
    ],
  });
  return { config, dataset, materialization, evidence };
}

function artifact(): SemWitnessQualificationArtifact {
  return Object.freeze({
    evidenceJsonl: "PRIVATE_EXACT_SEMWITNESS_EVIDENCE_CANARY\n",
    workbench: Object.freeze({
      privateWorkbench: "PRIVATE_EXACT_WORKBENCH_CANARY",
    }),
  }) as unknown as SemWitnessQualificationArtifact;
}

function authorityFor(
  plan: QualificationPlan,
  semwitness: SemWitnessQualificationArtifact,
  decision: "qualified" | "unqualified" = "unqualified",
  authorityId = "semwitness-intent-cache-promotion-evaluator",
): QualificationAuthorityPort {
  return Object.freeze({
    evaluate: (input: {
      readonly attestation: unknown;
      readonly records: readonly unknown[];
    }) => {
      expect(input.records).toHaveLength(plan.cases.length);
      return Object.freeze({
        projection: Object.freeze({
          authority: Object.freeze({ id: authorityId, version: "1" }),
          activationCeiling: "shadow-only" as const,
          decision,
          evidenceDigest: digest("a"),
          bindingDigest: digest("b"),
          reportDigest: digest("c"),
          ...(decision === "qualified"
            ? { qualificationDigest: digest("d") }
            : {}),
          cases: Object.freeze(
            plan.cases.map((item, ordinal) =>
              Object.freeze({
                ordinal,
                cohort: item.cohort,
                difficulty: item.difficulty,
                cacheRegime: item.cacheRegime,
                pairOrder: item.pairOrder,
                recordDigest: digest(String(ordinal + 1)),
              }),
            ),
          ),
        }),
        artifact: semwitness,
      });
    },
  }) as QualificationAuthorityPort;
}

describe("qualification composition", () => {
  it("materializes a deterministic content-free HMAC plan", async () => {
    const { config, dataset, materialization } = await fixtureInput();
    const second = materializeQualificationPlan({ config, dataset, secret });
    const serialized = JSON.stringify(materialization);

    expect(second).toEqual(materialization);
    expect(materialization.planRef).toMatch(
      /^hmac-sha256:evidence:[a-f0-9]{64}$/u,
    );
    expect(
      materialization.plan.cases.map((item) => item.pairOrder).sort(),
    ).toEqual(["candidate-first", "ordinary-first"]);
    expect(serialized).not.toContain("PRIVATE_DATASET_CANARY");
    expect(serialized).not.toContain("PRIVATE_CASE_ALPHA_CANARY");
    expect(serialized).not.toContain("PRIVATE_BALANCE_CELL_CANARY");
    expect(serialized).not.toContain(secret);
  });

  it("returns a deterministic authenticated shadow-only receipt and exact authority artifact", async () => {
    const input = await fixtureInput();
    const semwitness = artifact();
    const runInput = { ...input, secret };
    const first = await executeQualification(
      runInput,
      authorityFor(input.materialization.plan, semwitness),
    );
    const second = await executeQualification(
      runInput,
      authorityFor(input.materialization.plan, semwitness),
    );

    expect(second.receipt).toEqual(first.receipt);
    expect(first.semwitness).toBe(semwitness);
    expect(first.receipt).toMatchObject({
      activationCeiling: "shadow-only",
      activationAuthorized: false,
      authority: { decision: "unqualified" },
    });
    expect(first.receipt.runId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
    );
    expect(first.receipt.receiptMac).toMatch(
      /^hmac-sha256:evidence:[a-f0-9]{64}$/u,
    );
    expect(JSON.stringify(first.receipt)).not.toContain("PRIVATE");

    const qualificationArtifact = createQualificationArtifact(first);
    const bytes = serializeQualificationArtifact(
      qualificationArtifact,
      1024 * 1024,
    );
    const decoded = JSON.parse(Buffer.from(bytes).toString("utf8")) as {
      schema: string;
      semwitness: unknown;
    };
    expect(decoded.schema).toBe(QUALIFICATION_ARTIFACT_SCHEMA);
    expect(decoded.semwitness).toEqual(semwitness);
    expect(Buffer.from(bytes).toString("utf8").endsWith("\n")).toBe(true);
  });

  it("rejects a mismatched evaluator after core validation", async () => {
    const input = await fixtureInput();
    await expect(
      executeQualification(
        { ...input, secret },
        authorityFor(
          input.materialization.plan,
          artifact(),
          "unqualified",
          "different-evaluator",
        ),
      ),
    ).rejects.toThrow(/identity/u);
  });

  it("rejects hostile authority ports and results without executing proxy traps", async () => {
    const input = await fixtureInput();
    let portTrapCalls = 0;
    const hostilePort = new Proxy(
      { evaluate: () => ({}) },
      {
        get: () => {
          portTrapCalls += 1;
          return undefined;
        },
        getOwnPropertyDescriptor: () => {
          portTrapCalls += 1;
          return undefined;
        },
      },
    ) as unknown as QualificationAuthorityPort;
    await expect(
      executeQualification({ ...input, secret }, hostilePort),
    ).rejects.toThrow(/port/u);
    expect(portTrapCalls).toBe(0);

    let resultTrapCalls = 0;
    const hostileResult = new Proxy(
      {},
      {
        ownKeys: () => {
          resultTrapCalls += 1;
          return [];
        },
        getOwnPropertyDescriptor: () => {
          resultTrapCalls += 1;
          return undefined;
        },
      },
    );
    const authority = Object.freeze({
      evaluate: () => hostileResult,
    }) as unknown as QualificationAuthorityPort;
    await expect(
      executeQualification({ ...input, secret }, authority),
    ).rejects.toThrow(/invalid evidence/u);
    expect(resultTrapCalls).toBe(0);
  });
});
