import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  createSemWitnessQualificationAuthority,
  evaluateHostAttestedPromotionRun,
  evaluateSemWitnessQualification,
  projectSemWitnessQualificationResult,
} from "../src/index.js";
import { createEmptyPromotionAssemblyInput } from "./support/promotion-fixture.js";

describe("SemWitness Qualification Lab authority", () => {
  it("projects the exact reparsed artifact without inventing qualification", () => {
    const input = createEmptyPromotionAssemblyInput();

    const result = evaluateSemWitnessQualification(input);

    expect(result.projection).toEqual({
      authority: {
        id: "semwitness-intent-cache-promotion-evaluator",
        version: "1",
      },
      activationCeiling: "shadow-only",
      decision: "unqualified",
      evidenceDigest: sha256(result.artifact.evidenceJsonl),
      bindingDigest: result.artifact.workbench.report.bindingDigest,
      reportDigest: result.artifact.workbench.reportDigest,
      cases: [],
    });
    expect(result.artifact.workbench.qualified).toBe(false);
    expect("qualificationDigest" in result.projection).toBe(false);
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.projection)).toBe(true);
    expect(Object.isFrozen(result.projection.cases)).toBe(true);
  });

  it("exposes the structural authority port consumed by Qualification Lab", async () => {
    const input = createEmptyPromotionAssemblyInput();
    const authority = createSemWitnessQualificationAuthority();

    const result = await authority.evaluate({
      attestation: input.attestation,
      records: input.cases,
    });

    expect(result.projection.decision).toBe("unqualified");
    expect(result.projection.activationCeiling).toBe("shadow-only");
    expect(result.projection.cases).toEqual([]);
  });

  it("rejects a workbench result detached from the exact evidence binding", () => {
    const artifact = evaluateHostAttestedPromotionRun(
      createEmptyPromotionAssemblyInput(),
    );
    const detached = {
      ...artifact,
      workbench: {
        ...artifact.workbench,
        report: {
          ...artifact.workbench.report,
          bindingDigest: `sha256:${"f".repeat(64)}`,
        },
      },
    } as typeof artifact;

    expect(() => projectSemWitnessQualificationResult(detached)).toThrow(
      "SemWitness qualification result is not bound",
    );
  });

  it("re-evaluates the exact bytes and rejects a forged report digest", () => {
    const artifact = evaluateHostAttestedPromotionRun(
      createEmptyPromotionAssemblyInput(),
    );
    const detached = {
      ...artifact,
      workbench: {
        ...artifact.workbench,
        reportDigest: `sha256:${"e".repeat(64)}`,
      },
    } as typeof artifact;

    expect(() => projectSemWitnessQualificationResult(detached)).toThrow(
      "SemWitness qualification result is not bound",
    );
  });

  it("rejects accessor-bearing artifacts without invoking them", () => {
    const artifact = evaluateHostAttestedPromotionRun(
      createEmptyPromotionAssemblyInput(),
    );
    let invoked = false;
    const hostile: Record<string, unknown> = {
      evidenceJsonl: artifact.evidenceJsonl,
    };
    Object.defineProperty(hostile, "workbench", {
      enumerable: true,
      get: () => {
        invoked = true;
        return artifact.workbench;
      },
    });

    expect(() =>
      projectSemWitnessQualificationResult(
        hostile as unknown as typeof artifact,
      ),
    ).toThrow("SemWitness qualification artifact is invalid");
    expect(invoked).toBe(false);
  });

  it("keeps payload canaries out of public projection and errors", () => {
    const marker = "PRIVATE_QUALIFICATION_PAYLOAD";
    const input = createEmptyPromotionAssemblyInput();
    const result = evaluateSemWitnessQualification(input);

    expect(JSON.stringify(result.projection)).not.toContain(marker);
    expect(JSON.stringify(result.projection)).not.toMatch(
      /(?:candidate|provider|network|store|cache)Payload/u,
    );

    const smuggled = {
      ...input,
      attestation: { ...input.attestation, candidatePayload: marker },
    } as typeof input;
    let message = "";
    try {
      evaluateSemWitnessQualification(smuggled);
    } catch (error) {
      message = String(error);
    }
    expect(message).not.toContain(marker);
  });
});

function sha256(value: string): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}
