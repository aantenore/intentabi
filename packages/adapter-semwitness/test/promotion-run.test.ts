import { describe, expect, it } from "vitest";
import { parseIntentCachePromotionEvidenceJsonl } from "semwitness/intent/host";

import { evaluateHostAttestedPromotionRun } from "../src/index.js";
import { createEmptyPromotionAssemblyInput } from "./support/promotion-fixture.js";

describe("host-attested SemWitness promotion run", () => {
  it("assembles deterministic JSONL and evaluates the exact reparsed bytes", () => {
    const input = createEmptyPromotionAssemblyInput();
    const first = evaluateHostAttestedPromotionRun(input);
    const reordered = evaluateHostAttestedPromotionRun(
      reverseJsonObjectKeys(input) as typeof input,
    );

    expect(first.evidenceJsonl).toBe(reordered.evidenceJsonl);
    expect(first.workbench).toEqual(reordered.workbench);
    expect(first.evidenceJsonl.endsWith("\n")).toBe(true);
    expect(first.evidenceJsonl.endsWith("\n\n")).toBe(false);
    expect(
      parseIntentCachePromotionEvidenceJsonl(first.evidenceJsonl).cases,
    ).toEqual([]);
    expect(Object.keys(first).sort()).toEqual(["evidenceJsonl", "workbench"]);
    expect(first.workbench.qualified).toBe(false);
    expect(first.workbench.report.gateReasons).toContain(
      "INSUFFICIENT_OPERATION_HITS",
    );
    expect("qualification" in first.workbench).toBe(false);
  });

  it("returns detached frozen evidence without creating payload fields", () => {
    const input = createEmptyPromotionAssemblyInput();
    const result = evaluateHostAttestedPromotionRun(input);
    const originalEvidenceJsonl = result.evidenceJsonl;
    const originalReportDigest = result.workbench.reportDigest;

    const mutable = input.attestation.population as {
      attempted: number;
    };
    mutable.attempted = 99;

    expect(result.evidenceJsonl).toBe(originalEvidenceJsonl);
    expect(result.workbench.reportDigest).toBe(originalReportDigest);
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.workbench)).toBe(true);
    expect(Object.isFrozen(result.workbench.report)).toBe(true);
    expect(result.evidenceJsonl).not.toMatch(
      /(?:candidate|provider|network|store|cache)Payload/u,
    );
  });

  it("fails closed on count mismatches and malformed host attestations", () => {
    const mismatch = createEmptyPromotionAssemblyInput();
    const malformedCount = {
      ...mismatch,
      attestation: {
        ...mismatch.attestation,
        population: { ...mismatch.attestation.population, attempted: 1 },
      },
    };
    expect(() => evaluateHostAttestedPromotionRun(malformedCount)).toThrow();

    const malformed = createEmptyPromotionAssemblyInput();
    expect(() =>
      evaluateHostAttestedPromotionRun({
        ...malformed,
        attestation: {
          ...malformed.attestation,
          mode: "active",
        } as typeof malformed.attestation,
      }),
    ).toThrow();
  });

  it("rejects candidate and infrastructure payload smuggling", () => {
    for (const payloadField of [
      "candidatePayload",
      "providerPayload",
      "networkPayload",
      "storePayload",
      "cachePayload",
    ]) {
      const input = createEmptyPromotionAssemblyInput();
      expect(() =>
        evaluateHostAttestedPromotionRun({
          ...input,
          attestation: {
            ...input.attestation,
            [payloadField]: "PRIVATE_PAYLOAD_MUST_NOT_LEAVE_HOST",
          } as typeof input.attestation,
        }),
      ).toThrow();
    }

    const nested = createEmptyPromotionAssemblyInput();
    expect(() =>
      evaluateHostAttestedPromotionRun({
        ...nested,
        attestation: {
          ...nested.attestation,
          dependencies: {
            ...nested.attestation.dependencies,
            provider: {
              ...nested.attestation.dependencies.provider,
              providerPayload: "PRIVATE_PROVIDER_PAYLOAD_MUST_NOT_LEAVE_HOST",
            },
          },
        } as typeof nested.attestation,
      }),
    ).toThrow();
  });
});

function reverseJsonObjectKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(reverseJsonObjectKeys);
  if (value === null || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value as Readonly<Record<string, unknown>>)
      .reverse()
      .map(([key, entry]) => [key, reverseJsonObjectKeys(entry)]),
  );
}
