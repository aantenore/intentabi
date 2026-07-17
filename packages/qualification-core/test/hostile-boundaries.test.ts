import { describe, expect, it, vi } from "vitest";

import {
  createQualificationPlan,
  QualificationInvariantFailure,
  runQualification,
  type QualificationCase,
} from "../src/index.js";

const hmac = (character: string) =>
  `hmac-sha256:evidence:${character.repeat(64)}` as const;
const digest = (character: string) => `sha256:${character.repeat(64)}` as const;
const runId = "00000000-0000-4000-8000-000000000001";

const cases: readonly QualificationCase<string>[] = [
  {
    caseRef: hmac("1"),
    balanceCellRef: hmac("2"),
    cohort: "population",
    difficulty: "simple",
    cacheRegime: "cold",
    payload: "PRIVATE PAYLOAD",
  },
];

function setup() {
  const plan = createQualificationPlan({
    cases,
    seed: "seed",
    keyId: "qualification-v1",
    datasetDigest: hmac("3"),
    protocolDigest: digest("4"),
  });
  const projection = {
    authority: { id: "authority", version: "1" },
    activationCeiling: "shadow-only" as const,
    decision: "unqualified" as const,
    evidenceDigest: digest("5"),
    bindingDigest: digest("6"),
    reportDigest: digest("7"),
    cases: [
      {
        ordinal: 0,
        cohort: "population" as const,
        difficulty: "simple" as const,
        cacheRegime: "cold" as const,
        pairOrder: plan.cases[0]!.pairOrder,
        recordDigest: digest("8"),
      },
    ],
  };
  return { plan, projection };
}

describe("hostile qualification boundaries", () => {
  it("passes opaque records without invoking getters, serializers, or prototypes", async () => {
    let hostileCalls = 0;
    const record = Object.create({ inherited: "PRIVATE INHERITED" }) as Record<
      string,
      unknown
    >;
    Object.defineProperties(record, {
      secret: {
        enumerable: true,
        get: () => {
          hostileCalls += 1;
          return "PRIVATE GETTER";
        },
      },
      toJSON: {
        enumerable: true,
        value: () => {
          hostileCalls += 1;
          throw new Error("must not serialize");
        },
      },
    });
    const { plan, projection } = setup();

    const result = await runQualification({
      plan,
      cases,
      runner: { runCase: () => record },
      authority: {
        evaluate: ({ records }) => {
          expect(records[0]).toBe(record);
          return { projection, artifact: record };
        },
      },
      attestation: record,
      runId,
      executableDigest: digest("9"),
      authenticateReceipt: () => hmac("a"),
    });

    expect(result.authorityArtifact).toBe(record);
    expect(hostileCalls).toBe(0);
  });

  it("rejects authority projection accessors without invoking them", async () => {
    const { plan, projection } = setup();
    let getterCalls = 0;
    const hostileProjection = { ...projection } as Record<string, unknown>;
    Object.defineProperty(hostileProjection, "reportDigest", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return digest("7");
      },
    });

    await expect(
      runQualification({
        plan,
        cases,
        runner: { runCase: () => ({}) },
        authority: {
          evaluate: () => ({
            projection: hostileProjection as never,
            artifact: "private",
          }),
        },
        attestation: null,
        runId,
        executableDigest: digest("9"),
        authenticateReceipt: () => hmac("a"),
      }),
    ).rejects.toBeInstanceOf(QualificationInvariantFailure);
    expect(getterCalls).toBe(0);
  });

  it("rejects port accessors and proxies without invoking them", async () => {
    const { plan, projection } = setup();
    let accessorCalls = 0;
    const runner = {} as { runCase?: () => unknown };
    Object.defineProperty(runner, "runCase", {
      get: () => {
        accessorCalls += 1;
        return () => ({});
      },
    });
    await expect(
      runQualification({
        plan,
        cases,
        runner: runner as never,
        authority: {
          evaluate: () => ({ projection, artifact: "private" }),
        },
        attestation: null,
        runId,
        executableDigest: digest("9"),
        authenticateReceipt: () => hmac("a"),
      }),
    ).rejects.toThrow(/method/u);
    expect(accessorCalls).toBe(0);

    let trapCalls = 0;
    const authority = new Proxy(
      { evaluate: () => ({ projection, artifact: "private" }) },
      {
        get: () => {
          trapCalls += 1;
          return undefined;
        },
        getOwnPropertyDescriptor: () => {
          trapCalls += 1;
          return undefined;
        },
      },
    );
    await expect(
      runQualification({
        plan,
        cases,
        runner: { runCase: () => ({}) },
        authority,
        attestation: null,
        runId,
        executableDigest: digest("9"),
        authenticateReceipt: () => hmac("a"),
      }),
    ).rejects.toThrow(/port/u);
    expect(trapCalls).toBe(0);
  });

  it("rejects a top-level request accessor without invoking it", async () => {
    const { plan, projection } = setup();
    let getterCalls = 0;
    const request = {
      plan,
      cases,
      runner: { runCase: () => ({}) },
      authority: {
        evaluate: () => ({ projection, artifact: "private" }),
      },
      attestation: null,
      runId,
      executableDigest: digest("9"),
      authenticateReceipt: () => hmac("a"),
    };
    Object.defineProperty(request, "plan", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return plan;
      },
    });

    await expect(runQualification(request)).rejects.toThrow(/plain data/u);
    expect(getterCalls).toBe(0);
  });

  it("never returns an artifact when authentication fails", async () => {
    const { plan, projection } = setup();
    const authority = {
      evaluate: vi.fn(() => ({
        projection,
        artifact: { private: "PRIVATE" },
      })),
    };
    await expect(
      runQualification({
        plan,
        cases,
        runner: { runCase: () => ({}) },
        authority,
        attestation: null,
        runId,
        executableDigest: digest("9"),
        authenticateReceipt: () => {
          throw new Error("HSM unavailable");
        },
      }),
    ).rejects.toThrow(/authentication failed/u);
    expect(authority.evaluate).toHaveBeenCalledOnce();
  });

  it("rejects fake cancellation signals without invoking their accessors", async () => {
    const { plan, projection } = setup();
    let getterCalls = 0;
    const fakeSignal = {};
    Object.defineProperty(fakeSignal, "aborted", {
      get: () => {
        getterCalls += 1;
        return false;
      },
    });

    await expect(
      runQualification({
        plan,
        cases,
        runner: { runCase: () => ({}) },
        authority: {
          evaluate: () => ({ projection, artifact: "private" }),
        },
        attestation: null,
        runId,
        executableDigest: digest("9"),
        authenticateReceipt: () => hmac("a"),
        signal: fakeSignal as AbortSignal,
      }),
    ).rejects.toThrow(/signal is invalid/u);
    expect(getterCalls).toBe(0);
  });

  it("does not resolve lifecycle methods from Object.prototype pollution", async () => {
    const { plan, projection } = setup();
    const objectPrototype = Object.prototype as typeof Object.prototype & {
      runCase?: () => unknown;
    };
    objectPrototype.runCase = () => ({ private: "PRIVATE" });
    try {
      await expect(
        runQualification({
          plan,
          cases,
          runner: {} as never,
          authority: {
            evaluate: () => ({ projection, artifact: "private" }),
          },
          attestation: null,
          runId,
          executableDigest: digest("9"),
          authenticateReceipt: () => hmac("a"),
        }),
      ).rejects.toThrow(/method is missing/u);
    } finally {
      delete objectPrototype.runCase;
    }
  });
});
