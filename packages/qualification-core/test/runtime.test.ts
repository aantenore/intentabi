import { describe, expect, it, vi } from "vitest";

import {
  createQualificationPlan,
  QualificationCancelledFailure,
  QualificationInvariantFailure,
  runQualification,
  type AuthorityCaseBinding,
  type QualificationAuthorityProjection,
  type QualificationCase,
  type QualificationPlan,
} from "../src/index.js";

const hmac = (character: string) =>
  `hmac-sha256:evidence:${character.repeat(64)}` as const;
const digest = (character: string) => `sha256:${character.repeat(64)}` as const;
const runId = "00000000-0000-4000-8000-000000000001";

const cases: readonly QualificationCase<{ readonly secret: string }>[] = [
  {
    caseRef: hmac("1"),
    balanceCellRef: hmac("a"),
    cohort: "population",
    difficulty: "simple",
    cacheRegime: "cold",
    payload: { secret: "PRIVATE PAYLOAD ONE" },
  },
  {
    caseRef: hmac("2"),
    balanceCellRef: hmac("a"),
    cohort: "population",
    difficulty: "simple",
    cacheRegime: "cold",
    payload: { secret: "PRIVATE PAYLOAD TWO" },
  },
];

function plan(): QualificationPlan {
  return createQualificationPlan({
    cases,
    seed: "stable-seed",
    keyId: "qualification-evidence-v1",
    datasetDigest: hmac("b"),
    protocolDigest: digest("c"),
  });
}

function bindings(value: QualificationPlan): AuthorityCaseBinding[] {
  return value.cases.map((item, ordinal) => ({
    ordinal,
    cohort: item.cohort,
    difficulty: item.difficulty,
    cacheRegime: item.cacheRegime,
    pairOrder: item.pairOrder,
    recordDigest: digest(String(ordinal + 1)),
  }));
}

function projection(
  value: QualificationPlan,
  overrides: Partial<QualificationAuthorityProjection> = {},
): QualificationAuthorityProjection {
  return {
    authority: {
      id: "semwitness-intent-cache-promotion-evaluator",
      version: "1",
    },
    activationCeiling: "shadow-only",
    decision: "unqualified",
    evidenceDigest: digest("d"),
    bindingDigest: digest("e"),
    reportDigest: digest("f"),
    cases: bindings(value),
    ...overrides,
  };
}

describe("runQualification", () => {
  it("runs sequentially and returns authenticated content-free evidence", async () => {
    const active: number[] = [];
    const observedPayloads: unknown[] = [];
    const records = [{ privateRecord: "PRIVATE RECORD ONE" }, new Date(0)];
    const value = plan();
    const artifact = {
      privateArtifact: "PRIVATE AUTHORITY ARTIFACT",
      toJSON: () => {
        throw new Error("artifact must not be serialized");
      },
    };
    const authenticateReceipt = vi.fn(() => hmac("9"));
    const authority = {
      evaluate: vi.fn(
        (input: {
          readonly attestation: unknown;
          readonly records: readonly unknown[];
        }) => {
          expect(Object.isFrozen(input)).toBe(true);
          expect(Object.isFrozen(input.records)).toBe(true);
          expect(input.records[0]).toBe(records[0]);
          expect(input.records[1]).toBe(records[1]);
          return { projection: projection(value), artifact };
        },
      ),
    };
    let concurrent = 0;
    const runner = {
      runCase: vi.fn(async (payload: unknown, context: unknown) => {
        concurrent += 1;
        active.push(concurrent);
        observedPayloads.push(payload);
        expect(Object.isFrozen(context)).toBe(true);
        await Promise.resolve();
        concurrent -= 1;
        return records[observedPayloads.length - 1];
      }),
    };

    const result = await runQualification({
      plan: value,
      cases,
      runner,
      authority,
      attestation: { private: "PRIVATE ATTESTATION" },
      runId,
      executableDigest: digest("a"),
      authenticateReceipt,
    });

    expect(active).toEqual([1, 1]);
    expect(observedPayloads).toEqual(cases.map((item) => item.payload));
    expect(result.authorityArtifact).toBe(artifact);
    expect(result.receipt).toMatchObject({
      classification: "shadow-qualification",
      activationCeiling: "shadow-only",
      activationAuthorized: false,
      receiptMac: hmac("9"),
      authority: {
        decision: "unqualified",
        reportDigest: digest("f"),
      },
    });
    expect(result.receipt.cases).toEqual([
      { ordinal: 0, caseRef: hmac("1"), recordDigest: digest("1") },
      { ordinal: 1, caseRef: hmac("2"), recordDigest: digest("2") },
    ]);
    expect(JSON.stringify(result.receipt)).not.toContain("PRIVATE");
    expect(Object.isFrozen(result.receipt)).toBe(true);
    expect(Object.isFrozen(result.receipt.authority)).toBe(true);
    expect(Object.isFrozen(result.receipt.cases)).toBe(true);
    expect(Object.isFrozen(result.receipt.cases[0])).toBe(true);
    const unsigned = authenticateReceipt.mock.calls[0]?.[0];
    expect(unsigned).toBeDefined();
    expect(Object.isFrozen(unsigned)).toBe(true);
    expect(unsigned).not.toHaveProperty("receiptMac");
  });

  it("binds a qualified authority result without authorizing activation", async () => {
    const value = plan();
    const result = await runQualification({
      plan: value,
      cases,
      runner: { runCase: () => ({ sealed: true }) },
      authority: {
        evaluate: () => ({
          projection: projection(value, {
            decision: "qualified",
            qualificationDigest: digest("8"),
          }),
          artifact: "private",
        }),
      },
      attestation: null,
      runId,
      executableDigest: digest("a"),
      authenticateReceipt: () => hmac("9"),
    });

    expect(result.receipt.activationAuthorized).toBe(false);
    expect(result.receipt.authority).toMatchObject({
      decision: "qualified",
      activationCeiling: "shadow-only",
      qualificationDigest: digest("8"),
    });
  });

  it("aborts on a runner failure before authority or authentication", async () => {
    const authority = { evaluate: vi.fn() };
    const authenticateReceipt = vi.fn(() => hmac("9"));
    await expect(
      runQualification({
        plan: plan(),
        cases,
        runner: {
          runCase: () => {
            throw new Error("PRIVATE RUNNER ERROR");
          },
        },
        authority,
        attestation: null,
        runId,
        executableDigest: digest("a"),
        authenticateReceipt,
      }),
    ).rejects.toThrow("PRIVATE RUNNER ERROR");
    expect(authority.evaluate).not.toHaveBeenCalled();
    expect(authenticateReceipt).not.toHaveBeenCalled();
  });

  it("fails closed when authority bindings do not match the plan", async () => {
    const value = plan();
    const mismatched = bindings(value);
    mismatched[0] = { ...mismatched[0]!, pairOrder: mismatched[1]!.pairOrder };
    await expect(
      runQualification({
        plan: value,
        cases,
        runner: { runCase: () => ({ sealed: true }) },
        authority: {
          evaluate: () => ({
            projection: projection(value, { cases: mismatched }),
            artifact: "private",
          }),
        },
        attestation: null,
        runId,
        executableDigest: digest("a"),
        authenticateReceipt: () => hmac("9"),
      }),
    ).rejects.toBeInstanceOf(QualificationInvariantFailure);
  });

  it("fails closed on malformed authority decisions and receipt MACs", async () => {
    const value = plan();
    await expect(
      runQualification({
        plan: value,
        cases,
        runner: { runCase: () => ({ sealed: true }) },
        authority: {
          evaluate: () => ({
            projection: projection(value, {
              decision: "qualified",
              qualificationDigest: undefined,
            }),
            artifact: "private",
          }),
        },
        attestation: null,
        runId,
        executableDigest: digest("a"),
        authenticateReceipt: () => hmac("9"),
      }),
    ).rejects.toBeInstanceOf(QualificationInvariantFailure);

    await expect(
      runQualification({
        plan: value,
        cases,
        runner: { runCase: () => ({ sealed: true }) },
        authority: {
          evaluate: () => ({
            projection: projection(value),
            artifact: "private",
          }),
        },
        attestation: null,
        runId,
        executableDigest: digest("a"),
        authenticateReceipt: () => "invalid" as never,
      }),
    ).rejects.toThrow(/invalid MAC/u);
  });

  it("rejects mutated cases and externally supplied unbalanced plans", async () => {
    const value = plan();
    await expect(
      runQualification({
        plan: value,
        cases: [{ ...cases[0]!, cacheRegime: "warm" }, cases[1]!],
        runner: { runCase: () => ({}) },
        authority: { evaluate: () => ({}) as never },
        attestation: null,
        runId,
        executableDigest: digest("a"),
        authenticateReceipt: () => hmac("9"),
      }),
    ).rejects.toThrow(/do not match/u);

    const unbalanced = {
      ...value,
      cases: value.cases.map((item) => ({
        ...item,
        pairOrder: "ordinary-first" as const,
      })),
    };
    await expect(
      runQualification({
        plan: unbalanced,
        cases,
        runner: { runCase: () => ({}) },
        authority: { evaluate: () => ({}) as never },
        attestation: null,
        runId,
        executableDigest: digest("a"),
        authenticateReceipt: () => hmac("9"),
      }),
    ).rejects.toThrow(/counterbalanced/u);
  });

  it("honors cancellation before, during, and after port execution", async () => {
    const value = plan();
    const preCancelled = new AbortController();
    preCancelled.abort("PRIVATE CANCELLATION REASON");
    const runner = { runCase: vi.fn(() => ({})) };
    const authority = { evaluate: vi.fn(() => ({}) as never) };
    const authenticateReceipt = vi.fn(() => hmac("9"));

    const preError = await captureRejection(
      runQualification({
        plan: value,
        cases,
        runner,
        authority,
        attestation: null,
        runId,
        executableDigest: digest("a"),
        authenticateReceipt,
        signal: preCancelled.signal,
      }),
    );
    expect(preError).toBeInstanceOf(QualificationCancelledFailure);
    expect(String(preError)).not.toContain("PRIVATE CANCELLATION REASON");
    expect(runner.runCase).not.toHaveBeenCalled();
    expect(authority.evaluate).not.toHaveBeenCalled();
    expect(authenticateReceipt).not.toHaveBeenCalled();

    const duringCases = new AbortController();
    const duringAuthority = { evaluate: vi.fn(() => ({}) as never) };
    await expect(
      runQualification({
        plan: value,
        cases,
        runner: {
          runCase: () => {
            duringCases.abort();
            return { sealed: true };
          },
        },
        authority: duringAuthority,
        attestation: null,
        runId,
        executableDigest: digest("a"),
        authenticateReceipt: () => hmac("9"),
        signal: duringCases.signal,
      }),
    ).rejects.toBeInstanceOf(QualificationCancelledFailure);
    expect(duringAuthority.evaluate).not.toHaveBeenCalled();

    const duringEvaluation = new AbortController();
    const afterAuthorityAuthentication = vi.fn(() => hmac("9"));
    await expect(
      runQualification({
        plan: value,
        cases,
        runner: { runCase: () => ({ sealed: true }) },
        authority: {
          evaluate: (input) => {
            expect(input.signal).toBe(duringEvaluation.signal);
            duringEvaluation.abort();
            return { projection: projection(value), artifact: "private" };
          },
        },
        attestation: null,
        runId,
        executableDigest: digest("a"),
        authenticateReceipt: afterAuthorityAuthentication,
        signal: duringEvaluation.signal,
      }),
    ).rejects.toBeInstanceOf(QualificationCancelledFailure);
    expect(afterAuthorityAuthentication).not.toHaveBeenCalled();

    const duringAuthentication = new AbortController();
    await expect(
      runQualification({
        plan: value,
        cases,
        runner: { runCase: () => ({ sealed: true }) },
        authority: {
          evaluate: () => ({
            projection: projection(value),
            artifact: "private",
          }),
        },
        attestation: null,
        runId,
        executableDigest: digest("a"),
        authenticateReceipt: () => {
          duringAuthentication.abort();
          return hmac("9");
        },
        signal: duringAuthentication.signal,
      }),
    ).rejects.toBeInstanceOf(QualificationCancelledFailure);
  });

  it("rejects duplicate authority records and explicit absent qualification digests", async () => {
    const value = plan();
    const duplicateBindings = bindings(value).map((item) => ({
      ...item,
      recordDigest: digest("1"),
    }));
    for (const authorityProjection of [
      projection(value, { cases: duplicateBindings }),
      {
        ...projection(value),
        qualificationDigest: undefined,
      },
    ]) {
      await expect(
        runQualification({
          plan: value,
          cases,
          runner: { runCase: () => ({ sealed: true }) },
          authority: {
            evaluate: () => ({
              projection: authorityProjection,
              artifact: "private",
            }),
          },
          attestation: null,
          runId,
          executableDigest: digest("a"),
          authenticateReceipt: () => hmac("9"),
        }),
      ).rejects.toBeInstanceOf(QualificationInvariantFailure);
    }
  });
});

async function captureRejection(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error("Expected promise to reject");
}
