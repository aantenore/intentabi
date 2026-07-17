import { describe, expect, it } from "vitest";

import {
  createQualificationPlan,
  MAX_QUALIFICATION_CASES,
  type QualificationCase,
} from "../src/index.js";

const hmac = (character: string) =>
  `hmac-sha256:evidence:${character.repeat(64)}` as const;
const digest = (character: string) => `sha256:${character.repeat(64)}` as const;

function qualificationCase(
  character: string,
  overrides: Partial<QualificationCase<string>> = {},
): QualificationCase<string> {
  return {
    caseRef: hmac(character),
    balanceCellRef: hmac("f"),
    cohort: "population",
    difficulty: "simple",
    cacheRegime: "cold",
    payload: `PRIVATE PAYLOAD ${character}`,
    ...overrides,
  };
}

function create(cases: readonly QualificationCase<string>[]) {
  return createQualificationPlan({
    cases,
    seed: "stable-seed",
    keyId: "qualification-evidence-v1",
    datasetDigest: hmac("d"),
    protocolDigest: digest("e"),
  });
}

describe("createQualificationPlan", () => {
  it("creates deterministic, frozen, content-free cell-counterbalanced plans", () => {
    const cases = ["1", "2", "3", "4"].map((character) =>
      qualificationCase(character),
    );

    const first = create(cases);
    const second = create(cases);

    expect(second).toEqual(first);
    expect(
      first.cases.filter((item) => item.pairOrder === "ordinary-first"),
    ).toHaveLength(2);
    expect(
      first.cases.filter((item) => item.pairOrder === "candidate-first"),
    ).toHaveLength(2);
    expect(first.cases.map((item) => item.ordinal)).toEqual([0, 1, 2, 3]);
    expect(JSON.stringify(first)).not.toContain("PRIVATE");
    expect(Object.isFrozen(first)).toBe(true);
    expect(Object.isFrozen(first.cases)).toBe(true);
    expect(first.cases.every(Object.isFrozen)).toBe(true);
    expect(first).toMatchObject({
      classification: "shadow-qualification",
      activationCeiling: "shadow-only",
    });
  });

  it("counterbalances independently across every opaque cell and stratum", () => {
    const cases = [
      qualificationCase("1"),
      qualificationCase("2"),
      qualificationCase("3", { balanceCellRef: hmac("a") }),
      qualificationCase("4", { balanceCellRef: hmac("a") }),
      qualificationCase("5", { cacheRegime: "warm" }),
      qualificationCase("6", { cacheRegime: "warm" }),
      qualificationCase("7", {
        cohort: "adversarial",
        difficulty: "adversarial",
      }),
      qualificationCase("8", {
        cohort: "adversarial",
        difficulty: "adversarial",
      }),
    ];

    const plan = create(cases);
    const cells = new Map<string, string[]>();
    for (const item of plan.cases) {
      const key = [
        item.cohort,
        item.difficulty,
        item.cacheRegime,
        item.balanceCellRef,
      ].join("/");
      const orders = cells.get(key) ?? [];
      orders.push(item.pairOrder);
      cells.set(key, orders);
    }
    expect(cells.size).toBe(4);
    for (const orders of cells.values()) {
      expect(new Set(orders)).toEqual(
        new Set(["ordinary-first", "candidate-first"]),
      );
    }
  });

  it("keeps the opaque payload by reference without reflecting on it", () => {
    let getterCalls = 0;
    const payload = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(payload, "secret", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return "PRIVATE";
      },
    });
    const input = qualificationCase("1", { payload: payload as never });

    const plan = create([input]);

    expect(plan.cases).toHaveLength(1);
    expect(getterCalls).toBe(0);
  });

  it("rejects duplicate references, noncontiguous cohorts, and malformed data", () => {
    expect(() => create([])).toThrow(/empty/u);
    expect(() =>
      create([qualificationCase("1"), qualificationCase("1")]),
    ).toThrow(/case set/u);
    expect(() =>
      create([
        qualificationCase("1", { cohort: "adversarial" }),
        qualificationCase("2", { cohort: "population" }),
      ]),
    ).toThrow(/contiguous/u);
    expect(() =>
      create([
        qualificationCase("1", {
          caseRef: "hmac-sha256:evidence:not-a-digest" as never,
        }),
      ]),
    ).toThrow(/case set/u);

    const sparse: QualificationCase<string>[] = [];
    sparse.length = 2;
    sparse[1] = qualificationCase("2");
    expect(() => create(sparse)).toThrow(/sparse/u);

    const oversized: QualificationCase<string>[] = [];
    oversized.length = MAX_QUALIFICATION_CASES + 1;
    expect(() => create(oversized)).toThrow(/length/u);

    expect(MAX_QUALIFICATION_CASES).toBe(50_000);
  });

  it("rejects accessors and proxies without invoking their code", () => {
    let accessorCalls = 0;
    const hostile = qualificationCase("1") as Record<string, unknown>;
    Object.defineProperty(hostile, "caseRef", {
      enumerable: true,
      get: () => {
        accessorCalls += 1;
        return hmac("1");
      },
    });
    expect(() => create([hostile as never])).toThrow(/plain data/u);
    expect(accessorCalls).toBe(0);

    let trapCalls = 0;
    const proxy = new Proxy(qualificationCase("2"), {
      ownKeys: () => {
        trapCalls += 1;
        return [];
      },
      getOwnPropertyDescriptor: () => {
        trapCalls += 1;
        return undefined;
      },
      get: () => {
        trapCalls += 1;
        return undefined;
      },
    });
    expect(() => create([proxy])).toThrow(/record/u);
    expect(trapCalls).toBe(0);
  });

  it("rejects unknown, hidden, and symbol fields", () => {
    expect(() =>
      create([{ ...qualificationCase("1"), extra: "PRIVATE" } as never]),
    ).toThrow(/fields/u);

    const hidden = qualificationCase("2") as QualificationCase<string> & {
      hidden?: string;
    };
    Object.defineProperty(hidden, "hidden", { value: "PRIVATE" });
    expect(() => create([hidden])).toThrow(/fields/u);

    const symbol = qualificationCase("3") as QualificationCase<string> &
      Record<symbol, string>;
    symbol[Symbol("private")] = "PRIVATE";
    expect(() => create([symbol])).toThrow(/fields/u);
  });
});
