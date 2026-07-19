import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";
import {
  parseIntentEvaluationJsonl,
  parseIntentOperationRegistry,
} from "semwitness/intent";

import { prepareClinc150Pilot } from "../src/clinc150.js";

const labels = [
  "bill_balance",
  "bill_due",
  "credit_score",
  "exchange_rate",
] as const;
const revision = "a".repeat(40);

function source(overrides: Record<string, unknown> = {}) {
  const records = (prefix: string, label: string, count: number) =>
    Array.from({ length: count }, (_, index) => [
      `${prefix} ${label} phrase ${index}`,
      label,
    ]);
  return JSON.stringify({
    oos_val: records("oos-val", "oos", 2),
    val: labels.flatMap((label) => records("val", label, 3)),
    train: labels.flatMap((label) => records("train", label, 4)),
    oos_test: records("oos-test", "oos", 5),
    test: labels.flatMap((label) => records("test", label, 4)),
    oos_train: records("oos-train", "oos", 2),
    ...overrides,
  });
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function options(value: string) {
  return {
    revision,
    sha256: sha256(value),
    seed: "external-pilot-v1",
    locale: "en-US",
    labels,
    trainingAliasesPerIntent: 3,
    heldOutPerIntent: 2,
    outOfScopeCases: 2,
  } as const;
}

describe("CLINC150 pilot preparation", () => {
  it("builds deterministic, frozen SemWitness inputs without split leakage", () => {
    const input = source();
    const first = prepareClinc150Pilot(input, options(input));
    const second = prepareClinc150Pilot(
      new TextEncoder().encode(input),
      options(input),
    );

    expect(second).toEqual(first);
    expect(Object.isFrozen(first)).toBe(true);
    expect(Object.isFrozen(first.labels)).toBe(true);
    expect(first).toMatchObject({
      cases: 10,
      inScopeCases: 8,
      outOfScopeCases: 2,
      comparisons: 12,
      sourceDigest: `sha256:${sha256(input)}`,
    });

    const registry = parseIntentOperationRegistry(first.registrySource);
    const fixture = parseIntentEvaluationJsonl(first.fixtureSource);
    expect(fixture.corpusDigest).toBe(first.corpusDigest);
    expect(registry.operations).toHaveLength(labels.length);
    expect(fixture.cases).toHaveLength(first.cases);
    expect(fixture.comparisons).toHaveLength(first.comparisons);

    const aliases = new Set(
      registry.operations.flatMap((operation) =>
        operation.aliases.map((alias) => alias.text),
      ),
    );
    const evaluation = new Set(fixture.cases.map((item) => item.input.source));
    expect([...aliases].every((text) => /^(?:train|val) /u.test(text))).toBe(
      true,
    );
    expect(
      [...evaluation].every((text) => /^(?:test|oos-test) /u.test(text)),
    ).toBe(true);
    expect([...aliases].some((text) => evaluation.has(text))).toBe(false);
    expect(
      fixture.comparisons.filter((item) => item.relation === "equivalent"),
    ).toHaveLength(4);
    expect(
      fixture.comparisons.filter((item) => item.relation === "distinct"),
    ).toHaveLength(8);
  });

  it("rejects checksum drift and an open source shape", () => {
    const input = source();
    expect(() =>
      prepareClinc150Pilot(input, {
        ...options(input),
        sha256: "0".repeat(64),
      }),
    ).toThrow(/checksum/u);

    const open = source({ extra: [] });
    expect(() => prepareClinc150Pilot(open, options(open))).toThrow(
      /top-level shape/u,
    );
  });

  it("filters a held-out duplicate from aliases and fails closed if the alias budget cannot be met", () => {
    const parsed = JSON.parse(source()) as Record<string, unknown>;
    const train = parsed.train as string[][];
    const test = parsed.test as string[][];
    train[0]![0] = test[0]![0]!;
    const input = JSON.stringify(parsed);
    const prepared = prepareClinc150Pilot(input, options(input));
    const registry = parseIntentOperationRegistry(prepared.registrySource);
    const fixture = parseIntentEvaluationJsonl(prepared.fixtureSource);
    const evaluation = new Set(fixture.cases.map((item) => item.input.source));
    expect(
      registry.operations
        .flatMap((operation) => operation.aliases)
        .some((alias) => evaluation.has(alias.text)),
    ).toBe(false);

    const sparse = JSON.parse(source()) as Record<string, unknown>;
    let retainedAlpha = false;
    sparse.train = (sparse.train as string[][]).flatMap(([text, label]) => {
      if (label !== "bill_balance") return [[text, label]];
      if (retainedAlpha) return [];
      retainedAlpha = true;
      return [["test bill_balance phrase 0", label]];
    });
    sparse.val = (sparse.val as string[][]).map(([text, label]) =>
      label === "bill_balance"
        ? ["test bill_balance phrase 0", label]
        : [text, label],
    );
    const sparseSource = JSON.stringify(sparse);
    expect(() =>
      prepareClinc150Pilot(sparseSource, options(sparseSource)),
    ).toThrow(/too few non-leaking training aliases/u);
  });

  it("rejects malformed split records before materialization", () => {
    const parsed = JSON.parse(source()) as Record<string, unknown>;
    (parsed.oos_test as string[][])[0] = ["not really OOS", "alpha"];
    const input = JSON.stringify(parsed);
    expect(() => prepareClinc150Pilot(input, options(input))).toThrow(
      /invalid record/u,
    );
  });
});
