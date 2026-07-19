import { createHash } from "node:crypto";

import {
  parseIntentEvaluationJsonl,
  parseIntentOperationRegistry,
} from "semwitness/intent";

const SOURCE_SPLITS = [
  "oos_val",
  "val",
  "train",
  "oos_test",
  "test",
  "oos_train",
] as const;
const IN_SCOPE_SPLITS = new Set<Clinc150Split>(["train", "val", "test"]);
const MAX_SOURCE_BYTES = 8 * 1024 * 1024;
const MAX_SOURCE_RECORDS = 100_000;
const IDENTIFIER = /^[a-z0-9][a-z0-9._-]{0,127}$/u;
const LOCALE = /^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,4}$/u;
const SHA256 = /^(?:sha256:)?([a-f0-9]{64})$/u;
const REVISION = /^[a-f0-9]{40}$/u;
const UNPAIRED_SURROGATE = /[\uD800-\uDFFF]/u;

/**
 * CLINC labels whose published meaning was reviewed as an information lookup.
 * The benchmark adapter must not invent a read effect for arbitrary labels.
 */
export const CLINC150_REVIEWED_READ_LABELS = Object.freeze([
  "bill_balance",
  "bill_due",
  "credit_score",
  "exchange_rate",
  "flight_status",
  "interest_rate",
  "pto_balance",
  "pto_request_status",
  "rewards_balance",
  "spending_history",
  "transactions",
  "weather",
] as const);
const REVIEWED_READ_LABELS = new Set<string>(CLINC150_REVIEWED_READ_LABELS);

type Clinc150Split = (typeof SOURCE_SPLITS)[number];
type Clinc150Pair = readonly [text: string, label: string];
type Clinc150Source = Readonly<Record<Clinc150Split, readonly Clinc150Pair[]>>;

interface SourceRecord {
  readonly split: Clinc150Split;
  readonly index: number;
  readonly text: string;
  readonly label: string;
}

interface SelectedCase extends SourceRecord {
  readonly id: string;
  readonly familyId: string;
}

export interface PrepareClinc150PilotOptions {
  readonly revision: string;
  readonly sha256: string;
  readonly seed: string;
  readonly locale: string;
  readonly labels: readonly string[];
  readonly trainingAliasesPerIntent: number;
  readonly heldOutPerIntent: number;
  readonly outOfScopeCases: number;
}

export interface PreparedClinc150Pilot {
  readonly registrySource: string;
  readonly fixtureSource: string;
  readonly sourceDigest: `sha256:${string}`;
  readonly registryDigest: `sha256:${string}`;
  readonly corpusDigest: `sha256:${string}`;
  readonly cases: number;
  readonly comparisons: number;
  readonly inScopeCases: number;
  readonly outOfScopeCases: number;
  readonly labels: readonly string[];
}

/**
 * Deterministically materialize a CLINC150 Normalizer Lab input without
 * fetching data or invoking a model. The caller supplies and pins the exact
 * upstream bytes; aliases come only from train/val and evaluation cases only
 * from test/oos_test.
 */
export function prepareClinc150Pilot(
  source: Uint8Array | string,
  options: PrepareClinc150PilotOptions,
): PreparedClinc150Pilot {
  const sourceBytes = sourceToBytes(source);
  const actualSourceDigest = digestBytes(sourceBytes);
  const expectedSourceDigest = parseExpectedDigest(options.sha256);
  if (actualSourceDigest !== expectedSourceDigest) {
    throw new TypeError("CLINC150 source checksum does not match its pin");
  }
  validateOptions(options);

  const decoded = decodeSource(sourceBytes);
  const parsed = parseSource(decoded);
  const labels = Object.freeze([...options.labels].sort(compareCodeUnits));
  const selectedByLabel = new Map<string, readonly SelectedCase[]>();
  const inScopeCases: SelectedCase[] = [];

  for (const label of labels) {
    const candidates = recordsFor(parsed, "test", label);
    const selected = rankRecords(
      candidates,
      options.heldOutPerIntent,
      `${options.seed}\0held-out\0${label}`,
    ).map((record) => ({
      ...record,
      id: `clinc-i-${record.index.toString(36)}`,
      familyId: familyId(label),
    }));
    selectedByLabel.set(label, selected);
    inScopeCases.push(...selected);
  }

  const selectedOutOfScope = rankRecords(
    recordsFor(parsed, "oos_test", "oos"),
    options.outOfScopeCases,
    `${options.seed}\0held-out\0oos`,
  ).map((record) => ({
    ...record,
    id: `clinc-o-${record.index.toString(36)}`,
    familyId: "clinc-oos",
  }));

  const evaluationInputs = new Set<string>();
  for (const item of [...inScopeCases, ...selectedOutOfScope]) {
    const key = lexicalKey(options.locale, item.text);
    if (evaluationInputs.has(key)) {
      throw new TypeError(
        "CLINC150 held-out selection contains a duplicate normalized input",
      );
    }
    evaluationInputs.add(key);
  }

  const usedAliases = new Set<string>();
  const ontology = createOntology(options, labels, actualSourceDigest);
  const operations = labels.map((label) => {
    const aliasCandidates = [
      ...recordsFor(parsed, "train", label),
      ...recordsFor(parsed, "val", label),
    ];
    const ranked = rankAll(
      aliasCandidates,
      `${options.seed}\0aliases\0${label}`,
    );
    const aliases: { readonly locale: string; readonly text: string }[] = [];
    for (const candidate of ranked) {
      const key = lexicalKey(options.locale, candidate.text);
      if (evaluationInputs.has(key) || usedAliases.has(key)) continue;
      usedAliases.add(key);
      aliases.push({ locale: options.locale, text: candidate.text });
      if (aliases.length === options.trainingAliasesPerIntent) break;
    }
    if (aliases.length !== options.trainingAliasesPerIntent) {
      throw new TypeError(
        `CLINC150 label ${label} has too few non-leaking training aliases`,
      );
    }
    return {
      id: label,
      aliases,
      intent: createIntent(ontology, label, options.locale),
    };
  });

  const registrySource = JSON.stringify({
    schema: "semwitness.dev/intent-operation-registry/v1alpha1",
    ontology,
    minimumConfidencePpm: 950_000,
    operations,
  });
  parseIntentOperationRegistry(registrySource);

  const fixtureRecords: unknown[] = [];
  for (const item of inScopeCases) {
    fixtureRecords.push({
      schema: "semwitness.dev/intent-normalizer-eval-fixture/v1alpha1",
      kind: "case",
      id: item.id,
      familyId: item.familyId,
      split: "held-out",
      difficulty: "medium",
      phenomena: ["paraphrase"],
      input: { source: item.text, locale: options.locale },
      expect: {
        kind: "intent",
        intent: createIntent(ontology, item.label, options.locale),
      },
    });
  }
  for (const item of selectedOutOfScope) {
    fixtureRecords.push({
      schema: "semwitness.dev/intent-normalizer-eval-fixture/v1alpha1",
      kind: "case",
      id: item.id,
      familyId: item.familyId,
      split: "held-out",
      difficulty: "adversarial",
      phenomena: ["paraphrase"],
      input: { source: item.text, locale: options.locale },
      expect: { kind: "bypass" },
    });
  }

  let equivalent = 0;
  for (const label of labels) {
    const cases = selectedByLabel.get(label)!;
    if (cases.length === 2) {
      fixtureRecords.push(
        comparison(
          `clinc-e-${equivalent.toString(36)}`,
          cases[0]!,
          cases[1]!,
          "equivalent",
        ),
      );
      equivalent += 1;
      continue;
    }
    for (const [index, left] of cases.entries()) {
      const right = cases[(index + 1) % cases.length]!;
      fixtureRecords.push(
        comparison(
          `clinc-e-${equivalent.toString(36)}`,
          left,
          right,
          "equivalent",
        ),
      );
      equivalent += 1;
    }
  }

  let distinct = 0;
  for (const [labelIndex, label] of labels.entries()) {
    const leftCases = selectedByLabel.get(label)!;
    const nextLabel = labels[(labelIndex + 1) % labels.length]!;
    const rightCases = selectedByLabel.get(nextLabel)!;
    for (const [caseIndex, left] of leftCases.entries()) {
      fixtureRecords.push(
        comparison(
          `clinc-d-${distinct.toString(36)}`,
          left,
          rightCases[caseIndex]!,
          "distinct",
        ),
      );
      distinct += 1;
    }
  }

  const fixtureSource = `${fixtureRecords.map((item) => JSON.stringify(item)).join("\n")}\n`;
  const fixture = parseIntentEvaluationJsonl(fixtureSource);
  const totalCases = inScopeCases.length + selectedOutOfScope.length;
  if (
    fixture.cases.length !== totalCases ||
    fixture.comparisons.length !== equivalent + distinct
  ) {
    throw new TypeError("CLINC150 materialization count invariant failed");
  }

  return Object.freeze({
    registrySource,
    fixtureSource,
    sourceDigest: `sha256:${actualSourceDigest}`,
    registryDigest: `sha256:${digestText(registrySource)}`,
    corpusDigest: fixture.corpusDigest,
    cases: totalCases,
    comparisons: equivalent + distinct,
    inScopeCases: inScopeCases.length,
    outOfScopeCases: selectedOutOfScope.length,
    labels,
  });
}

function createOntology(
  options: PrepareClinc150PilotOptions,
  labels: readonly string[],
  sourceDigest: string,
) {
  const binding = JSON.stringify({
    schema: "io.github.aantenore.intentabi/clinc150-ontology-binding/v1",
    revision: options.revision,
    sourceDigest: `sha256:${sourceDigest}`,
    locale: options.locale,
    labels,
  });
  return {
    id: "clinc150-read-intents",
    version: `1.0.0+${options.revision.slice(0, 12)}`,
    digest: `sha256:${digestText(binding)}`,
  } as const;
}

function createIntent(
  ontology: ReturnType<typeof createOntology>,
  label: string,
  locale: string,
) {
  return {
    schema: "semwitness.dev/intent-ir/v1alpha1",
    ontology,
    goal: {
      namespace: "clinc150",
      action: "identify",
      object: label,
      polarity: "affirm",
    },
    slots: [],
    constraints: [],
    temporal: { kind: "none" },
    output: { format: "json", locale, detail: "exact" },
    // This benchmark identifies a requested read route. It never executes the
    // natural-language request represented by the source dataset.
    effect: "read",
  } as const;
}

function comparison(
  id: string,
  left: SelectedCase,
  right: SelectedCase,
  relation: "equivalent" | "distinct",
) {
  return {
    schema: "semwitness.dev/intent-normalizer-eval-fixture/v1alpha1",
    kind: "comparison",
    id,
    split: "held-out",
    leftCaseId: left.id,
    rightCaseId: right.id,
    relation,
  } as const;
}

function parseSource(source: string): Clinc150Source {
  let value: unknown;
  try {
    value = JSON.parse(source);
  } catch {
    throw new TypeError("CLINC150 source is not valid JSON");
  }
  if (!isPlainRecord(value)) {
    throw new TypeError("CLINC150 source must be an object");
  }
  const keys = Object.keys(value).sort(compareCodeUnits);
  const expectedKeys = [...SOURCE_SPLITS].sort(compareCodeUnits);
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key, index) => key !== expectedKeys[index])
  ) {
    throw new TypeError("CLINC150 source has an unexpected top-level shape");
  }

  const parsed = {} as Record<Clinc150Split, Clinc150Pair[]>;
  let records = 0;
  for (const split of SOURCE_SPLITS) {
    const entries = value[split];
    if (!Array.isArray(entries)) {
      throw new TypeError(`CLINC150 split ${split} must be an array`);
    }
    const expectedOos = !IN_SCOPE_SPLITS.has(split);
    parsed[split] = entries.map((entry, index) => {
      records += 1;
      if (
        records > MAX_SOURCE_RECORDS ||
        !Array.isArray(entry) ||
        entry.length !== 2 ||
        typeof entry[0] !== "string" ||
        typeof entry[1] !== "string" ||
        entry[0].length === 0 ||
        entry[0].length > 16_384 ||
        UNPAIRED_SURROGATE.test(entry[0]) ||
        !IDENTIFIER.test(entry[1]) ||
        (expectedOos ? entry[1] !== "oos" : entry[1] === "oos")
      ) {
        throw new TypeError(
          `CLINC150 split ${split} has an invalid record at ${index}`,
        );
      }
      return [entry[0], entry[1]] as const;
    });
  }
  return parsed;
}

function validateOptions(options: PrepareClinc150PilotOptions): void {
  if (!REVISION.test(options.revision)) {
    throw new TypeError("CLINC150 revision must be a full Git commit id");
  }
  if (!IDENTIFIER.test(options.seed)) {
    throw new TypeError("CLINC150 seed is invalid");
  }
  if (!LOCALE.test(options.locale) || options.locale !== "en-US") {
    throw new TypeError("CLINC150 is an English-only en-US source");
  }
  if (
    !Array.isArray(options.labels) ||
    options.labels.length < 4 ||
    options.labels.length > 64 ||
    new Set(options.labels).size !== options.labels.length ||
    options.labels.some(
      (label) =>
        !IDENTIFIER.test(label) ||
        label === "oos" ||
        !REVIEWED_READ_LABELS.has(label),
    )
  ) {
    throw new TypeError("CLINC150 labels are not reviewed read operations");
  }
  assertBoundedInteger(options.trainingAliasesPerIntent, 1, 20, "alias count");
  assertBoundedInteger(options.heldOutPerIntent, 2, 30, "held-out count");
  assertBoundedInteger(options.outOfScopeCases, 1, 1_000, "OOS count");
}

function recordsFor(
  source: Clinc150Source,
  split: Clinc150Split,
  label: string,
): SourceRecord[] {
  const records = source[split].flatMap(([text, candidate], index) =>
    candidate === label ? [{ split, index, text, label: candidate }] : [],
  );
  if (records.length === 0) {
    throw new TypeError(`CLINC150 label ${label} is absent from ${split}`);
  }
  return records;
}

function rankRecords(
  records: readonly SourceRecord[],
  count: number,
  seed: string,
): SourceRecord[] {
  const ranked = rankAll(records, seed);
  if (ranked.length < count) {
    throw new TypeError(
      "CLINC150 split does not contain enough requested cases",
    );
  }
  return ranked.slice(0, count);
}

function rankAll(
  records: readonly SourceRecord[],
  seed: string,
): SourceRecord[] {
  return records
    .map((record) => ({
      record,
      rank: digestText(
        `${seed}\0${record.split}\0${record.index}\0${record.text}\0${record.label}`,
      ),
    }))
    .sort((left, right) =>
      left.rank === right.rank
        ? left.record.index - right.record.index
        : compareCodeUnits(left.rank, right.rank),
    )
    .map(({ record }) => record);
}

function sourceToBytes(source: Uint8Array | string): Uint8Array {
  if (typeof source === "string") {
    if (UNPAIRED_SURROGATE.test(source)) {
      throw new TypeError("CLINC150 source contains malformed Unicode");
    }
    const bytes = new TextEncoder().encode(source);
    assertSourceSize(bytes.byteLength);
    return bytes;
  }
  if (!(source instanceof Uint8Array)) {
    throw new TypeError("CLINC150 source must be UTF-8 bytes or text");
  }
  assertSourceSize(source.byteLength);
  return new Uint8Array(source);
}

function decodeSource(source: Uint8Array): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(source);
  } catch {
    throw new TypeError("CLINC150 source is not valid UTF-8");
  }
}

function assertSourceSize(bytes: number): void {
  if (bytes < 2 || bytes > MAX_SOURCE_BYTES) {
    throw new TypeError("CLINC150 source exceeds its byte budget");
  }
}

function parseExpectedDigest(value: string): string {
  const match = SHA256.exec(value);
  if (match === null) throw new TypeError("CLINC150 SHA-256 pin is invalid");
  return match[1]!;
}

function assertBoundedInteger(
  value: number,
  minimum: number,
  maximum: number,
  label: string,
): void {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`CLINC150 ${label} is invalid`);
  }
}

function lexicalKey(locale: string, text: string): string {
  return `${locale.toLowerCase()}\0${text
    .normalize("NFKC")
    .toLowerCase()
    .replace(/[\t\n\r ]+/gu, " ")
    .trim()}`;
}

function familyId(label: string): string {
  return `clinc-f-${digestText(label).slice(0, 20)}`;
}

function digestBytes(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function digestText(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function compareCodeUnits(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
