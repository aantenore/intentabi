import { createHash } from "node:crypto";

import {
  openPrivateRunStore,
  PrivateRunStoreError,
  type PrivateRunStorePartition,
} from "@intentabi/private-run-store";
import { z } from "zod";

import {
  DIAGNOSTIC_CAPTURE_CLASSIFICATION,
  normalizeProviderBaseUrl,
  type DiagnosticCaptureCase,
  type DiagnosticCaptureConfig,
  type DiagnosticCaptureDataset,
} from "./config.js";
import type {
  DiagnosticProviderObservation,
  DiagnosticProviderRunner,
} from "./provider.js";
import { DiagnosticProviderError } from "./provider.js";

export const DIAGNOSTIC_CAPTURE_RECORD_SCHEMA =
  "io.github.aantenore.intentabi/diagnostic-capture-record/v1alpha1" as const;
export const DIAGNOSTIC_CAPTURE_MANIFEST_SCHEMA =
  "io.github.aantenore.intentabi/diagnostic-capture-manifest/v1alpha1" as const;
export const CACHE_IMPACT_WORKLOAD_SCHEMA =
  "io.github.aantenore.intentabi/cache-impact-workload/v1alpha1" as const;

const digest = z.string().regex(/^sha256:[a-f0-9]{64}$/u);
const identifier = z.string().regex(/^[a-z0-9][a-z0-9._-]{0,127}$/u);
const tokenCounter = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const nullableTokenCounter = tokenCounter.nullable();

const captureRecordSchema = z
  .object({
    schema: z.literal(DIAGNOSTIC_CAPTURE_RECORD_SCHEMA),
    classification: z.literal(DIAGNOSTIC_CAPTURE_CLASSIFICATION),
    statisticalQualification: z.literal(false),
    activationAuthorized: z.literal(false),
    promotionManifest: z.literal("not-produced"),
    datasetDigest: digest,
    configDigest: digest,
    ordinal: z.number().int().min(0),
    caseId: identifier,
    caseDigest: digest,
    provider: z
      .object({
        kind: z.literal("openai-compatible-chat-completions"),
        name: identifier,
        model: z.string().min(1).max(256),
        deploymentRevisionDigest: digest,
        credentialKeyId: identifier,
        endpointDigest: digest,
        usageProvenance: z.literal("host-observed-openai-compatible-response"),
        usage: z
          .object({
            inputTokens: tokenCounter,
            outputTokens: tokenCounter,
            totalTokens: tokenCounter,
            reasoningOutputTokens: nullableTokenCounter,
          })
          .strict(),
        response: z
          .object({
            wireContentDigest: digest,
            canonicalValueDigest: digest,
            reasoningPresent: z.boolean(),
            reasoningDigest: digest.nullable(),
            warningCount: tokenCounter,
          })
          .strict(),
      })
      .strict(),
    oracle: z
      .object({
        provenance: z.literal("host-supplied-canonical-json"),
        expectedValueDigest: digest,
        matched: z.boolean(),
      })
      .strict(),
    normalizationUsage: z
      .object({ inputTokens: tokenCounter, outputTokens: tokenCounter })
      .strict(),
  })
  .strict();

export type DiagnosticCaptureRecord = z.infer<typeof captureRecordSchema>;

export interface DiagnosticCaptureResult {
  readonly classification: typeof DIAGNOSTIC_CAPTURE_CLASSIFICATION;
  readonly statisticalQualification: false;
  readonly activationAuthorized: false;
  readonly complete: boolean;
  readonly workloadProduced: boolean;
  readonly totalCases: number;
  readonly capturedThisRun: number;
  readonly resumedCases: number;
  readonly remainingCases: number;
  readonly oracleMismatches: number;
  readonly workloadDigest: `sha256:${string}` | null;
}

export function assertDiagnosticArtifactBudgets(
  config: DiagnosticCaptureConfig,
  dataset: DiagnosticCaptureDataset,
): void {
  try {
    const configDigest = sha256Canonical(config);
    const datasetDigest = sha256Canonical(dataset);
    const endpointDigest = sha256Text(
      `${normalizeProviderBaseUrl(config.provider.baseUrl)}/chat/completions`,
    );
    const maximumBalancedCounter = Math.floor(Number.MAX_SAFE_INTEGER / 2);
    const maximumRecords = dataset.cases.map((item, ordinal) => {
      const record = createRecord({
        config,
        expected: expectedCaseBinding(item, ordinal, {
          configDigest,
          datasetDigest,
        }),
        endpointDigest,
        observation: {
          output: { preflight: true },
          rawText: "preflight",
          reasoningText: "preflight",
          warningCount: Number.MAX_SAFE_INTEGER,
          usage: {
            inputTokens: maximumBalancedCounter,
            outputTokens: maximumBalancedCounter,
            totalTokens: maximumBalancedCounter * 2,
            reasoningOutputTokens: maximumBalancedCounter,
          },
        },
      });
      const maximumRecord = captureRecordSchema.parse({
        ...record,
        oracle: { ...record.oracle, matched: false },
      });
      if (serialize(maximumRecord).byteLength > config.capture.maxRecordBytes) {
        throw new DiagnosticCaptureError();
      }
      return maximumRecord;
    });

    const maximumWorkload = createWorkload(dataset, maximumRecords);
    if (
      serialize(maximumWorkload).byteLength > config.capture.maxWorkloadBytes
    ) {
      throw new DiagnosticCaptureError();
    }

    const maximumManifestRecords = maximumRecords.map((record) =>
      captureRecordSchema.parse({
        ...record,
        provider: {
          ...record.provider,
          response: {
            ...record.provider.response,
            reasoningPresent: false,
            reasoningDigest: null,
          },
        },
      }),
    );
    const matchingManifestRecords = maximumManifestRecords.map((record) =>
      captureRecordSchema.parse({
        ...record,
        oracle: { ...record.oracle, matched: true },
      }),
    );
    const maximumAggregateTokens = (
      BigInt(Number.MAX_SAFE_INTEGER) * BigInt(maximumRecords.length)
    ).toString();
    const maximumManifest = (input: {
      readonly records: readonly DiagnosticCaptureRecord[];
      readonly oracleMismatches: number;
      readonly workloadDigest: `sha256:${string}` | null;
    }) => {
      const manifest = createManifest({
        config,
        dataset,
        configDigest,
        datasetDigest,
        endpointDigest,
        ...input,
      });
      return {
        ...manifest,
        summary: {
          ...manifest.summary,
          providerInputTokens: maximumAggregateTokens,
          providerOutputTokens: maximumAggregateTokens,
        },
      };
    };
    const withoutWorkload = serialize(
      maximumManifest({
        records: maximumManifestRecords,
        oracleMismatches: maximumManifestRecords.length,
        workloadDigest: null,
      }),
    ).byteLength;
    const withWorkload = serialize(
      maximumManifest({
        records: matchingManifestRecords,
        oracleMismatches: 0,
        workloadDigest: sha256Text("preflight-workload"),
      }),
    ).byteLength;
    const mixedSummaryAllowance =
      2 * String(Math.max(1, maximumRecords.length)).length;
    if (
      Math.max(withWorkload, withoutWorkload + mixedSummaryAllowance) >
      config.capture.maxManifestBytes
    ) {
      throw new DiagnosticCaptureError();
    }
  } catch (error) {
    if (error instanceof DiagnosticCaptureError) throw error;
    throw new DiagnosticCaptureError();
  }
}

export interface DiagnosticCaptureInput {
  readonly config: DiagnosticCaptureConfig;
  readonly dataset: DiagnosticCaptureDataset;
  readonly runDirectory: string;
  readonly runner: DiagnosticProviderRunner;
  readonly limit?: number;
}

export async function captureDiagnosticPilot(
  input: DiagnosticCaptureInput,
): Promise<DiagnosticCaptureResult> {
  try {
    return await captureDiagnosticPilotWithStore(input);
  } catch (error) {
    if (error instanceof PrivateRunStoreError) {
      throw new DiagnosticCaptureError();
    }
    throw error;
  }
}

async function captureDiagnosticPilotWithStore(
  input: DiagnosticCaptureInput,
): Promise<DiagnosticCaptureResult> {
  assertDiagnosticArtifactBudgets(input.config, input.dataset);
  const store = await openPrivateRunStore({
    path: input.runDirectory,
    partitions: ["records"],
  });
  const recordsStore = store.partition("records");
  const configDigest = sha256Canonical(input.config);
  const datasetDigest = sha256Canonical(input.dataset);
  const endpointDigest = sha256Text(
    `${normalizeProviderBaseUrl(input.config.provider.baseUrl)}/chat/completions`,
  );
  const limit = input.limit ?? input.dataset.cases.length;
  if (!Number.isSafeInteger(limit) || limit < 1) {
    throw new DiagnosticCaptureError();
  }

  const records: DiagnosticCaptureRecord[] = [];
  let capturedThisRun = 0;
  let resumedCases = 0;
  for (const [ordinal, item] of input.dataset.cases.entries()) {
    const expected = expectedCaseBinding(item, ordinal, {
      configDigest,
      datasetDigest,
    });
    const existing = await readOptionalRecord(
      recordName(ordinal, item.id),
      input.config.capture.maxRecordBytes,
      recordsStore,
    );
    if (existing !== null) {
      assertRecordBinding(existing, expected, input.config, endpointDigest);
      records.push(existing);
      resumedCases += 1;
      continue;
    }
    if (capturedThisRun >= limit) continue;

    try {
      const observation = await store.guard(() =>
        input.runner.run(item.source),
      );
      const record = createRecord({
        config: input.config,
        expected,
        endpointDigest,
        observation,
      });
      const bytes = serialize(record);
      if (
        (await recordsStore.create(
          recordName(ordinal, item.id),
          bytes,
          input.config.capture.maxRecordBytes,
        )) !== "created"
      ) {
        throw new DiagnosticCaptureError();
      }
      records.push(record);
      capturedThisRun += 1;
    } catch (error) {
      if (error instanceof DiagnosticProviderError) throw error;
      throw new DiagnosticCaptureError();
    }
  }

  records.sort((left, right) => left.ordinal - right.ordinal);
  const remainingCases = input.dataset.cases.length - records.length;
  const oracleMismatches = records.filter(
    (record) => !record.oracle.matched,
  ).length;
  if (remainingCases > 0) {
    await store.assertStable();
    return result({
      complete: false,
      workloadProduced: false,
      totalCases: input.dataset.cases.length,
      capturedThisRun,
      resumedCases,
      remainingCases,
      oracleMismatches,
      workloadDigest: null,
    });
  }

  assertDenseRecords(records, input.dataset.cases.length);
  let workloadDigest: `sha256:${string}` | null = null;
  let workloadProduced = false;
  if (oracleMismatches === 0) {
    const workload = createWorkload(input.dataset, records);
    workloadDigest = sha256Canonical(workload);
    await store.root.publishOrVerify(
      "cache-impact-workload.json",
      serialize(workload),
      input.config.capture.maxWorkloadBytes,
    );
    workloadProduced = true;
  }
  const manifest = createManifest({
    config: input.config,
    dataset: input.dataset,
    configDigest,
    datasetDigest,
    endpointDigest,
    records,
    oracleMismatches,
    workloadDigest,
  });
  await store.root.publishOrVerify(
    "diagnostic-capture-manifest.json",
    serialize(manifest),
    input.config.capture.maxManifestBytes,
  );
  await store.assertStable();

  return result({
    complete: true,
    workloadProduced,
    totalCases: input.dataset.cases.length,
    capturedThisRun,
    resumedCases,
    remainingCases: 0,
    oracleMismatches,
    workloadDigest,
  });
}

function expectedCaseBinding(
  item: DiagnosticCaptureCase,
  ordinal: number,
  bindings: {
    readonly configDigest: `sha256:${string}`;
    readonly datasetDigest: `sha256:${string}`;
  },
) {
  return Object.freeze({
    ordinal,
    caseId: item.id,
    caseDigest: sha256Canonical({
      schema: "io.github.aantenore.intentabi/diagnostic-case-binding/v1",
      ordinal,
      item,
    }),
    oracleDigest: sha256Canonical(item.oracleValue),
    ...bindings,
  });
}

function createRecord(input: {
  readonly config: DiagnosticCaptureConfig;
  readonly expected: ReturnType<typeof expectedCaseBinding>;
  readonly endpointDigest: `sha256:${string}`;
  readonly observation: DiagnosticProviderObservation;
}): DiagnosticCaptureRecord {
  const canonicalValueDigest = sha256Canonical(input.observation.output);
  const reasoning = input.observation.reasoningText;
  return captureRecordSchema.parse({
    schema: DIAGNOSTIC_CAPTURE_RECORD_SCHEMA,
    classification: DIAGNOSTIC_CAPTURE_CLASSIFICATION,
    statisticalQualification: false,
    activationAuthorized: false,
    promotionManifest: "not-produced",
    datasetDigest: input.expected.datasetDigest,
    configDigest: input.expected.configDigest,
    ordinal: input.expected.ordinal,
    caseId: input.expected.caseId,
    caseDigest: input.expected.caseDigest,
    provider: {
      kind: input.config.provider.kind,
      name: input.config.provider.name,
      model: input.config.provider.model,
      deploymentRevisionDigest: input.config.provider.deploymentRevisionDigest,
      credentialKeyId: input.config.provider.credentialKeyId,
      endpointDigest: input.endpointDigest,
      usageProvenance: "host-observed-openai-compatible-response",
      usage: input.observation.usage,
      response: {
        wireContentDigest: sha256Text(input.observation.rawText),
        canonicalValueDigest,
        reasoningPresent: reasoning !== null,
        reasoningDigest: reasoning === null ? null : sha256Text(reasoning),
        warningCount: input.observation.warningCount,
      },
    },
    oracle: {
      provenance: "host-supplied-canonical-json",
      expectedValueDigest: input.expected.oracleDigest,
      matched: canonicalValueDigest === input.expected.oracleDigest,
    },
    normalizationUsage: input.config.capture.normalizationUsage,
  });
}

function createWorkload(
  dataset: DiagnosticCaptureDataset,
  records: readonly DiagnosticCaptureRecord[],
) {
  return {
    schema: CACHE_IMPACT_WORKLOAD_SCHEMA,
    datasetId: dataset.id,
    cases: dataset.cases.map((item, ordinal) => {
      const record = records[ordinal]!;
      return {
        source: item.source,
        locale: item.locale,
        routeInput: item.routeInput,
        expectedValueDigest: record.oracle.expectedValueDigest,
        usage: {
          modelInputTokens: record.provider.usage.inputTokens,
          modelOutputTokens: record.provider.usage.outputTokens,
          normalizationInputTokens: record.normalizationUsage.inputTokens,
          normalizationOutputTokens: record.normalizationUsage.outputTokens,
        },
      };
    }),
  };
}

function createManifest(input: {
  readonly config: DiagnosticCaptureConfig;
  readonly dataset: DiagnosticCaptureDataset;
  readonly configDigest: `sha256:${string}`;
  readonly datasetDigest: `sha256:${string}`;
  readonly endpointDigest: `sha256:${string}`;
  readonly records: readonly DiagnosticCaptureRecord[];
  readonly oracleMismatches: number;
  readonly workloadDigest: `sha256:${string}` | null;
}) {
  const inputTokens = input.records.reduce(
    (total, record) => total + BigInt(record.provider.usage.inputTokens),
    0n,
  );
  const outputTokens = input.records.reduce(
    (total, record) => total + BigInt(record.provider.usage.outputTokens),
    0n,
  );
  return {
    schema: DIAGNOSTIC_CAPTURE_MANIFEST_SCHEMA,
    classification: DIAGNOSTIC_CAPTURE_CLASSIFICATION,
    statisticalQualification: false,
    activationAuthorized: false,
    promotionManifest: "not-produced",
    dataset: {
      id: input.dataset.id,
      split: input.dataset.split,
      digest: input.datasetDigest,
    },
    configDigest: input.configDigest,
    provider: {
      kind: input.config.provider.kind,
      name: input.config.provider.name,
      model: input.config.provider.model,
      deploymentRevisionDigest: input.config.provider.deploymentRevisionDigest,
      credentialKeyId: input.config.provider.credentialKeyId,
      endpointDigest: input.endpointDigest,
      usageProvenance: "host-observed-openai-compatible-response",
    },
    records: input.records.map((record) => ({
      ordinal: record.ordinal,
      caseId: record.caseId,
      recordDigest: sha256Canonical(record),
      oracleMatched: record.oracle.matched,
      reasoningPresent: record.provider.response.reasoningPresent,
    })),
    workload:
      input.workloadDigest === null
        ? { status: "not-produced", digest: null }
        : { status: "produced", digest: input.workloadDigest },
    summary: {
      cases: input.records.length,
      oracleMatches: input.records.length - input.oracleMismatches,
      oracleMismatches: input.oracleMismatches,
      providerInputTokens: inputTokens.toString(),
      providerOutputTokens: outputTokens.toString(),
    },
  };
}

async function readOptionalRecord(
  name: string,
  maximumBytes: number,
  partition: PrivateRunStorePartition,
): Promise<DiagnosticCaptureRecord | null> {
  try {
    const bytes = await partition.readOptional(name, maximumBytes);
    if (bytes === null) return null;
    return captureRecordSchema.parse(
      JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)),
    );
  } catch {
    throw new DiagnosticCaptureError();
  }
}

function assertRecordBinding(
  record: DiagnosticCaptureRecord,
  expected: ReturnType<typeof expectedCaseBinding>,
  config: DiagnosticCaptureConfig,
  endpointDigest: `sha256:${string}`,
): void {
  if (
    record.ordinal !== expected.ordinal ||
    record.caseId !== expected.caseId ||
    record.caseDigest !== expected.caseDigest ||
    record.datasetDigest !== expected.datasetDigest ||
    record.configDigest !== expected.configDigest ||
    record.oracle.expectedValueDigest !== expected.oracleDigest ||
    record.oracle.matched !==
      (record.provider.response.canonicalValueDigest ===
        expected.oracleDigest) ||
    record.provider.kind !== config.provider.kind ||
    record.provider.name !== config.provider.name ||
    record.provider.model !== config.provider.model ||
    record.provider.deploymentRevisionDigest !==
      config.provider.deploymentRevisionDigest ||
    record.provider.credentialKeyId !== config.provider.credentialKeyId ||
    record.provider.endpointDigest !== endpointDigest ||
    record.normalizationUsage.inputTokens !==
      config.capture.normalizationUsage.inputTokens ||
    record.normalizationUsage.outputTokens !==
      config.capture.normalizationUsage.outputTokens ||
    record.provider.response.reasoningPresent !==
      (record.provider.response.reasoningDigest !== null) ||
    record.provider.usage.totalTokens !==
      record.provider.usage.inputTokens + record.provider.usage.outputTokens ||
    (record.provider.usage.reasoningOutputTokens !== null &&
      record.provider.usage.reasoningOutputTokens >
        record.provider.usage.outputTokens)
  ) {
    throw new DiagnosticCaptureError();
  }
}

function assertDenseRecords(
  records: readonly DiagnosticCaptureRecord[],
  expectedLength: number,
): void {
  if (
    records.length !== expectedLength ||
    records.some((record, ordinal) => record.ordinal !== ordinal)
  ) {
    throw new DiagnosticCaptureError();
  }
}

function recordName(ordinal: number, id: string): string {
  return `${String(ordinal).padStart(5, "0")}-${id}.json`;
}

function serialize(value: unknown): Uint8Array {
  return new TextEncoder().encode(`${JSON.stringify(value, null, 2)}\n`);
}

function sha256Canonical(value: unknown): `sha256:${string}` {
  return sha256Text(canonicalJson(value));
}

function sha256Text(value: string): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalValue(value));
}

function canonicalValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value !== null && typeof value === "object") {
    const record = value as Readonly<Record<string, unknown>>;
    return Object.fromEntries(
      Object.keys(record)
        .sort()
        .map((key) => [key, canonicalValue(record[key])]),
    );
  }
  return value;
}

function result(
  value: Omit<
    DiagnosticCaptureResult,
    "classification" | "statisticalQualification" | "activationAuthorized"
  >,
): DiagnosticCaptureResult {
  return Object.freeze({
    classification: DIAGNOSTIC_CAPTURE_CLASSIFICATION,
    statisticalQualification: false,
    activationAuthorized: false,
    ...value,
  });
}

export class DiagnosticCaptureError extends Error {
  constructor() {
    super("Diagnostic capture failed");
    this.name = "DiagnosticCaptureError";
  }
}
