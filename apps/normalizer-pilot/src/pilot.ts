import { createHash } from "node:crypto";

import {
  openPrivateRunStore,
  type PrivateRunStore,
} from "@intentabi/private-run-store";
import {
  DeclarativeIntentNormalizer,
  parseIntentEvaluationJsonl,
  runIntentNormalizerEvaluation,
  type IntentEvaluationCheckpointStore,
  type IntentEvaluationProgress,
  type IntentEvaluationReport,
  type IntentProposalCompiler,
  type RunIntentNormalizerEvaluationResult,
} from "semwitness/intent";
import {
  OpenAICompatibleIntentCompiler,
  type OpenAICompatibleIntentCompilerConfig,
} from "semwitness/intent/openai-compatible";

import { prepareClinc150Pilot } from "./clinc150.js";
import {
  EXAMPLE_DEPLOYMENT_REVISION_DIGEST,
  NORMALIZER_PILOT_CLASSIFICATION,
  parseNormalizerPilotConfig,
  type NormalizerPilotConfig,
} from "./config.js";
import { createNormalizerPilotCheckpointStore } from "./checkpoint-store.js";

export const NORMALIZER_PILOT_ARTIFACT_SCHEMA =
  "io.github.aantenore.intentabi/normalizer-pilot-artifact/v1alpha2" as const;
export const NORMALIZER_PILOT_RUN_BINDING_SCHEMA =
  "io.github.aantenore.intentabi/normalizer-pilot-run-binding/v2" as const;
export const NORMALIZER_PILOT_ARTIFACT_NAME =
  "normalizer-pilot-artifact.json" as const;
export const NORMALIZER_PILOT_RUN_BINDING_NAME =
  "normalizer-pilot-run-binding.json" as const;
export const NORMALIZER_PILOT_SEMWITNESS_REVISION =
  "b31e0e05e0bc723f918afeca9287a18af12cae9d" as const;

export interface NormalizerPilotPreparation {
  readonly prepared: ReturnType<typeof prepareClinc150Pilot>;
  readonly registry: DeclarativeIntentNormalizer;
  readonly fixture: ReturnType<typeof parseIntentEvaluationJsonl>;
  readonly plannedRequests: number;
}

export interface NormalizerPilotArtifact {
  readonly schema: typeof NORMALIZER_PILOT_ARTIFACT_SCHEMA;
  readonly classification: typeof NORMALIZER_PILOT_CLASSIFICATION;
  readonly statisticalQualification: false;
  readonly economicQualification: false;
  readonly activationAuthorized: false;
  readonly promotionManifest: "not-produced";
  readonly qualificationStatus: "external-evidence-required";
  readonly pilotRunBindingDigest: `sha256:${string}`;
  readonly checkpointLineage: {
    readonly protocol: "semwitness.intent-evaluation-checkpoint/v1";
    readonly semwitnessRevision: typeof NORMALIZER_PILOT_SEMWITNESS_REVISION;
    readonly evaluationBindingDigest: `sha256:${string}`;
    readonly completedObservations: number;
    readonly totalObservations: number;
  };
  readonly source: {
    readonly kind: "clinc150";
    readonly revision: string;
    readonly sourceDigest: `sha256:${string}`;
    readonly registryDigest: `sha256:${string}`;
    readonly corpusDigest: `sha256:${string}`;
    readonly seed: string;
    readonly locale: "en-US";
    readonly labels: readonly string[];
    readonly cases: number;
    readonly comparisons: number;
    readonly inScopeCases: number;
    readonly outOfScopeCases: number;
  };
  readonly compiler: {
    readonly kind: "openai-compatible";
    readonly deploymentRevisionDigest: `sha256:${string}`;
    readonly credentialKeyId: string;
    readonly manifest: IntentProposalCompiler["manifest"];
  };
  readonly evaluation: IntentEvaluationReport;
}

export interface NormalizerPilotDependencies {
  prepare(
    config: NormalizerPilotConfig,
    source: Uint8Array | string,
  ): NormalizerPilotPreparation;
  createCompiler(input: {
    readonly registrySource: string;
    readonly config: OpenAICompatibleIntentCompilerConfig;
    readonly environment: Readonly<Record<string, string | undefined>>;
  }): IntentProposalCompiler;
  evaluate(input: {
    readonly compiler: IntentProposalCompiler;
    readonly registry: DeclarativeIntentNormalizer;
    readonly fixture: ReturnType<typeof parseIntentEvaluationJsonl>;
    readonly split: "held-out";
    readonly attempts: number;
    readonly checkpointStore: IntentEvaluationCheckpointStore;
    readonly checkpointBindingDigest: `sha256:${string}`;
    readonly maxNewObservations?: number;
  }): Promise<RunIntentNormalizerEvaluationResult>;
  openRunStore(input: {
    readonly path: string;
    readonly partitions: readonly string[];
  }): Promise<PrivateRunStore>;
  createCheckpointStore(input: {
    readonly store: PrivateRunStore;
    readonly maximumBytes: number;
  }): IntentEvaluationCheckpointStore;
}

const defaultDependencies: NormalizerPilotDependencies = Object.freeze({
  prepare: prepareNormalizerPilot,
  createCompiler: createNormalizerPilotCompiler,
  evaluate: runIntentNormalizerEvaluation,
  openRunStore: openPrivateRunStore,
  createCheckpointStore: createNormalizerPilotCheckpointStore,
});

export function createNormalizerPilotCompiler(
  input: Parameters<NormalizerPilotDependencies["createCompiler"]>[0],
): IntentProposalCompiler {
  return new OpenAICompatibleIntentCompiler({
    registrySource: input.registrySource,
    config: input.config,
    environment: input.environment,
  });
}

export function prepareNormalizerPilot(
  config: NormalizerPilotConfig,
  source: Uint8Array | string,
): NormalizerPilotPreparation {
  const prepared = prepareClinc150Pilot(source, config.source);
  const registry = new DeclarativeIntentNormalizer(prepared.registrySource);
  const fixture = parseIntentEvaluationJsonl(prepared.fixtureSource);
  if (
    fixture.corpusDigest !== prepared.corpusDigest ||
    fixture.cases.length !== prepared.cases ||
    fixture.comparisons.length !== prepared.comparisons
  ) {
    throw new TypeError("Prepared normalizer corpus is not bound");
  }
  const plannedRequests =
    fixture.cases.length * config.evaluation.attemptsPerCase;
  if (
    !Number.isSafeInteger(plannedRequests) ||
    plannedRequests < 1 ||
    plannedRequests > config.evaluation.maxRequests
  ) {
    throw new TypeError("Normalizer pilot exceeds its request budget");
  }
  return Object.freeze({ prepared, registry, fixture, plannedRequests });
}

export async function executeNormalizerPilot(input: {
  readonly config: NormalizerPilotConfig;
  readonly source: Uint8Array | string;
  readonly runDirectory: string;
  readonly limit?: number;
  readonly environment: Readonly<Record<string, string | undefined>>;
  readonly dependencies?: Partial<NormalizerPilotDependencies>;
}): Promise<NormalizerPilotExecutionResult> {
  const limit = input.limit;
  const runDirectory = input.runDirectory;
  const source = input.source;
  const dependencyOverrides = input.dependencies;
  const environmentInput = input.environment;
  const config = parseNormalizerPilotConfig(input.config);
  const environment = snapshotCompilerEnvironment(config, environmentInput);
  assertNormalizerPilotExecutionReady(config);
  if (limit !== undefined && (!Number.isSafeInteger(limit) || limit < 0)) {
    throw new TypeError(
      "Normalizer pilot limit must be a non-negative integer",
    );
  }
  const dependencies: NormalizerPilotDependencies = {
    prepare: dependencyOverrides?.prepare ?? defaultDependencies.prepare,
    createCompiler:
      dependencyOverrides?.createCompiler ?? defaultDependencies.createCompiler,
    evaluate: dependencyOverrides?.evaluate ?? defaultDependencies.evaluate,
    openRunStore:
      dependencyOverrides?.openRunStore ?? defaultDependencies.openRunStore,
    createCheckpointStore:
      dependencyOverrides?.createCheckpointStore ??
      defaultDependencies.createCheckpointStore,
  };
  const preparation = dependencies.prepare(config, source);
  const compiler = dependencies.createCompiler({
    registrySource: preparation.prepared.registrySource,
    config: normalizerPilotCompilerConfig(config),
    environment,
  });
  const manifest = snapshotCompilerManifest(compiler.manifest);
  const pilotRunBindingDigest = normalizerPilotRunBindingDigest(
    config,
    preparation,
    manifest,
  );
  const store = await dependencies.openRunStore({
    path: runDirectory,
    partitions: ["claims", "checkpoints"],
  });
  await store.root.publishOrVerify(
    NORMALIZER_PILOT_RUN_BINDING_NAME,
    serialize({
      schema: NORMALIZER_PILOT_RUN_BINDING_SCHEMA,
      classification: NORMALIZER_PILOT_CLASSIFICATION,
      mode: "shadow",
      activeCacheQualified: false,
      activationAuthorized: false,
      pilotRunBindingDigest,
    }),
    config.evaluation.maxCheckpointBytes,
  );
  const checkpointStore = dependencies.createCheckpointStore({
    store,
    maximumBytes: config.evaluation.maxCheckpointBytes,
  });
  const evaluation = await dependencies.evaluate({
    compiler,
    registry: preparation.registry,
    fixture: preparation.fixture,
    split: "held-out",
    attempts: config.evaluation.attemptsPerCase,
    checkpointStore,
    checkpointBindingDigest: pilotRunBindingDigest,
    ...(limit === undefined ? {} : { maxNewObservations: limit }),
  });
  assertEvaluationProgress(preparation, evaluation.progress, limit);
  if (evaluation.status !== "complete") {
    await store.assertStable();
    return evaluation.status === "indeterminate"
      ? Object.freeze({
          status: "indeterminate" as const,
          progress: evaluation.progress,
          checkpointRef: evaluation.checkpointRef,
        })
      : Object.freeze({
          status: "incomplete" as const,
          progress: evaluation.progress,
        });
  }
  const artifact = createArtifact(
    config,
    preparation,
    manifest,
    pilotRunBindingDigest,
    evaluation.progress,
    evaluation.report,
  );
  await store.root.publishOrVerify(
    NORMALIZER_PILOT_ARTIFACT_NAME,
    serialize(artifact),
    config.evaluation.maxArtifactBytes,
  );
  await store.assertStable();
  return Object.freeze({
    status: "complete" as const,
    progress: evaluation.progress,
    artifact,
  });
}

function snapshotCompilerEnvironment(
  config: NormalizerPilotConfig,
  environment: Readonly<Record<string, string | undefined>>,
): Readonly<Record<string, string | undefined>> {
  if (environment === null || typeof environment !== "object") {
    throw new TypeError("Normalizer pilot environment is invalid");
  }
  const reference = config.compiler.provider.environmentRef;
  if (reference === undefined) return Object.freeze(Object.create(null));
  const descriptor = Object.getOwnPropertyDescriptor(environment, reference);
  if (
    descriptor !== undefined &&
    (!("value" in descriptor) ||
      (descriptor.value !== undefined && typeof descriptor.value !== "string"))
  ) {
    throw new TypeError("Normalizer pilot environment is invalid");
  }
  const snapshot: Record<string, string | undefined> = Object.create(
    null,
  ) as Record<string, string | undefined>;
  Object.defineProperty(snapshot, reference, {
    value: descriptor?.value as string | undefined,
    enumerable: true,
    configurable: false,
    writable: false,
  });
  return Object.freeze(snapshot);
}

export type NormalizerPilotExecutionResult =
  | Readonly<{
      status: "incomplete";
      progress: IntentEvaluationProgress;
    }>
  | Readonly<{
      status: "indeterminate";
      progress: IntentEvaluationProgress;
      checkpointRef: `sha256:${string}`;
    }>
  | Readonly<{
      status: "complete";
      progress: IntentEvaluationProgress;
      artifact: NormalizerPilotArtifact;
    }>;

export function normalizerPilotCompilerConfig(
  config: NormalizerPilotConfig,
): OpenAICompatibleIntentCompilerConfig {
  const policy = config.compiler.policy;
  return Object.freeze({
    provider: Object.freeze({
      name: config.compiler.provider.name,
      baseUrl: config.compiler.provider.baseUrl,
      model: config.compiler.provider.model,
      ...(config.compiler.provider.environmentRef === undefined
        ? {}
        : { environmentRef: config.compiler.provider.environmentRef }),
    }),
    policy: Object.freeze({
      requestTimeoutMs: policy.requestTimeoutMs,
      maxResponseBytes: policy.maxResponseBytes,
      maxOutputTokens: policy.maxOutputTokens,
      maxPromptBytes: policy.maxPromptBytes,
      ...(policy.reasoningEffort === undefined
        ? {}
        : { reasoningEffort: policy.reasoningEffort }),
    }),
  });
}

function createArtifact(
  config: NormalizerPilotConfig,
  preparation: NormalizerPilotPreparation,
  manifest: IntentProposalCompiler["manifest"],
  pilotRunBindingDigest: `sha256:${string}`,
  progress: IntentEvaluationProgress,
  evaluation: IntentEvaluationReport,
): NormalizerPilotArtifact {
  const prepared = preparation.prepared;
  if (evaluation.corpusDigest !== prepared.corpusDigest) {
    throw new TypeError("Normalizer evaluation is not bound to the corpus");
  }
  if (
    evaluation.mode !== "shadow" ||
    evaluation.activeCacheQualified !== false ||
    evaluation.split !== "held-out" ||
    evaluation.attemptsPerCase !== config.evaluation.attemptsPerCase ||
    evaluation.caseMetrics.total !== prepared.cases ||
    progress.completedObservations !== progress.totalObservations ||
    progress.remainingObservations !== 0
  ) {
    throw new TypeError("Normalizer evaluation result is not bound");
  }
  return Object.freeze({
    schema: NORMALIZER_PILOT_ARTIFACT_SCHEMA,
    classification: NORMALIZER_PILOT_CLASSIFICATION,
    statisticalQualification: false,
    economicQualification: false,
    activationAuthorized: false,
    promotionManifest: "not-produced" as const,
    qualificationStatus: "external-evidence-required" as const,
    pilotRunBindingDigest,
    checkpointLineage: Object.freeze({
      protocol: "semwitness.intent-evaluation-checkpoint/v1" as const,
      semwitnessRevision: NORMALIZER_PILOT_SEMWITNESS_REVISION,
      evaluationBindingDigest: progress.evaluationBindingDigest,
      completedObservations: progress.completedObservations,
      totalObservations: progress.totalObservations,
    }),
    source: Object.freeze({
      kind: "clinc150" as const,
      revision: config.source.revision,
      sourceDigest: prepared.sourceDigest,
      registryDigest: prepared.registryDigest,
      corpusDigest: prepared.corpusDigest,
      seed: config.source.seed,
      locale: config.source.locale,
      labels: Object.freeze([...prepared.labels]),
      cases: prepared.cases,
      comparisons: prepared.comparisons,
      inScopeCases: prepared.inScopeCases,
      outOfScopeCases: prepared.outOfScopeCases,
    }),
    compiler: Object.freeze({
      kind: "openai-compatible" as const,
      deploymentRevisionDigest: config.compiler
        .deploymentRevisionDigest as `sha256:${string}`,
      credentialKeyId: config.compiler.credentialKeyId,
      manifest: snapshotCompilerManifest(manifest),
    }),
    evaluation,
  });
}

function assertEvaluationProgress(
  preparation: NormalizerPilotPreparation,
  progress: IntentEvaluationProgress,
  limit?: number,
): void {
  const counters = [
    progress.totalObservations,
    progress.completedObservations,
    progress.resumedObservations,
    progress.observedThisRun,
    progress.remainingObservations,
  ];
  if (
    !/^sha256:[a-f0-9]{64}$/u.test(progress.evaluationBindingDigest) ||
    counters.some((value) => !Number.isSafeInteger(value) || value < 0) ||
    progress.totalObservations !== preparation.plannedRequests ||
    progress.completedObservations + progress.remainingObservations !==
      progress.totalObservations ||
    progress.resumedObservations + progress.observedThisRun !==
      progress.completedObservations ||
    (limit !== undefined && progress.observedThisRun > limit)
  ) {
    throw new TypeError("Normalizer evaluation progress is not bound");
  }
}

export function normalizerPilotRunBindingDigest(
  config: NormalizerPilotConfig,
  preparation: NormalizerPilotPreparation,
  manifestInput: IntentProposalCompiler["manifest"],
): `sha256:${string}` {
  const prepared = preparation.prepared;
  const manifest = snapshotCompilerManifest(manifestInput);
  const binding = JSON.stringify({
    schema: NORMALIZER_PILOT_RUN_BINDING_SCHEMA,
    source: {
      revision: config.source.revision,
      sourceDigest: prepared.sourceDigest,
      registryDigest: prepared.registryDigest,
      corpusDigest: prepared.corpusDigest,
      seed: config.source.seed,
      locale: config.source.locale,
      labels: prepared.labels,
      cases: prepared.cases,
      comparisons: prepared.comparisons,
    },
    compiler: {
      manifest,
      deploymentRevisionDigest: config.compiler.deploymentRevisionDigest,
      credentialKeyId: config.compiler.credentialKeyId,
    },
    evaluation: {
      evaluator: "semwitness.runIntentNormalizerEvaluation",
      checkpointProtocol: "semwitness.intent-evaluation-checkpoint/v1",
      semwitnessRevision: NORMALIZER_PILOT_SEMWITNESS_REVISION,
      split: "held-out",
      attemptsPerCase: config.evaluation.attemptsPerCase,
      plannedRequests: preparation.plannedRequests,
    },
  });
  return `sha256:${createHash("sha256").update(binding, "utf8").digest("hex")}`;
}

function serialize(value: unknown): Uint8Array {
  return new TextEncoder().encode(`${JSON.stringify(value)}\n`);
}

export function normalizerPilotExecutionReady(
  config: NormalizerPilotConfig,
): boolean {
  return (
    config.compiler.deploymentRevisionDigest !==
    EXAMPLE_DEPLOYMENT_REVISION_DIGEST
  );
}

function assertNormalizerPilotExecutionReady(
  config: NormalizerPilotConfig,
): void {
  if (!normalizerPilotExecutionReady(config)) {
    throw new TypeError(
      "Normalizer pilot deployment revision is still an example placeholder",
    );
  }
}

function snapshotCompilerManifest(
  input: IntentProposalCompiler["manifest"],
): IntentProposalCompiler["manifest"] {
  const normalizer = input.normalizer;
  const ontology = input.ontology;
  for (const value of [
    normalizer.id,
    normalizer.version,
    ontology.id,
    ontology.version,
  ]) {
    if (typeof value !== "string" || value.length < 1 || value.length > 256) {
      throw new TypeError("Normalizer compiler manifest is invalid");
    }
  }
  for (const value of [
    normalizer.artifactDigest,
    normalizer.configDigest,
    ontology.digest,
  ]) {
    if (!/^sha256:[a-f0-9]{64}$/u.test(value)) {
      throw new TypeError("Normalizer compiler manifest is invalid");
    }
  }
  return Object.freeze({
    normalizer: Object.freeze({
      id: normalizer.id,
      version: normalizer.version,
      artifactDigest: normalizer.artifactDigest,
      configDigest: normalizer.configDigest,
    }),
    ontology: Object.freeze({
      id: ontology.id,
      version: ontology.version,
      digest: ontology.digest,
    }),
  });
}
