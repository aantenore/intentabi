import { createHash } from "node:crypto";

import {
  reservePrivateArtifact,
  type PrivateArtifactReservation,
} from "@intentabi/cli-io";
import {
  DeclarativeIntentNormalizer,
  evaluateIntentNormalizer,
  parseIntentEvaluationJsonl,
  type IntentEvaluationReport,
  type IntentProposalCompiler,
} from "semwitness/intent";
import {
  OpenAICompatibleIntentCompiler,
  type OpenAICompatibleIntentCompilerConfig,
} from "semwitness/intent/openai-compatible";

import { prepareClinc150Pilot } from "./clinc150.js";
import {
  EXAMPLE_DEPLOYMENT_REVISION_DIGEST,
  NORMALIZER_PILOT_CLASSIFICATION,
  type NormalizerPilotConfig,
} from "./config.js";

export const NORMALIZER_PILOT_ARTIFACT_SCHEMA =
  "io.github.aantenore.intentabi/normalizer-pilot-artifact/v1alpha1" as const;
export const NORMALIZER_PILOT_SEMWITNESS_REVISION =
  "de1e30509fdcf92f021dc0db06f3fa6ad1d48c80" as const;

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
  }): Promise<IntentEvaluationReport>;
  reserveArtifact(
    path: string,
    maximumBytes: number,
  ): Promise<PrivateArtifactReservation>;
}

const defaultDependencies: NormalizerPilotDependencies = Object.freeze({
  prepare: prepareNormalizerPilot,
  createCompiler: createNormalizerPilotCompiler,
  evaluate: evaluateIntentNormalizer,
  reserveArtifact: reservePrivateArtifact,
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
  readonly outputPath: string;
  readonly environment: Readonly<Record<string, string | undefined>>;
  readonly dependencies?: Partial<NormalizerPilotDependencies>;
}): Promise<NormalizerPilotArtifact> {
  assertNormalizerPilotExecutionReady(input.config);
  const dependencies: NormalizerPilotDependencies = {
    prepare: input.dependencies?.prepare ?? defaultDependencies.prepare,
    createCompiler:
      input.dependencies?.createCompiler ?? defaultDependencies.createCompiler,
    evaluate: input.dependencies?.evaluate ?? defaultDependencies.evaluate,
    reserveArtifact:
      input.dependencies?.reserveArtifact ??
      defaultDependencies.reserveArtifact,
  };
  const preparation = dependencies.prepare(input.config, input.source);
  const reservation = await dependencies.reserveArtifact(
    input.outputPath,
    input.config.evaluation.maxArtifactBytes,
  );
  try {
    const compiler = dependencies.createCompiler({
      registrySource: preparation.prepared.registrySource,
      config: compilerConfig(input.config),
      environment: input.environment,
    });
    const evaluation = await dependencies.evaluate({
      compiler,
      registry: preparation.registry,
      fixture: preparation.fixture,
      split: "held-out",
      attempts: input.config.evaluation.attemptsPerCase,
    });
    const artifact = createArtifact(
      input.config,
      preparation,
      compiler,
      evaluation,
    );
    await reservation.commit(
      new TextEncoder().encode(`${JSON.stringify(artifact)}\n`),
    );
    return artifact;
  } catch (error) {
    await reservation.abort();
    throw error;
  }
}

function compilerConfig(
  config: NormalizerPilotConfig,
): OpenAICompatibleIntentCompilerConfig {
  return Object.freeze({
    provider: Object.freeze({
      name: config.compiler.provider.name,
      baseUrl: config.compiler.provider.baseUrl,
      model: config.compiler.provider.model,
      ...(config.compiler.provider.environmentRef === undefined
        ? {}
        : { environmentRef: config.compiler.provider.environmentRef }),
    }),
    policy: Object.freeze({ ...config.compiler.policy }),
  });
}

function createArtifact(
  config: NormalizerPilotConfig,
  preparation: NormalizerPilotPreparation,
  compiler: IntentProposalCompiler,
  evaluation: IntentEvaluationReport,
): NormalizerPilotArtifact {
  const prepared = preparation.prepared;
  if (evaluation.corpusDigest !== prepared.corpusDigest) {
    throw new TypeError("Normalizer evaluation is not bound to the corpus");
  }
  const manifest = snapshotCompilerManifest(compiler.manifest);
  const pilotRunBindingDigest = normalizerPilotRunBindingDigest(
    config,
    preparation,
    manifest,
  );
  return Object.freeze({
    schema: NORMALIZER_PILOT_ARTIFACT_SCHEMA,
    classification: NORMALIZER_PILOT_CLASSIFICATION,
    statisticalQualification: false,
    economicQualification: false,
    activationAuthorized: false,
    promotionManifest: "not-produced" as const,
    qualificationStatus: "external-evidence-required" as const,
    pilotRunBindingDigest,
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
      manifest,
    }),
    evaluation,
  });
}

export function normalizerPilotRunBindingDigest(
  config: NormalizerPilotConfig,
  preparation: NormalizerPilotPreparation,
  manifestInput: IntentProposalCompiler["manifest"],
): `sha256:${string}` {
  const prepared = preparation.prepared;
  const manifest = snapshotCompilerManifest(manifestInput);
  const binding = JSON.stringify({
    schema: "io.github.aantenore.intentabi/normalizer-pilot-run-binding/v1",
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
      evaluator: "semwitness.evaluateIntentNormalizer",
      semwitnessRevision: NORMALIZER_PILOT_SEMWITNESS_REVISION,
      split: "held-out",
      attemptsPerCase: config.evaluation.attemptsPerCase,
      plannedRequests: preparation.plannedRequests,
    },
  });
  return `sha256:${createHash("sha256").update(binding, "utf8").digest("hex")}`;
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
