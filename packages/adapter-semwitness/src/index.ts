import { createHmac, timingSafeEqual } from "node:crypto";
import { isProxy } from "node:util/types";

import type {
  HmacRouteInputDigest,
  HmacShadowBindingDigest,
  HmacShadowIntentKey,
  HmacShadowScopeDigest,
  HmacShadowWitnessKey,
  IntentInspector,
  IntentInspectionRequest,
} from "@intentabi/core";
import type { QualificationAuthority } from "@intentabi/qualification-core";
import type { Sha256Digest } from "semwitness";
import {
  DeclarativeIntentNormalizer,
  digestIntent,
  hmacIntentSourceDigest,
  hmacScopeDigest,
  normalizeIntentShadow,
  type IntentCompilerResult,
  type IntentNormalizerManifest,
  type IntentProposalCompiler,
} from "semwitness/intent";
import {
  assembleIntentCachePromotionEvidence,
  evaluateIntentCachePromotionEvidence,
  parseIntentCachePromotionEvidenceFixture,
  parseIntentCachePromotionEvidenceJsonl,
  type IntentCachePromotionEvidenceAssemblyInput,
  type IntentCachePromotionEvidenceFixture,
  type IntentCachePromotionWorkbenchResult,
} from "semwitness/intent/host";

import {
  projectSemWitnessQualificationResult,
  type SemWitnessQualificationAuthorityResult,
} from "./qualification.js";

export * from "./qualification.js";

/**
 * Inspector contract and SemWitness dependency pinned by this source release.
 * Cache-impact provenance additionally binds the injected compiler manifest and
 * authoritative registry configuration so a changed authority cannot reuse a
 * dataset binding silently.
 */
export const SEMWITNESS_INTENT_INSPECTOR_IMPLEMENTATION =
  "io.github.aantenore.intentabi/semwitness-intent-inspector/v2+semwitness-de1e30509fdcf92f021dc0db06f3fa6ad1d48c80" as const;

export interface SemWitnessInspectorOptions {
  readonly registrySource: string;
  /**
   * Candidate generation only. The declarative registry remains authoritative
   * for operation resolution, effect, and the complete IntentIR.
   */
  readonly compiler?: IntentProposalCompiler;
  readonly policyDigest: Sha256Digest;
  readonly hmacSecret: Uint8Array | string;
  readonly expectedScope: {
    readonly tenant: string;
    readonly authorization: string;
  };
  /** Trusted operation-id to exact application-route input bindings. */
  readonly routeBindings: Readonly<Record<string, unknown>>;
}

/**
 * Validate and deterministically serialize a complete, host-attested
 * SemWitness intent-cache promotion fixture.
 *
 * IntentABI shadow envelopes intentionally do not contain the normalization
 * witnesses, oracle facts, paired usage accounting, or cohort bindings that
 * SemWitness requires for qualification. This exporter therefore never
 * derives promotion evidence from an IntentABI envelope. The host must supply
 * the complete SemWitness fixture; SemWitness owns both validation and the
 * evaluator that consumes the returned JSONL.
 */
export function exportIntentCachePromotionEvidenceJsonl(
  source: unknown,
): string {
  const fixture = parseIntentCachePromotionEvidenceFixture(source);
  const jsonl = serializeParsedPromotionEvidence(fixture);

  // Re-parse the actual bytes so size/JSONL constraints cannot diverge from
  // the in-memory fixture parser. No IntentABI-owned fallback is permitted.
  parseIntentCachePromotionEvidenceJsonl(jsonl);
  return jsonl;
}

/**
 * Deployment facts and already-sealed case records observed by the host.
 * SemWitness owns their schema, validation, aggregation, and qualification.
 */
export type HostAttestedPromotionRunInput =
  IntentCachePromotionEvidenceAssemblyInput;

/** A content-free evidence artifact and the authoritative SemWitness result. */
export interface HostAttestedPromotionRunResult {
  readonly evidenceJsonl: string;
  readonly workbench: IntentCachePromotionWorkbenchResult;
}

/**
 * Run the narrow host-to-SemWitness promotion pipeline.
 *
 * IntentABI performs no repair, aggregation, or qualification. SemWitness
 * assembles the host-attested records, the shared serializer emits deterministic
 * JSONL, and the SemWitness evaluator parses those exact bytes before making
 * the final fail-closed decision. An unqualified result is valid evidence.
 */
export function evaluateHostAttestedPromotionRun(
  input: HostAttestedPromotionRunInput,
): HostAttestedPromotionRunResult {
  const assembled = assembleIntentCachePromotionEvidence(input);
  const evidenceJsonl = serializeParsedPromotionEvidence(assembled);
  const workbench = evaluateIntentCachePromotionEvidence(evidenceJsonl);

  return Object.freeze({ evidenceJsonl, workbench });
}

/**
 * Qualification Lab authority adapter. It preserves the exact private
 * SemWitness artifact separately and exposes only ordered, content-free case
 * bindings to the provider-neutral orchestration core.
 */
export function evaluateSemWitnessQualification(
  input: HostAttestedPromotionRunInput,
): SemWitnessQualificationAuthorityResult {
  return projectSemWitnessQualificationResult(
    evaluateHostAttestedPromotionRun(input),
  );
}

export type SemWitnessQualificationAuthority = QualificationAuthority<
  HostAttestedPromotionRunInput["attestation"],
  SemWitnessQualificationAuthorityResult["artifact"]
>;

/**
 * Structural authority port for the provider-neutral Qualification Lab core.
 * Records remain opaque until the SemWitness parser accepts or rejects them.
 */
export function createSemWitnessQualificationAuthority(): SemWitnessQualificationAuthority {
  return Object.freeze({
    evaluate: (input: {
      readonly attestation: HostAttestedPromotionRunInput["attestation"];
      readonly records: readonly unknown[];
    }) =>
      evaluateSemWitnessQualification({
        attestation: input.attestation,
        cases: input.records,
      }),
  });
}

/** Serialize only a detached fixture already accepted by SemWitness. */
function serializeParsedPromotionEvidence(
  fixture: IntentCachePromotionEvidenceFixture,
): string {
  return `${[fixture.binding, ...fixture.cases]
    .map((record) => JSON.stringify(record))
    .join("\n")}\n`;
}

/**
 * Anti-corruption layer: SemWitness remains the sole owner of IntentIR,
 * normalization witnesses, and qualification. IntentABI receives only keyed,
 * scope/route-bound correlation metadata.
 */
export class SemWitnessIntentInspector implements IntentInspector {
  readonly #compiler: IntentProposalCompiler;
  readonly #registry: DeclarativeIntentNormalizer;
  readonly #policyDigest: Sha256Digest;
  readonly #hmacSecret: Buffer;
  readonly #expectedTenant: string;
  readonly #expectedAuthorization: string;
  readonly #routeBindings: ReadonlyMap<string, string>;

  constructor(options: SemWitnessInspectorOptions) {
    const secret = Buffer.from(options.hmacSecret);
    if (secret.byteLength < 32) {
      throw new TypeError(
        "SemWitness HMAC secret must contain at least 32 bytes",
      );
    }
    this.#hmacSecret = secret;
    this.#registry = new DeclarativeIntentNormalizer(options.registrySource);
    this.#compiler = snapshotCompiler(options.compiler ?? this.#registry);
    this.#policyDigest = options.policyDigest;
    this.#expectedTenant = hmacScopeDigest(
      "tenant",
      secret,
      options.expectedScope.tenant,
    );
    this.#expectedAuthorization = hmacScopeDigest(
      "authorization",
      secret,
      options.expectedScope.authorization,
    );
    const bindings = Object.entries(options.routeBindings);
    if (bindings.length === 0) {
      throw new TypeError("At least one trusted route binding is required");
    }
    this.#routeBindings = new Map(
      bindings.map(([operationId, routeInput]) => {
        if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(operationId)) {
          throw new TypeError(
            "SemWitness route binding operation id is invalid",
          );
        }
        return [operationId, canonicalJson(routeInput)];
      }),
    );
  }

  async inspect(request: IntentInspectionRequest) {
    const routeInputCanonical = canonicalJson(request.routeInput);
    const sourceDigest = hmacIntentSourceDigest(
      this.#hmacSecret,
      request.source,
    );
    const scopeDigest = opaqueDigest(
      "shadow-scope",
      this.#hmacSecret,
      canonicalJson([
        request.scopeEpoch,
        hmacScopeDigest("tenant", this.#hmacSecret, request.scope.tenant),
        hmacScopeDigest(
          "authorization",
          this.#hmacSecret,
          request.scope.authorization,
        ),
      ]),
    ) as HmacShadowScopeDigest;
    const routeInputDigest = opaqueDigest(
      "route-input",
      this.#hmacSecret,
      canonicalJson([
        request.route.id,
        request.route.revisionDigest,
        routeInputCanonical,
      ]),
    ) as HmacRouteInputDigest;
    const bindingDigest = opaqueDigest(
      "shadow-binding",
      this.#hmacSecret,
      canonicalJson([
        SEMWITNESS_INTENT_INSPECTOR_IMPLEMENTATION,
        this.#policyDigest,
        this.#compiler.manifest,
        {
          configDigest: this.#registry.manifest.normalizer.configDigest,
          ontology: this.#registry.ontology,
          minimumConfidencePpm: this.#registry.minimumConfidencePpm,
        },
        request.route.id,
        request.route.revisionDigest,
        scopeDigest,
        routeInputDigest,
      ]),
    ) as HmacShadowBindingDigest;
    const base = {
      sourceDigest,
      scopeDigest,
      bindingDigest,
      routeInputDigest,
    };

    if (!this.#scopeMatches(request)) {
      return {
        status: "bypass" as const,
        ...base,
        reasons: ["SCOPE_MISMATCH"],
      };
    }

    let proposal: IntentCompilerResult;
    try {
      proposal = await this.#compiler.compile({
        source: request.source,
        locale: request.locale,
        ...(request.signal === undefined ? {} : { signal: request.signal }),
      });
    } catch {
      return {
        status: "bypass" as const,
        ...base,
        reasons: ["INTENT_COMPILER_FAILURE"],
      };
    }

    let result: Awaited<ReturnType<typeof normalizeIntentShadow>>;
    try {
      result = await normalizeIntentShadow({
        source: request.source,
        locale: request.locale,
        sourceDigest,
        sourceDigestSecret: this.#hmacSecret,
        policyDigest: this.#policyDigest,
        compiler: {
          manifest: this.#compiler.manifest,
          compile: () => proposal,
        },
        registry: this.#registry,
        ...(request.signal === undefined ? {} : { signal: request.signal }),
      });
    } catch {
      return {
        status: "bypass" as const,
        ...base,
        reasons: ["INTENT_COMPILER_FAILURE"],
      };
    }
    if (result.status === "bypass") {
      return {
        status: "bypass" as const,
        ...base,
        reasons: result.decision.reasons,
      };
    }
    if (result.intent.effect !== "read") {
      return {
        status: "bypass" as const,
        ...base,
        reasons: ["EFFECT_NOT_SHADOW_ELIGIBLE"],
      };
    }
    const operationId = proposedOperationId(proposal);
    if (operationId === undefined) {
      return {
        status: "bypass" as const,
        ...base,
        reasons: ["INTENT_COMPILER_FAILURE"],
      };
    }
    if (this.#routeBindings.get(operationId) !== routeInputCanonical) {
      return {
        status: "bypass" as const,
        ...base,
        reasons: ["ROUTE_INPUT_MISMATCH"],
      };
    }
    return {
      status: "eligible" as const,
      ...base,
      intentKey: opaqueDigest(
        "shadow-intent",
        this.#hmacSecret,
        canonicalJson([bindingDigest, digestIntent(result.intent)]),
      ) as HmacShadowIntentKey,
      witnessKey: opaqueDigest(
        "shadow-witness",
        this.#hmacSecret,
        canonicalJson([bindingDigest, result.witness.witnessDigest]),
      ) as HmacShadowWitnessKey,
      effect: "read" as const,
      reasons: result.witness.decision.reasons,
    };
  }

  #scopeMatches(request: IntentInspectionRequest): boolean {
    return (
      constantTimeEqual(
        hmacScopeDigest("tenant", this.#hmacSecret, request.scope.tenant),
        this.#expectedTenant,
      ) &&
      constantTimeEqual(
        hmacScopeDigest(
          "authorization",
          this.#hmacSecret,
          request.scope.authorization,
        ),
        this.#expectedAuthorization,
      )
    );
  }
}

function snapshotCompiler(
  source: IntentProposalCompiler,
): IntentProposalCompiler {
  try {
    if (source === null || typeof source !== "object" || isProxy(source)) {
      throw new Error();
    }
    const compile = dataMethod(source, "compile");
    const manifestSource = ownEnumerableDataValue(source, "manifest");
    if (compile === undefined || manifestSource === undefined)
      throw new Error();
    const manifest = snapshotCompilerManifest(manifestSource);
    return Object.freeze({
      manifest,
      compile: (request: Parameters<IntentProposalCompiler["compile"]>[0]) =>
        Reflect.apply(compile, source, [request]) as ReturnType<
          IntentProposalCompiler["compile"]
        >,
    });
  } catch {
    throw new TypeError("SemWitness intent compiler is invalid");
  }
}

function dataMethod(
  source: object,
  key: string,
): IntentProposalCompiler["compile"] | undefined {
  try {
    let current: object | null = source;
    while (current !== null) {
      if (isProxy(current)) return undefined;
      const descriptor = Object.getOwnPropertyDescriptor(current, key);
      if (descriptor !== undefined) {
        return "value" in descriptor && typeof descriptor.value === "function"
          ? (descriptor.value as IntentProposalCompiler["compile"])
          : undefined;
      }
      current = Object.getPrototypeOf(current);
    }
  } catch {
    return undefined;
  }
  return undefined;
}

function ownEnumerableDataValue(source: object, key: string): unknown {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(source, key);
    return descriptor?.enumerable === true && "value" in descriptor
      ? descriptor.value
      : undefined;
  } catch {
    return undefined;
  }
}

function snapshotCompilerManifest(source: unknown): IntentNormalizerManifest {
  const manifest = plainDataRecord(source);
  const normalizer = plainDataRecord(manifest?.normalizer);
  const ontology = plainDataRecord(manifest?.ontology);
  if (
    manifest === undefined ||
    !hasExactKeys(manifest, ["normalizer", "ontology"]) ||
    normalizer === undefined ||
    !hasExactKeys(normalizer, [
      "id",
      "version",
      "artifactDigest",
      "configDigest",
    ]) ||
    ontology === undefined ||
    !hasExactKeys(ontology, ["id", "version", "digest"]) ||
    typeof normalizer.id !== "string" ||
    !/^[a-z0-9][a-z0-9._-]{0,127}$/u.test(normalizer.id) ||
    typeof normalizer.version !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/u.test(normalizer.version) ||
    !isSha256Digest(normalizer.artifactDigest) ||
    !isSha256Digest(normalizer.configDigest) ||
    typeof ontology.id !== "string" ||
    !/^[a-z0-9][a-z0-9._-]{0,127}$/u.test(ontology.id) ||
    typeof ontology.version !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/u.test(ontology.version) ||
    !isSha256Digest(ontology.digest)
  ) {
    throw new TypeError("SemWitness intent compiler manifest is invalid");
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

function proposedOperationId(source: unknown): string | undefined {
  const proposal = plainDataRecord(source);
  return proposal?.status === "proposed" &&
    typeof proposal.operationId === "string" &&
    /^[a-z0-9][a-z0-9._-]{0,127}$/u.test(proposal.operationId)
    ? proposal.operationId
    : undefined;
}

function plainDataRecord(source: unknown): Record<string, unknown> | undefined {
  if (
    source === null ||
    typeof source !== "object" ||
    Array.isArray(source) ||
    isProxy(source)
  ) {
    return undefined;
  }
  try {
    const prototype = Object.getPrototypeOf(source);
    if (prototype !== Object.prototype && prototype !== null) return undefined;
    if (Object.getOwnPropertySymbols(source).length !== 0) return undefined;
    const result: Record<string, unknown> = Object.create(null) as Record<
      string,
      unknown
    >;
    for (const [key, descriptor] of Object.entries(
      Object.getOwnPropertyDescriptors(source),
    )) {
      if (!descriptor.enumerable || !("value" in descriptor)) return undefined;
      result[key] = descriptor.value;
    }
    return result;
  } catch {
    return undefined;
  }
}

function hasExactKeys(
  source: Readonly<Record<string, unknown>>,
  expected: readonly string[],
): boolean {
  const keys = Object.keys(source);
  return (
    keys.length === expected.length &&
    expected.every((key) => Object.hasOwn(source, key))
  );
}

function isSha256Digest(source: unknown): source is Sha256Digest {
  return typeof source === "string" && /^sha256:[a-f0-9]{64}$/u.test(source);
}

function opaqueDigest(
  domain: string,
  secret: Uint8Array,
  value: string,
): string {
  return `hmac-sha256:${domain}:${createHmac("sha256", secret)
    .update(`io.github.aantenore.intentabi/${domain}/v1\0`)
    .update(value)
    .digest("hex")}`;
}

function constantTimeEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  return (
    leftBytes.byteLength === rightBytes.byteLength &&
    timingSafeEqual(leftBytes, rightBytes)
  );
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalValue(value, new Set()));
}

function canonicalValue(value: unknown, ancestors: Set<object>): unknown {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) {
    if (ancestors.has(value)) throw new TypeError("Cyclic route input");
    ancestors.add(value);
    const result = value.map((entry, index) => {
      if (!(index in value)) throw new TypeError("Sparse route input array");
      return canonicalValue(entry, ancestors);
    });
    ancestors.delete(value);
    return result;
  }
  if (typeof value === "object") {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError("Route bindings must be strict JSON values");
    }
    if (ancestors.has(value)) throw new TypeError("Cyclic route input");
    ancestors.add(value);
    const record = value as Record<string, unknown>;
    const result = Object.fromEntries(
      Object.keys(record)
        .sort()
        .map((key) => [key, canonicalValue(record[key], ancestors)]),
    );
    ancestors.delete(value);
    return result;
  }
  throw new TypeError("Route bindings must be strict JSON values");
}
