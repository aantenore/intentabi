import { createHmac, timingSafeEqual } from "node:crypto";

import type {
  HmacRouteInputDigest,
  HmacShadowBindingDigest,
  HmacShadowIntentKey,
  HmacShadowScopeDigest,
  HmacShadowWitnessKey,
  IntentInspector,
  IntentInspectionRequest,
} from "@intentabi/core";
import type { Sha256Digest } from "semwitness";
import {
  DeclarativeIntentNormalizer,
  digestIntent,
  hmacIntentSourceDigest,
  hmacScopeDigest,
  normalizeIntentShadow,
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

export interface SemWitnessInspectorOptions {
  readonly registrySource: string;
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
  readonly #normalizer: DeclarativeIntentNormalizer;
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
    this.#normalizer = new DeclarativeIntentNormalizer(options.registrySource);
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
        this.#policyDigest,
        this.#normalizer.manifest.normalizer.id,
        this.#normalizer.manifest.normalizer.version,
        this.#normalizer.manifest.normalizer.artifactDigest,
        this.#normalizer.manifest.normalizer.configDigest,
        this.#normalizer.manifest.ontology.digest,
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

    const proposal = await this.#normalizer.compile({
      source: request.source,
      locale: request.locale,
      ...(request.signal === undefined ? {} : { signal: request.signal }),
    });
    const result = await normalizeIntentShadow({
      source: request.source,
      locale: request.locale,
      sourceDigest,
      sourceDigestSecret: this.#hmacSecret,
      policyDigest: this.#policyDigest,
      compiler: {
        manifest: this.#normalizer.manifest,
        compile: () => proposal,
      },
      registry: this.#normalizer,
      ...(request.signal === undefined ? {} : { signal: request.signal }),
    });
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
    if (
      proposal.status !== "proposed" ||
      this.#routeBindings.get(proposal.operationId) !== routeInputCanonical
    ) {
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
