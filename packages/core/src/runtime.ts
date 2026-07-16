import { randomUUID } from "node:crypto";

import { z } from "zod";

import type {
  AuthenticatedShadowEvidence,
  CandidateOutcome,
  CandidateProbe,
  EvidenceSink,
  HmacEvidenceDigest,
  IntentInspection,
  IntentInspector,
  KeyedHmacDigester,
  OrdinaryRoute,
  ShadowCandidateStore,
  ShadowEvidence,
  ShadowRunRequest,
  ShadowRunResult,
} from "./types.js";
import {
  SHADOW_EVIDENCE_ENVELOPE_SCHEMA,
  SHADOW_EVIDENCE_SCHEMA,
} from "./types.js";

export interface ShadowRuntimeDependencies<Input, Output> {
  readonly inspector: IntentInspector;
  readonly store: ShadowCandidateStore;
  readonly route: OrdinaryRoute<Input, Output>;
  readonly digester: KeyedHmacDigester;
  readonly timeouts?: {
    readonly inspectionMs: number;
    readonly storeMs: number;
    readonly evidenceSinkMs: number;
  };
  readonly evidenceSink?: EvidenceSink;
}

interface ShadowCandidateEvidence {
  readonly outcome: CandidateOutcome;
  readonly sourceDigest: string;
  readonly scopeDigest: string;
  readonly bindingDigest: string;
  readonly routeInputDigest: string;
  readonly intentKey?: `hmac-sha256:shadow-intent:${string}`;
  readonly witnessKey?: `hmac-sha256:shadow-witness:${string}`;
  readonly reasons: readonly string[];
}

const SAFE_REASON_CODES = [
  "INTENT_NORMALIZATION_ELIGIBLE",
  "INTENT_AMBIGUOUS",
  "INTENT_CONFIDENCE_LOW",
  "INTENT_NO_MATCH",
  "INTENT_COMPILER_FAILURE",
  "INTENT_REGISTRY_MISMATCH",
  "INTENT_MALFORMED",
  "INTENT_DOCUMENT_LIMIT",
  "INTENT_SOURCE_DIGEST_MISMATCH",
  "INTENT_DIGEST_MISMATCH",
  "INTENT_NORMALIZER_MISMATCH",
  "INTENT_POLICY_MISMATCH",
  "INTENT_WITNESS_TAMPERED",
  "SCOPE_MISMATCH",
  "EFFECT_NOT_SHADOW_ELIGIBLE",
  "ROUTE_INPUT_MISMATCH",
] as const;

const reasonSchema = z.enum(SAFE_REASON_CODES);
const sourceDigestSchema = z
  .string()
  .regex(/^hmac-sha256:intent-source:[a-f0-9]{64}$/u);
const scopeDigestSchema = z
  .string()
  .regex(/^hmac-sha256:shadow-scope:[a-f0-9]{64}$/u);
const bindingDigestSchema = z
  .string()
  .regex(/^hmac-sha256:shadow-binding:[a-f0-9]{64}$/u);
const routeInputDigestSchema = z
  .string()
  .regex(/^hmac-sha256:route-input:[a-f0-9]{64}$/u);
const inspectionBindingSchema = {
  sourceDigest: sourceDigestSchema,
  scopeDigest: scopeDigestSchema,
  bindingDigest: bindingDigestSchema,
  routeInputDigest: routeInputDigestSchema,
};
const inspectionSchema = z.discriminatedUnion("status", [
  z
    .object({
      status: z.literal("eligible"),
      ...inspectionBindingSchema,
      intentKey: z.string().regex(/^hmac-sha256:shadow-intent:[a-f0-9]{64}$/u),
      witnessKey: z
        .string()
        .regex(/^hmac-sha256:shadow-witness:[a-f0-9]{64}$/u),
      effect: z.literal("read"),
      reasons: z.array(reasonSchema).max(16),
    })
    .strict(),
  z
    .object({
      status: z.literal("bypass"),
      ...inspectionBindingSchema,
      reasons: z.array(reasonSchema).min(1).max(16),
    })
    .strict(),
]);
const candidateProbeSchema = z.discriminatedUnion("found", [
  z.object({ found: z.literal(false) }).strict(),
  z.object({ found: z.literal(true) }).strict(),
]);

/**
 * Runs the ordinary route and shadow inspection concurrently. Candidate content
 * is structurally absent, and only the ordinary route can produce output.
 */
export class ShadowRuntime<Input, Output> {
  readonly #inspector: IntentInspector;
  readonly #store: ShadowCandidateStore;
  readonly #route: OrdinaryRoute<Input, Output>;
  readonly #digester: KeyedHmacDigester;
  readonly #evidenceSink: EvidenceSink | undefined;
  readonly #timeouts: {
    readonly inspectionMs: number;
    readonly storeMs: number;
    readonly evidenceSinkMs: number;
  };

  constructor(dependencies: ShadowRuntimeDependencies<Input, Output>) {
    this.#inspector = dependencies.inspector;
    this.#store = dependencies.store;
    this.#route = validateRoute(dependencies.route);
    this.#digester = dependencies.digester;
    this.#evidenceSink = dependencies.evidenceSink;
    this.#timeouts = validateTimeouts(
      dependencies.timeouts ?? {
        inspectionMs: 1_000,
        storeMs: 500,
        evidenceSinkMs: 250,
      },
    );
  }

  async run(
    request: ShadowRunRequest<Input>,
  ): Promise<ShadowRunResult<Output>> {
    const eventId = randomUUID();
    const routeInputSnapshots = snapshotRouteInput(request.routeInput);
    const executionPromise = settle(
      Promise.resolve().then(() =>
        this.#route.execute(routeInputSnapshots.executionInput),
      ),
    );
    const shadowPromise =
      routeInputSnapshots.shadowInput === null
        ? Promise.resolve(
            unavailableShadow("normalizer-fault", "route-input-unavailable", [
              "NORMALIZER_UNAVAILABLE",
            ]),
          )
        : this.#runShadow(
            {
              ...request,
              scope: Object.freeze({ ...request.scope }),
              routeInput: routeInputSnapshots.shadowInput,
            },
            eventId,
          );
    const [execution, shadow] = await Promise.all([
      executionPromise,
      shadowPromise,
    ]);

    const executionDigest =
      execution.status === "fulfilled"
        ? safeDigest(
            this.#digester,
            execution.value,
            "unavailable:output-digest",
          )
        : safeDigest(
            this.#digester,
            errorShape(execution.reason),
            "unavailable:error-digest",
          );
    const routeDigest = safeDigest(
      this.#digester,
      { id: this.#route.id, revisionDigest: this.#route.revisionDigest },
      "unavailable:route-digest",
    );
    const evidence: ShadowEvidence = Object.freeze({
      schema: SHADOW_EVIDENCE_SCHEMA,
      mode: "shadow",
      routeDigest,
      sourceDigest: shadow.sourceDigest,
      scopeDigest: shadow.scopeDigest,
      bindingDigest: shadow.bindingDigest,
      routeInputDigest: shadow.routeInputDigest,
      execution: Object.freeze({
        status:
          execution.status === "fulfilled" ? "succeeded" : ("failed" as const),
        outputDigest: executionDigest,
      }),
      candidate: Object.freeze({
        outcome: shadow.outcome,
        applied: false as const,
        ...(shadow.intentKey === undefined
          ? {}
          : { intentKey: shadow.intentKey }),
        ...(shadow.witnessKey === undefined
          ? {}
          : { witnessKey: shadow.witnessKey }),
        reasons: Object.freeze([...shadow.reasons]),
      }),
    });

    const envelope = createEnvelope(eventId, evidence, this.#digester);
    const evidenceDelivery = await this.#emitEvidence(envelope);
    if (execution.status === "rejected") throw execution.reason;
    return {
      output: execution.value,
      evidence,
      envelope,
      evidenceDigest: envelope?.mac ?? null,
      evidenceDelivery,
    };
  }

  async #runShadow(
    request: ShadowRunRequest<Input>,
    observationId: string,
  ): Promise<ShadowCandidateEvidence> {
    const controller = new AbortController();
    let inspection: IntentInspection;
    try {
      const rawInspection: unknown = await withTimeout(
        this.#inspector.inspect({
          source: request.source,
          locale: request.locale,
          scope: request.scope,
          scopeEpoch: request.scopeEpoch,
          route: {
            id: this.#route.id,
            revisionDigest: this.#route.revisionDigest,
          },
          routeInput: request.routeInput,
          signal: controller.signal,
        }),
        this.#timeouts.inspectionMs,
        controller,
      );
      inspection = inspectionSchema.parse(rawInspection) as IntentInspection;
    } catch (error) {
      if (error instanceof ShadowTimeoutError) {
        return unavailableShadow("shadow-timeout", "inspection-timeout", [
          "INSPECTION_TIMEOUT",
        ]);
      }
      return unavailableShadow("normalizer-fault", "normalizer-fault", [
        "NORMALIZER_UNAVAILABLE",
      ]);
    }
    if (inspection.status === "bypass") {
      return {
        outcome: "bypass",
        sourceDigest: inspection.sourceDigest,
        scopeDigest: inspection.scopeDigest,
        bindingDigest: inspection.bindingDigest,
        routeInputDigest: inspection.routeInputDigest,
        reasons: Object.freeze([...inspection.reasons]),
      };
    }

    try {
      const probeController = new AbortController();
      const rawProbe: unknown = await withTimeout(
        this.#store.probe(inspection.intentKey, probeController.signal),
        this.#timeouts.storeMs,
        probeController,
      );
      const parsedProbe = candidateProbeSchema.parse(rawProbe);
      const probe: CandidateProbe = parsedProbe.found
        ? Object.freeze({ found: true as const })
        : Object.freeze({ found: false as const });
      const observeController = new AbortController();
      await withTimeout(
        this.#store.observe(
          Object.freeze({
            observationId,
            sourceDigest: inspection.sourceDigest,
            intentKey: inspection.intentKey,
            witnessKey: inspection.witnessKey,
            scopeDigest: inspection.scopeDigest,
            bindingDigest: inspection.bindingDigest,
            routeInputDigest: inspection.routeInputDigest,
            probe,
          }),
          observeController.signal,
        ),
        this.#timeouts.storeMs,
        observeController,
      );
      return {
        outcome: probe.found
          ? "unverified-candidate-observed"
          : "miss-observed",
        sourceDigest: inspection.sourceDigest,
        scopeDigest: inspection.scopeDigest,
        bindingDigest: inspection.bindingDigest,
        routeInputDigest: inspection.routeInputDigest,
        intentKey: inspection.intentKey,
        witnessKey: inspection.witnessKey,
        reasons: Object.freeze([...inspection.reasons]),
      };
    } catch (error) {
      if (error instanceof ShadowTimeoutError) {
        return {
          outcome: "shadow-timeout",
          sourceDigest: inspection.sourceDigest,
          scopeDigest: inspection.scopeDigest,
          bindingDigest: inspection.bindingDigest,
          routeInputDigest: inspection.routeInputDigest,
          intentKey: inspection.intentKey,
          witnessKey: inspection.witnessKey,
          reasons: ["STORE_TIMEOUT"],
        };
      }
      return {
        outcome: "store-fault",
        sourceDigest: inspection.sourceDigest,
        scopeDigest: inspection.scopeDigest,
        bindingDigest: inspection.bindingDigest,
        routeInputDigest: inspection.routeInputDigest,
        intentKey: inspection.intentKey,
        witnessKey: inspection.witnessKey,
        reasons: ["STORE_UNAVAILABLE"],
      };
    }
  }

  async #emitEvidence(
    envelope: AuthenticatedShadowEvidence | null,
  ): Promise<"emitted" | "unacknowledged" | "dropped"> {
    if (this.#evidenceSink === undefined || envelope === null) return "dropped";
    const controller = new AbortController();
    try {
      await withTimeout(
        this.#evidenceSink.emit(envelope, controller.signal),
        this.#timeouts.evidenceSinkMs,
        controller,
      );
      return "emitted";
    } catch (error) {
      return error instanceof ShadowTimeoutError ? "unacknowledged" : "dropped";
    }
  }
}

function createEnvelope(
  eventId: string,
  evidence: ShadowEvidence,
  digester: KeyedHmacDigester,
): AuthenticatedShadowEvidence | null {
  const unsigned = Object.freeze({
    schema: SHADOW_EVIDENCE_ENVELOPE_SCHEMA,
    eventId,
    keyId: digester.keyId,
    evidence,
  });
  const mac = safeDigest(digester, unsigned, null);
  return mac === null ? null : Object.freeze({ ...unsigned, mac });
}

function unavailableShadow(
  outcome: "normalizer-fault" | "shadow-timeout",
  suffix: string,
  reasons: readonly string[],
): ShadowCandidateEvidence {
  return {
    outcome,
    sourceDigest: `unavailable:${suffix}`,
    scopeDigest: `unavailable:${suffix}`,
    bindingDigest: `unavailable:${suffix}`,
    routeInputDigest: `unavailable:${suffix}`,
    reasons,
  };
}

async function settle<Value>(
  promise: Promise<Value>,
): Promise<PromiseSettledResult<Value>> {
  try {
    return { status: "fulfilled", value: await promise };
  } catch (reason) {
    return { status: "rejected", reason };
  }
}

function errorShape(error: unknown): { readonly name: string } {
  return { name: error instanceof Error ? error.name : "UnknownError" };
}

function safeDigest<Fallback extends string | null>(
  digester: KeyedHmacDigester,
  value: unknown,
  fallback: Fallback,
): HmacEvidenceDigest | Fallback {
  try {
    const digest = digester.digestJson(value);
    return /^hmac-sha256:evidence:[a-f0-9]{64}$/u.test(digest)
      ? digest
      : fallback;
  } catch {
    return fallback;
  }
}

function validateRoute<Input, Output>(
  route: OrdinaryRoute<Input, Output>,
): OrdinaryRoute<Input, Output> {
  if (
    typeof route.id !== "string" ||
    route.id.length < 1 ||
    route.id.length > 256 ||
    !/^sha256:[a-f0-9]{64}$/u.test(route.revisionDigest)
  ) {
    throw new TypeError("Ordinary route binding is invalid");
  }
  return Object.freeze({
    id: route.id,
    revisionDigest: route.revisionDigest,
    execute: route.execute.bind(route),
  });
}

function snapshotRouteInput<Input>(input: Input): {
  readonly executionInput: Input;
  readonly shadowInput: Input | null;
} {
  try {
    return {
      executionInput: strictJsonSnapshot(input) as Input,
      shadowInput: strictJsonSnapshot(input) as Input,
    };
  } catch {
    return { executionInput: input, shadowInput: null };
  }
}

function strictJsonSnapshot(value: unknown): unknown {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) {
    const result = value.map((entry, index) => {
      if (!(index in value)) throw new TypeError("Sparse route input array");
      return strictJsonSnapshot(entry);
    });
    return Object.freeze(result);
  }
  if (typeof value === "object") {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError("Route input must be strict JSON");
    }
    const record = value as Record<string, unknown>;
    return Object.freeze(
      Object.fromEntries(
        Object.keys(record).map((key) => [
          key,
          strictJsonSnapshot(record[key]),
        ]),
      ),
    );
  }
  throw new TypeError("Route input must be strict JSON");
}

function validateTimeouts(timeouts: {
  readonly inspectionMs: number;
  readonly storeMs: number;
  readonly evidenceSinkMs: number;
}) {
  for (const value of [
    timeouts.inspectionMs,
    timeouts.storeMs,
    timeouts.evidenceSinkMs,
  ]) {
    if (!Number.isInteger(value) || value < 1 || value > 30_000) {
      throw new TypeError(
        "Shadow timeouts must be integers from 1 to 30000 ms",
      );
    }
  }
  return Object.freeze({ ...timeouts });
}

class ShadowTimeoutError extends Error {
  constructor() {
    super("Shadow operation exceeded its deadline");
    this.name = "ShadowTimeoutError";
  }
}

async function withTimeout<Value>(
  promise: Promise<Value>,
  timeoutMs: number,
  controller: AbortController,
): Promise<Value> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      controller.abort(new ShadowTimeoutError());
      reject(new ShadowTimeoutError());
    }, timeoutMs);
    timer.unref?.();
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}
