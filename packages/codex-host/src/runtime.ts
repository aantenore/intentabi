import { randomUUID } from "node:crypto";

import type {
  HmacEvidenceDigest,
  KeyedHmacDigester,
  Sha256Digest,
} from "@intentabi/core";
import {
  isHostReasonCode,
  isSha256Digest,
  type HostReasonCode,
} from "semwitness/host";

import {
  CODEX_SHADOW_EVIDENCE_ENVELOPE_SCHEMA,
  CODEX_SHADOW_EVIDENCE_SCHEMA,
  type AuthenticatedCodexShadowEvidence,
  type CodexExecutionBinding,
  type CodexPreparationBinding,
  type CodexPreparationReason,
  type CodexShadowEvidence,
  type CodexShadowHostOptions,
  type CodexShadowRequest,
  type CodexShadowResult,
  type UnavailableEvidenceDigest,
} from "./types.js";

const HMAC_PATTERN = /^hmac-sha256:evidence:[a-f0-9]{64}$/u;
const IDENTIFIER_PATTERN = /^[a-z0-9][a-z0-9._-]{0,127}$/u;
const ADAPTER_PATTERN = /^[A-Za-z0-9@][A-Za-z0-9@/._+-]{0,255}$/u;
const CODEC_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,127}$/u;
const VERSION_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$/u;
const KEY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const MEDIA_TYPE_PATTERN =
  /^[a-z0-9][a-z0-9!#$&^_.+-]{0,63}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,63}(?:; ?[a-z0-9][a-z0-9._-]{0,31}=[a-z0-9][a-z0-9._-]{0,63}){0,8}$/u;

type PreparationObservation = CodexShadowEvidence["preparation"];
type DigestJson = (value: unknown) => HmacEvidenceDigest;

interface ParsedPreparation {
  readonly content: string;
  readonly selectedCodec: string;
  readonly reasons: readonly HostReasonCode[];
  readonly promotionDigest?: Sha256Digest;
  readonly proofPresent: boolean;
  readonly applied: boolean;
}

interface CapturedHostOptions<Input, Options, Output> {
  readonly prepare: CodexShadowHostOptions<
    Input,
    Options,
    Output
  >["preparer"]["prepare"];
  readonly prepareThis: CodexShadowHostOptions<
    Input,
    Options,
    Output
  >["preparer"];
  readonly runExact: CodexShadowHostOptions<
    Input,
    Options,
    Output
  >["transport"]["runExact"];
  readonly transportThis: CodexShadowHostOptions<
    Input,
    Options,
    Output
  >["transport"];
  readonly emit: CodexShadowHostOptions<
    Input,
    Options,
    Output
  >["evidenceSink"]["emit"];
  readonly sinkThis: CodexShadowHostOptions<
    Input,
    Options,
    Output
  >["evidenceSink"];
  readonly digestJson: DigestJson;
  readonly digestThis: KeyedHmacDigester;
  readonly keyId: string;
  readonly executionBinding: CodexExecutionBinding;
  readonly preparationBinding: CodexPreparationBinding;
  readonly limits: CodexShadowHostOptions<Input, Options, Output>["limits"];
}

export interface CodexShadowBindingDerivation {
  readonly digester: KeyedHmacDigester;
  readonly executionBinding: CodexExecutionBinding;
  readonly preparationBinding: CodexPreparationBinding;
}

/** Derive the trusted expected binding before accepting any evidence event. */
export function deriveCodexShadowBindingDigest(
  input: CodexShadowBindingDerivation,
): HmacEvidenceDigest | null {
  try {
    const execution = deepFreeze(
      snapshotExecutionBinding(input.executionBinding),
    );
    const preparation = Object.freeze(
      snapshotPreparationBinding(input.preparationBinding),
    );
    const digestJson = input.digester.digestJson.bind(input.digester);
    return digestBinding(digestJson, { execution, preparation });
  } catch {
    return null;
  }
}

export class CodexShadowHost<Input, Options, Output> {
  readonly #prepare: CodexShadowHostOptions<
    Input,
    Options,
    Output
  >["preparer"]["prepare"];
  readonly #runExact: CodexShadowHostOptions<
    Input,
    Options,
    Output
  >["transport"]["runExact"];
  readonly #emitEvidence: CodexShadowHostOptions<
    Input,
    Options,
    Output
  >["evidenceSink"]["emit"];
  readonly #digestJson: DigestJson;
  readonly #keyId: string;
  readonly #executionBinding: CodexExecutionBinding;
  readonly #preparationBinding: CodexPreparationBinding;
  readonly #limits: CodexShadowHostOptions<Input, Options, Output>["limits"];
  readonly #digestContext: Readonly<{
    execution: CodexExecutionBinding;
    preparation: CodexPreparationBinding;
  }>;
  readonly #bindingDigest: HmacEvidenceDigest | "unavailable:binding-digest";

  constructor(options: CodexShadowHostOptions<Input, Options, Output>) {
    const captured = captureHostOptions(options);
    validateOptions(captured);
    this.#executionBinding = captured.executionBinding;
    this.#preparationBinding = captured.preparationBinding;
    this.#limits = captured.limits;
    this.#prepare = captured.prepare.bind(captured.prepareThis);
    this.#runExact = captured.runExact.bind(captured.transportThis);
    this.#emitEvidence = captured.emit.bind(captured.sinkThis);
    this.#digestJson = captured.digestJson.bind(captured.digestThis);
    this.#keyId = captured.keyId;
    this.#digestContext = deepFreeze({
      execution: this.#executionBinding,
      preparation: this.#preparationBinding,
    });
    this.#bindingDigest =
      digestBinding(this.#digestJson, this.#digestContext) ??
      "unavailable:binding-digest";
  }

  async run(
    request: CodexShadowRequest<Input, Options>,
  ): Promise<CodexShadowResult<Output>> {
    const input = request.input;
    const textInput = typeof input === "string" ? input : undefined;
    const options = request.options;
    const observationController = new AbortController();
    const preparation = this.#observePreparation(
      request.id,
      textInput,
      observationController.signal,
    ).catch(() => observation("preparer-fault", "PREPARER_FAULT"));

    let output: Output;
    try {
      output =
        options === undefined
          ? await this.#runExact(input)
          : await this.#runExact(input, options);
    } catch (error) {
      // No shadow operation, sink, or digester may delay or replace a Codex
      // transport error. The settled preparation has its own rejection handler.
      observationController.abort();
      throw error;
    }

    try {
      const observed = await preparation;
      const evidence = this.#evidence(
        textInput,
        options === undefined
          ? "unavailable:not-provided"
          : "unavailable:unbound-options",
        observed,
      );
      const envelope = this.#envelope(evidence);
      const delivery = await this.#emit(envelope);
      return {
        output,
        evidence,
        // Return the stable event even when acknowledgement is uncertain so a
        // caller can retry idempotently with the same eventId.
        envelope,
        evidenceDelivery: delivery,
      };
    } catch {
      // This last-resort constant artifact contains no caller-controlled value.
      // It keeps the successfully returned SDK output authoritative.
      return {
        output,
        evidence: emergencyEvidence(
          textInput === undefined ? "non-text" : "text",
        ),
        envelope: null,
        evidenceDelivery: "dropped",
      };
    }
  }

  async #observePreparation(
    requestId: string,
    textInput: string | undefined,
    signal: AbortSignal,
  ): Promise<PreparationObservation> {
    if (textInput === undefined) {
      return observation("bypass", "NON_TEXT_INPUT");
    }
    if (typeof requestId !== "string" || !IDENTIFIER_PATTERN.test(requestId)) {
      return observation("bypass", "REQUEST_ID_INVALID");
    }
    if (Buffer.byteLength(textInput) > this.#limits.maximumInputBytes) {
      return observation("bypass", "INPUT_LIMIT_EXCEEDED");
    }

    const binding = this.#preparationBinding;
    const pending = Promise.resolve().then(() =>
      this.#prepare({
        id: requestId,
        role: binding.role,
        kind: binding.kind,
        trust: binding.trust,
        mediaType: binding.mediaType,
        equivalence: binding.equivalence,
        deploymentScopeDigest: binding.deploymentScopeDigest,
        content: textInput,
      }),
    );
    const settled = await settleWithTimeout(
      pending,
      this.#limits.preparationMs,
      undefined,
      signal,
    );
    if (settled.status === "timeout") {
      return observation("preparer-timeout", "PREPARATION_TIMEOUT_UNCANCELLED");
    }
    if (settled.status === "rejected" || settled.status === "cancelled") {
      return observation("preparer-fault", "PREPARER_FAULT");
    }
    return this.#validatedPreparation(textInput, settled.value);
  }

  #validatedPreparation(
    original: string,
    value: unknown,
  ): PreparationObservation {
    try {
      const parsed = snapshotPreparationResult(
        value,
        original,
        this.#limits.maximumCandidateBytes,
        this.#preparationBinding.deploymentScopeDigest,
      );
      if (parsed === undefined) {
        return observation(
          "invalid-preparer-result",
          "PREPARER_RESULT_INVALID",
        );
      }
      const metadata = {
        selectedCodecDigest: this.#digest(
          "io.github.aantenore.intentabi/semwitness-codec/v1",
          parsed.selectedCodec,
          "unavailable:codec-digest",
        ),
        reasonSetDigest: this.#digest(
          "io.github.aantenore.intentabi/semwitness-reason-set/v1",
          parsed.reasons,
          "unavailable:reason-set-digest",
        ),
        ...(parsed.promotionDigest === undefined
          ? {}
          : {
              promotionBindingDigest: this.#digest(
                "io.github.aantenore.intentabi/semwitness-promotion-binding/v1",
                parsed.promotionDigest,
                "unavailable:promotion-binding-digest",
              ),
            }),
        proof: parsed.proofPresent
          ? ("present-unverified" as const)
          : ("not-observed" as const),
      };
      if (!parsed.applied || parsed.content === original) {
        return deepFreeze({
          outcome: "identity",
          reason: "IDENTITY_ATTESTED",
          ...metadata,
        });
      }
      return deepFreeze({
        outcome: "candidate-observed",
        reason: "CANDIDATE_ATTESTED",
        candidateDigest: this.#digest(
          "io.github.aantenore.intentabi/codex-candidate/v1",
          parsed.content,
          "unavailable:candidate-digest",
        ),
        ...metadata,
      });
    } catch {
      return observation("invalid-preparer-result", "PREPARER_RESULT_INVALID");
    }
  }

  #evidence(
    textInput: string | undefined,
    optionsDigest: CodexShadowEvidence["optionsDigest"],
    preparation: PreparationObservation,
  ): CodexShadowEvidence {
    return deepFreeze({
      schema: CODEX_SHADOW_EVIDENCE_SCHEMA,
      mode: "shadow",
      submitted: "original",
      inputKind: textInput === undefined ? "non-text" : "text",
      bindingDigest: this.#bindingDigest,
      originalDigest:
        textInput === undefined
          ? "unavailable:non-text-input"
          : this.#digest(
              "io.github.aantenore.intentabi/codex-original/v1",
              textInput,
              "unavailable:original-digest",
            ),
      optionsDigest,
      execution: {
        status: "succeeded",
        outputDigest: "unavailable:opaque-output",
      },
      preparation,
    });
  }

  #envelope(
    evidence: CodexShadowEvidence,
  ): AuthenticatedCodexShadowEvidence | null {
    if (
      evidence.bindingDigest === "unavailable:binding-digest" ||
      typeof this.#keyId !== "string" ||
      !KEY_ID_PATTERN.test(this.#keyId)
    )
      return null;
    const unsigned = {
      schema: CODEX_SHADOW_EVIDENCE_ENVELOPE_SCHEMA,
      eventId: randomUUID(),
      keyId: this.#keyId,
      evidence,
    } as const;
    const mac = safeDigest(
      this.#digestJson,
      {
        domain: "io.github.aantenore.intentabi/codex-evidence-envelope/v1",
        ...unsigned,
      },
      null,
    );
    return mac === null ? null : deepFreeze({ ...unsigned, mac });
  }

  async #emit(
    envelope: AuthenticatedCodexShadowEvidence | null,
  ): Promise<"emitted" | "unacknowledged" | "dropped"> {
    if (envelope === null) return "dropped";
    try {
      const controller = new AbortController();
      const pending = Promise.resolve().then(() =>
        this.#emitEvidence(envelope, controller.signal),
      );
      const settled = await settleWithTimeout(
        pending,
        this.#limits.evidenceSinkMs,
        controller,
      );
      if (settled.status === "fulfilled") return "emitted";
      return "unacknowledged";
    } catch {
      return "unacknowledged";
    }
  }

  #digest<Fallback extends UnavailableEvidenceDigest>(
    domain: string,
    value: unknown,
    fallback: Fallback,
  ): HmacEvidenceDigest | Fallback {
    return safeDigest(
      this.#digestJson,
      { domain, binding: this.#digestContext, value },
      fallback,
    );
  }
}

function captureHostOptions<Input, Options, Output>(
  options: CodexShadowHostOptions<Input, Options, Output>,
): CapturedHostOptions<Input, Options, Output> {
  const optionsRecord = asObject(options, "host options");
  const preparer = asObject(
    ownEnumerableDataValue(optionsRecord, "preparer"),
    "preparer",
  ) as CodexShadowHostOptions<Input, Options, Output>["preparer"];
  const transport = asObject(
    ownEnumerableDataValue(optionsRecord, "transport"),
    "transport",
  ) as CodexShadowHostOptions<Input, Options, Output>["transport"];
  const digester = asObject(
    ownEnumerableDataValue(optionsRecord, "digester"),
    "digester",
  ) as unknown as KeyedHmacDigester;
  const evidenceSink = asObject(
    ownEnumerableDataValue(optionsRecord, "evidenceSink"),
    "evidence sink",
  ) as CodexShadowHostOptions<Input, Options, Output>["evidenceSink"];
  const executionBinding = deepFreeze(
    snapshotExecutionBinding(
      ownEnumerableDataValue(
        transport as unknown as object,
        "executionBinding",
      ) as CodexExecutionBinding,
    ),
  );
  const preparationBinding = Object.freeze(
    snapshotPreparationBinding(
      ownEnumerableDataValue(optionsRecord, "preparationBinding") as
        CodexPreparationBinding | never,
    ),
  );
  const limits = Object.freeze(
    snapshotLimits(
      ownEnumerableDataValue(optionsRecord, "limits") as
        CodexShadowHostOptions<Input, Options, Output>["limits"] | never,
    ),
  );
  return {
    prepare: Reflect.get(preparer, "prepare") as CapturedHostOptions<
      Input,
      Options,
      Output
    >["prepare"],
    prepareThis: preparer,
    runExact: Reflect.get(transport, "runExact") as CapturedHostOptions<
      Input,
      Options,
      Output
    >["runExact"],
    transportThis: transport,
    emit: Reflect.get(evidenceSink, "emit") as CapturedHostOptions<
      Input,
      Options,
      Output
    >["emit"],
    sinkThis: evidenceSink,
    digestJson: Reflect.get(digester, "digestJson") as DigestJson,
    digestThis: digester,
    keyId: Reflect.get(digester, "keyId") as string,
    executionBinding,
    preparationBinding,
    limits,
  };
}

function validateOptions<Input, Options, Output>(
  options: CapturedHostOptions<Input, Options, Output>,
): void {
  const execution = options.executionBinding;
  const preparation = options.preparationBinding;
  const limits = options.limits;
  const thread = execution.thread;
  if (
    execution.provenance !== "adapter-thread-factory" ||
    !ADAPTER_PATTERN.test(execution.adapterId) ||
    !VERSION_PATTERN.test(execution.sdkVersion) ||
    !isSha256Digest(execution.adapterContractDigest) ||
    !isSha256Digest(execution.threadOptionsDigest) ||
    execution.externalClientConfiguration !== "unavailable:external-client" ||
    execution.contracts.provenance !== "host-declared-unverified" ||
    !isSha256Digest(execution.contracts.runtimeRevisionDigest) ||
    !isSha256Digest(execution.contracts.promptContractDigest) ||
    !isSha256Digest(execution.contracts.toolContractDigest) ||
    !isSha256Digest(execution.contracts.agentsDigest) ||
    !isBoundedTextOrDefault(thread.model, 256) ||
    !isBoundedPathOrDefault(thread.workingDirectory) ||
    ![
      "read-only",
      "workspace-write",
      "danger-full-access",
      "unavailable:not-explicit",
    ].includes(thread.sandboxMode) ||
    ![
      "untrusted",
      "on-failure",
      "on-request",
      "never",
      "unavailable:not-explicit",
    ].includes(thread.approvalPolicy) ||
    !["disabled", "cached", "live", "unavailable:not-explicit"].includes(
      thread.webSearchMode,
    ) ||
    !isBooleanOrUnavailable(thread.skipGitRepoCheck) ||
    ![
      "minimal",
      "low",
      "medium",
      "high",
      "xhigh",
      "unavailable:not-explicit",
    ].includes(thread.modelReasoningEffort) ||
    !isBooleanOrUnavailable(thread.networkAccessEnabled) ||
    !isBooleanOrUnavailable(thread.webSearchEnabled) ||
    !Number.isSafeInteger(thread.additionalDirectories) ||
    thread.additionalDirectories < 0 ||
    thread.additionalDirectories > 64 ||
    (thread.additionalDirectoriesDigest !== "unavailable:not-explicit" &&
      !isSha256Digest(thread.additionalDirectoriesDigest)) ||
    !["system", "developer", "user", "assistant", "tool"].includes(
      preparation.role,
    ) ||
    ![
      "instruction",
      "prose",
      "code",
      "diff",
      "json-data",
      "tool-schema",
      "tool-call",
      "tool-result",
      "log",
    ].includes(preparation.kind) ||
    !["host-trusted", "workspace-trusted", "untrusted-external"].includes(
      preparation.trust,
    ) ||
    ![
      "byte-exact",
      "roundtrip-exact",
      "typed-semantic",
      "shadow-lossy",
    ].includes(preparation.equivalence) ||
    !MEDIA_TYPE_PATTERN.test(preparation.mediaType) ||
    !isSha256Digest(preparation.deploymentScopeDigest) ||
    !isLimit(limits.maximumInputBytes, 16 * 1024 * 1024) ||
    !isLimit(limits.maximumCandidateBytes, 16 * 1024 * 1024) ||
    !isLimit(limits.preparationMs, 120_000) ||
    !isLimit(limits.evidenceSinkMs, 30_000) ||
    typeof options.prepare !== "function" ||
    typeof options.runExact !== "function" ||
    typeof options.digestJson !== "function" ||
    typeof options.emit !== "function" ||
    typeof options.keyId !== "string" ||
    !KEY_ID_PATTERN.test(options.keyId)
  ) {
    throw new TypeError("Codex shadow host configuration is invalid");
  }
}

function snapshotExecutionBinding(
  value: CodexExecutionBinding,
): CodexExecutionBinding {
  const record = asObject(value, "execution binding");
  const thread = asObject(
    ownEnumerableDataValue(record, "thread"),
    "thread binding",
  );
  const contracts = asObject(
    ownEnumerableDataValue(record, "contracts"),
    "contract binding",
  );
  return {
    provenance: ownEnumerableDataValue(record, "provenance") as never,
    adapterId: ownEnumerableDataValue(record, "adapterId") as string,
    adapterContractDigest: ownEnumerableDataValue(
      record,
      "adapterContractDigest",
    ) as Sha256Digest,
    sdkVersion: ownEnumerableDataValue(record, "sdkVersion") as string,
    threadOptionsDigest: ownEnumerableDataValue(
      record,
      "threadOptionsDigest",
    ) as Sha256Digest,
    externalClientConfiguration: ownEnumerableDataValue(
      record,
      "externalClientConfiguration",
    ) as never,
    thread: {
      model: ownEnumerableDataValue(thread, "model") as never,
      workingDirectory: ownEnumerableDataValue(
        thread,
        "workingDirectory",
      ) as never,
      sandboxMode: ownEnumerableDataValue(thread, "sandboxMode") as never,
      approvalPolicy: ownEnumerableDataValue(thread, "approvalPolicy") as never,
      webSearchMode: ownEnumerableDataValue(thread, "webSearchMode") as never,
      skipGitRepoCheck: ownEnumerableDataValue(
        thread,
        "skipGitRepoCheck",
      ) as never,
      modelReasoningEffort: ownEnumerableDataValue(
        thread,
        "modelReasoningEffort",
      ) as never,
      networkAccessEnabled: ownEnumerableDataValue(
        thread,
        "networkAccessEnabled",
      ) as never,
      webSearchEnabled: ownEnumerableDataValue(
        thread,
        "webSearchEnabled",
      ) as never,
      additionalDirectories: ownEnumerableDataValue(
        thread,
        "additionalDirectories",
      ) as number,
      additionalDirectoriesDigest: ownEnumerableDataValue(
        thread,
        "additionalDirectoriesDigest",
      ) as never,
    },
    contracts: {
      provenance: ownEnumerableDataValue(contracts, "provenance") as never,
      runtimeRevisionDigest: ownEnumerableDataValue(
        contracts,
        "runtimeRevisionDigest",
      ) as Sha256Digest,
      promptContractDigest: ownEnumerableDataValue(
        contracts,
        "promptContractDigest",
      ) as Sha256Digest,
      toolContractDigest: ownEnumerableDataValue(
        contracts,
        "toolContractDigest",
      ) as Sha256Digest,
      agentsDigest: ownEnumerableDataValue(
        contracts,
        "agentsDigest",
      ) as Sha256Digest,
    },
  };
}

function snapshotPreparationBinding(
  value: CodexPreparationBinding,
): CodexPreparationBinding {
  const record = asObject(value, "preparation binding");
  return {
    role: ownEnumerableDataValue(record, "role") as never,
    kind: ownEnumerableDataValue(record, "kind") as never,
    trust: ownEnumerableDataValue(record, "trust") as never,
    mediaType: ownEnumerableDataValue(record, "mediaType") as string,
    equivalence: ownEnumerableDataValue(record, "equivalence") as never,
    deploymentScopeDigest: ownEnumerableDataValue(
      record,
      "deploymentScopeDigest",
    ) as Sha256Digest,
  };
}

function snapshotLimits(
  value: CodexShadowHostOptions<unknown, unknown, unknown>["limits"],
): CodexShadowHostOptions<unknown, unknown, unknown>["limits"] {
  const record = asObject(value, "shadow limits");
  return {
    maximumInputBytes: ownEnumerableDataValue(
      record,
      "maximumInputBytes",
    ) as number,
    maximumCandidateBytes: ownEnumerableDataValue(
      record,
      "maximumCandidateBytes",
    ) as number,
    preparationMs: ownEnumerableDataValue(record, "preparationMs") as number,
    evidenceSinkMs: ownEnumerableDataValue(record, "evidenceSinkMs") as number,
  };
}

function snapshotPreparationResult(
  value: unknown,
  original: string,
  maximumCandidateBytes: number,
  expectedDeploymentScope: Sha256Digest,
): ParsedPreparation | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  const allowed = new Set([
    "applied",
    "content",
    "deploymentScopeDigest",
    "promotionDigest",
    "proof",
    "reasons",
    "selectedCodec",
  ]);
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.some((key) => typeof key !== "string" || !allowed.has(key)) ||
    !["applied", "content", "reasons", "selectedCodec"].every((field) =>
      ownKeys.includes(field),
    )
  ) {
    return undefined;
  }
  const content = ownEnumerableDataValue(value, "content");
  const applied = ownEnumerableDataValue(value, "applied");
  const selectedCodec = ownEnumerableDataValue(value, "selectedCodec");
  const reasons = snapshotReasons(ownEnumerableDataValue(value, "reasons"));
  const promotionDigest = optionalDataValue(value, "promotionDigest");
  const deploymentScopeDigest = optionalDataValue(
    value,
    "deploymentScopeDigest",
  );
  const proof = optionalDataValue(value, "proof");
  if (
    typeof content !== "string" ||
    Buffer.byteLength(content) > maximumCandidateBytes ||
    typeof applied !== "boolean" ||
    typeof selectedCodec !== "string" ||
    !CODEC_PATTERN.test(selectedCodec) ||
    reasons === undefined ||
    (promotionDigest !== undefined && !isSha256Digest(promotionDigest)) ||
    (deploymentScopeDigest !== undefined &&
      (!isSha256Digest(deploymentScopeDigest) ||
        deploymentScopeDigest !== expectedDeploymentScope)) ||
    (proof !== undefined &&
      (proof === null || typeof proof !== "object" || Array.isArray(proof)))
  ) {
    return undefined;
  }
  if (!applied) {
    if (content !== original || reasons.includes("APPLIED")) return undefined;
  } else if (
    content === original ||
    selectedCodec === "identity" ||
    reasons.length !== 1 ||
    reasons[0] !== "APPLIED" ||
    proof === undefined ||
    promotionDigest === undefined ||
    deploymentScopeDigest !== expectedDeploymentScope
  ) {
    return undefined;
  }
  return Object.freeze({
    content,
    applied,
    selectedCodec,
    reasons,
    ...(promotionDigest === undefined ? {} : { promotionDigest }),
    proofPresent: proof !== undefined,
  });
}

function ownEnumerableDataValue(value: object, field: string): unknown {
  const descriptor = Reflect.getOwnPropertyDescriptor(value, field);
  if (
    descriptor === undefined ||
    !descriptor.enumerable ||
    !Object.hasOwn(descriptor, "value") ||
    Object.hasOwn(descriptor, "get") ||
    Object.hasOwn(descriptor, "set")
  ) {
    throw new TypeError("Preparation result must contain data-only fields");
  }
  return descriptor.value;
}

function optionalDataValue(value: object, field: string): unknown {
  return Reflect.has(value, field)
    ? ownEnumerableDataValue(value, field)
    : undefined;
}

function snapshotReasons(
  value: unknown,
): readonly HostReasonCode[] | undefined {
  if (
    !Array.isArray(value) ||
    Reflect.getPrototypeOf(value) !== Array.prototype
  )
    return undefined;
  const ownKeys = Reflect.ownKeys(value);
  const lengthDescriptor = Reflect.getOwnPropertyDescriptor(value, "length");
  if (
    lengthDescriptor === undefined ||
    !("value" in lengthDescriptor) ||
    !Number.isSafeInteger(lengthDescriptor.value) ||
    lengthDescriptor.value < 1 ||
    lengthDescriptor.value > 16 ||
    ownKeys.length !== lengthDescriptor.value + 1
  ) {
    return undefined;
  }
  const reasons: HostReasonCode[] = [];
  for (let index = 0; index < lengthDescriptor.value; index += 1) {
    const reason = ownEnumerableDataValue(value, String(index));
    if (!isHostReasonCode(reason)) return undefined;
    reasons.push(reason);
  }
  return Object.freeze(reasons);
}

function observation(
  outcome: CodexShadowEvidence["preparation"]["outcome"],
  reason: CodexPreparationReason,
): PreparationObservation {
  return Object.freeze({ outcome, reason, proof: "not-observed" });
}

function emergencyEvidence(
  inputKind: "text" | "non-text",
): CodexShadowEvidence {
  return deepFreeze({
    schema: CODEX_SHADOW_EVIDENCE_SCHEMA,
    mode: "shadow",
    submitted: "original",
    inputKind,
    bindingDigest: "unavailable:binding-digest",
    originalDigest:
      inputKind === "text"
        ? "unavailable:original-digest"
        : "unavailable:non-text-input",
    optionsDigest: "unavailable:unbound-options",
    execution: {
      status: "succeeded",
      outputDigest: "unavailable:opaque-output",
    },
    preparation: {
      outcome: inputKind === "non-text" ? "bypass" : "preparer-fault",
      reason: inputKind === "non-text" ? "NON_TEXT_INPUT" : "PREPARER_FAULT",
      proof: "not-observed",
    },
  });
}

function safeDigest<Fallback extends string | null>(
  digestJson: DigestJson,
  value: unknown,
  fallback: Fallback,
): HmacEvidenceDigest | Fallback {
  try {
    const digest = digestJson(value);
    return typeof digest === "string" && HMAC_PATTERN.test(digest)
      ? digest
      : fallback;
  } catch {
    return fallback;
  }
}

function digestBinding(
  digestJson: DigestJson,
  binding: Readonly<{
    execution: CodexExecutionBinding;
    preparation: CodexPreparationBinding;
  }>,
): HmacEvidenceDigest | null {
  return safeDigest(
    digestJson,
    {
      domain: "io.github.aantenore.intentabi/codex-execution-binding/v1",
      binding,
      value: null,
    },
    null,
  );
}

type Settled<T> =
  | { readonly status: "fulfilled"; readonly value: T }
  | { readonly status: "rejected" }
  | { readonly status: "timeout" }
  | { readonly status: "cancelled" };

async function settleWithTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  abortController?: AbortController,
  cancellationSignal?: AbortSignal,
): Promise<Settled<T>> {
  let timer: NodeJS.Timeout | undefined;
  let cancel: (() => void) | undefined;
  const timeout = new Promise<Settled<T>>((resolve) => {
    timer = setTimeout(() => {
      abortController?.abort();
      resolve({ status: "timeout" });
    }, timeoutMs);
  });
  const cancellation = new Promise<Settled<T>>((resolve) => {
    if (cancellationSignal === undefined) return;
    cancel = () => resolve({ status: "cancelled" });
    if (cancellationSignal.aborted) cancel();
    else cancellationSignal.addEventListener("abort", cancel, { once: true });
  });
  const settled: Promise<Settled<T>> = promise
    .then((value) => ({ status: "fulfilled" as const, value }))
    .catch(() => ({ status: "rejected" as const }));
  const result = await Promise.race([settled, timeout, cancellation]);
  if (timer !== undefined) clearTimeout(timer);
  if (cancel !== undefined)
    cancellationSignal?.removeEventListener("abort", cancel);
  return result;
}

function isBoundedTextOrDefault(value: string, maximumLength: number): boolean {
  return (
    value === "unavailable:not-explicit" ||
    (value.length > 0 &&
      value.length <= maximumLength &&
      !hasControlCharacter(value))
  );
}

function isBoundedPathOrDefault(value: string): boolean {
  return (
    value === "unavailable:not-explicit" ||
    (value.length > 0 && value.length <= 4_096 && !value.includes("\0"))
  );
}

function isBooleanOrUnavailable(value: unknown): boolean {
  return typeof value === "boolean" || value === "unavailable:not-explicit";
}

function asObject(value: unknown, label: string): object {
  if (
    value === null ||
    (typeof value !== "object" && typeof value !== "function")
  ) {
    throw new TypeError(`Codex ${label} must be an object`);
  }
  return value;
}

function isLimit(value: number, maximum: number): boolean {
  return Number.isSafeInteger(value) && value >= 1 && value <= maximum;
}

function hasControlCharacter(value: string): boolean {
  return Array.from(value).some((character) => {
    const codePoint = character.codePointAt(0);
    return codePoint !== undefined && (codePoint <= 31 || codePoint === 127);
  });
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const nested of Object.values(value)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
}
