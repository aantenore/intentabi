import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  createHmacOpaqueDigester,
  type KeyedHmacDigester,
} from "@intentabi/core";
import { createSemWitness } from "semwitness";
import {
  createVerifiedTextRequestPreparer,
  type TextPreparationResult,
} from "semwitness/host";
import { describe, expect, it, vi } from "vitest";

import {
  CodexShadowHost,
  deriveCodexShadowBindingDigest,
  verifyAndClaimCodexShadowEvidenceEnvelope,
  verifyCodexShadowEvidenceEnvelope,
  type AuthenticatedCodexShadowEvidence,
  type CodexExecutionBinding,
  type CodexShadowHostOptions,
} from "../src/index.js";

const digest = (character: string) => `sha256:${character.repeat(64)}` as const;
const secret = "intentabi-codex-shadow-test-secret-32-bytes";
const originalSentinel = "PRIVATE_ORIGINAL_SENTINEL";
const candidateSentinel = "PRIVATE_CANDIDATE_SENTINEL";

interface RunOptions {
  readonly outputSchema: { readonly type: "object" };
}

interface TurnOutput {
  readonly finalResponse: string;
}

function executionBinding(): CodexExecutionBinding {
  return {
    provenance: "adapter-thread-factory",
    adapterId: "@intentabi/adapter-codex-sdk",
    adapterContractDigest: digest("0"),
    sdkVersion: "0.144.4",
    threadOptionsDigest: digest("5"),
    externalClientConfiguration: "unavailable:external-client",
    thread: {
      model: "gpt-codex-test",
      workingDirectory: "/private/workspace",
      sandboxMode: "read-only",
      approvalPolicy: "never",
      webSearchMode: "disabled",
      skipGitRepoCheck: false,
      modelReasoningEffort: "high",
      networkAccessEnabled: false,
      webSearchEnabled: false,
      additionalDirectories: 0,
      additionalDirectoriesDigest: "unavailable:not-explicit",
    },
    contracts: {
      provenance: "host-declared-unverified",
      runtimeRevisionDigest: digest("1"),
      promptContractDigest: digest("2"),
      toolContractDigest: digest("3"),
      agentsDigest: digest("4"),
    },
  };
}

function appliedPreparation(
  selectedCodec = "verified-json-v1",
): TextPreparationResult {
  return {
    content: candidateSentinel,
    applied: true,
    selectedCodec,
    reasons: ["APPLIED"],
    proof: {
      schema: "test-proof",
      candidateReference: digest("8"),
    } as never,
    promotionDigest: digest("7"),
    deploymentScopeDigest: digest("6"),
  };
}

function hostOptions(
  overrides: Partial<
    CodexShadowHostOptions<string, RunOptions, TurnOutput>
  > = {},
) {
  const envelopes: AuthenticatedCodexShadowEvidence[] = [];
  const submitted: { input?: string; options?: RunOptions } = {};
  const defaults: CodexShadowHostOptions<string, RunOptions, TurnOutput> = {
    preparer: {
      prepare: vi.fn(async () => appliedPreparation()),
    },
    transport: {
      executionBinding: executionBinding(),
      runExact: vi.fn(async (input, options) => {
        submitted.input = input;
        if (options !== undefined) submitted.options = options;
        return { finalResponse: "ordinary-result" };
      }),
    },
    digester: createHmacOpaqueDigester(secret, "codex-test-v1"),
    evidenceSink: {
      emit: vi.fn(async (envelope) => {
        envelopes.push(envelope);
      }),
    },
    preparationBinding: {
      role: "user",
      kind: "instruction",
      trust: "untrusted-external",
      mediaType: "text/plain",
      equivalence: "typed-semantic",
      deploymentScopeDigest: digest("6"),
    },
    limits: {
      maximumInputBytes: 16_384,
      maximumCandidateBytes: 16_384,
      preparationMs: 50,
      evidenceSinkMs: 50,
    },
  };
  return {
    options: { ...defaults, ...overrides },
    envelopes,
    submitted,
  };
}

function verificationContext(
  options: CodexShadowHostOptions<string, RunOptions, TurnOutput>,
) {
  const expectedBindingDigest = deriveCodexShadowBindingDigest({
    digester: options.digester,
    executionBinding: options.transport.executionBinding,
    preparationBinding: options.preparationBinding,
  });
  if (expectedBindingDigest === null) {
    throw new Error("Test binding derivation failed");
  }
  return { digester: options.digester, expectedBindingDigest };
}

describe("CodexShadowHost", () => {
  it("observes a candidate but submits only the exact original", async () => {
    const fixture = hostOptions();
    const options: RunOptions = { outputSchema: { type: "object" } };
    const host = new CodexShadowHost(fixture.options);

    const result = await host.run({
      id: "turn-1",
      input: originalSentinel,
      options,
    });

    expect(fixture.submitted).toEqual({ input: originalSentinel, options });
    expect(result.output).toEqual({ finalResponse: "ordinary-result" });
    expect(result.evidence).toMatchObject({
      submitted: "original",
      optionsDigest: "unavailable:unbound-options",
      execution: { outputDigest: "unavailable:opaque-output" },
      preparation: {
        outcome: "candidate-observed",
        reason: "CANDIDATE_ATTESTED",
        proof: "present-unverified",
      },
    });
    expect(result.evidence.preparation.candidateDigest).toMatch(
      /^hmac-sha256:evidence:[a-f0-9]{64}$/u,
    );
    const serialized = JSON.stringify({ result, envelopes: fixture.envelopes });
    expect(serialized).not.toContain(originalSentinel);
    expect(serialized).not.toContain(candidateSentinel);
    expect(serialized).not.toContain("verified-json-v1");
  });

  it("never reflects on opaque options before transport", async () => {
    let observations = 0;
    const opaqueOptions = new Proxy({} as RunOptions, {
      getOwnPropertyDescriptor() {
        observations += 1;
        throw new Error("options observed");
      },
      ownKeys() {
        observations += 1;
        throw new Error("options observed");
      },
    });
    let received: RunOptions | undefined;
    const fixture = hostOptions({
      transport: {
        executionBinding: executionBinding(),
        runExact: vi.fn(async (_input, options) => {
          received = options;
          return { finalResponse: "ordinary-result" };
        }),
      },
    });
    const host = new CodexShadowHost(fixture.options);

    const result = await host.run({
      id: "turn-options",
      input: originalSentinel,
      options: opaqueOptions,
    });

    expect(observations).toBe(0);
    expect(received).toBe(opaqueOptions);
    expect(result.evidence.optionsDigest).toBe("unavailable:unbound-options");
  });

  it("returns an opaque output without reflecting on or freezing it", async () => {
    let observations = 0;
    const opaqueOutput = new Proxy(
      { finalResponse: "ordinary-result" },
      {
        getOwnPropertyDescriptor() {
          observations += 1;
          throw new Error("output observed");
        },
        ownKeys() {
          observations += 1;
          throw new Error("output observed");
        },
      },
    );
    const fixture = hostOptions({
      transport: {
        executionBinding: executionBinding(),
        runExact: vi.fn(async () => opaqueOutput),
      },
    });
    const host = new CodexShadowHost(fixture.options);

    const result = await host.run({
      id: "turn-output",
      input: originalSentinel,
    });

    expect(result.output).toBe(opaqueOutput);
    expect(observations).toBe(0);
    expect(Object.isFrozen(opaqueOutput)).toBe(false);
  });

  it("does not expose malicious but syntactically valid codec metadata", async () => {
    const fixture = hostOptions({
      preparer: {
        prepare: vi.fn(async () => appliedPreparation(originalSentinel)),
      },
    });
    const host = new CodexShadowHost(fixture.options);

    const result = await host.run({
      id: "turn-metadata",
      input: originalSentinel,
    });

    expect(result.evidence.preparation.selectedCodecDigest).toMatch(
      /^hmac-sha256:evidence:[a-f0-9]{64}$/u,
    );
    expect(JSON.stringify(result.evidence)).not.toContain(originalSentinel);
  });

  it("rejects regex-valid reasons outside the SemWitness allowlist", async () => {
    const fixture = hostOptions({
      preparer: {
        prepare: vi.fn(async () => ({
          ...appliedPreparation(),
          reasons: ["UNKNOWN_BUT_VALID"],
        })) as never,
      },
    });
    const host = new CodexShadowHost(fixture.options);

    const result = await host.run({
      id: "turn-reason",
      input: originalSentinel,
    });

    expect(result.evidence.preparation).toEqual({
      outcome: "invalid-preparer-result",
      reason: "PREPARER_RESULT_INVALID",
      proof: "not-observed",
    });
    expect(JSON.stringify(result.evidence)).not.toContain("UNKNOWN_BUT_VALID");
  });

  it("turns accessor and Proxy preparer results into content-free failure", async () => {
    const hostile = new Proxy(appliedPreparation(), {
      ownKeys() {
        throw new Error("SHADOW_MASKED_ORDINARY");
      },
    });
    const fixture = hostOptions({
      preparer: { prepare: vi.fn(async () => hostile) },
    });
    const host = new CodexShadowHost(fixture.options);

    const result = await host.run({
      id: "turn-proxy",
      input: originalSentinel,
    });

    expect(result.output.finalResponse).toBe("ordinary-result");
    expect(result.evidence.preparation).toEqual({
      outcome: "invalid-preparer-result",
      reason: "PREPARER_RESULT_INVALID",
      proof: "not-observed",
    });
  });

  it("does not treat a null proof field as proof presence", async () => {
    const fixture = hostOptions({
      preparer: {
        prepare: vi.fn(async () => ({
          ...appliedPreparation(),
          proof: null,
        })) as never,
      },
    });
    const host = new CodexShadowHost(fixture.options);

    const result = await host.run({
      id: "turn-null-proof",
      input: originalSentinel,
    });

    expect(result.evidence.preparation).toEqual({
      outcome: "invalid-preparer-result",
      reason: "PREPARER_RESULT_INVALID",
      proof: "not-observed",
    });
  });

  it("rejects an applied identity codec attestation", async () => {
    const fixture = hostOptions({
      preparer: {
        prepare: vi.fn(async () => appliedPreparation("identity")),
      },
    });
    const host = new CodexShadowHost(fixture.options);

    const result = await host.run({
      id: "turn-identity-codec",
      input: originalSentinel,
    });

    expect(result.evidence.preparation).toEqual({
      outcome: "invalid-preparer-result",
      reason: "PREPARER_RESULT_INVALID",
      proof: "not-observed",
    });
  });

  it("keeps ordinary output when every evidence digest fails", async () => {
    const digester: KeyedHmacDigester = {
      kind: "keyed-hmac-sha256",
      keyId: "faulty-v1",
      digestJson: vi.fn(() => {
        throw new Error("hmac unavailable");
      }),
    };
    const fixture = hostOptions({ digester });
    const host = new CodexShadowHost(fixture.options);

    const result = await host.run({
      id: "turn-digester",
      input: originalSentinel,
    });

    expect(result.output.finalResponse).toBe("ordinary-result");
    expect(result.evidence.bindingDigest).toBe("unavailable:binding-digest");
    expect(result.evidence.originalDigest).toBe("unavailable:original-digest");
    expect(result.envelope).toBeNull();
    expect(result.evidenceDelivery).toBe("dropped");
  });

  it("rejects a digester that returns plaintext without exposing it", async () => {
    const fixture = hostOptions({
      digester: {
        kind: "keyed-hmac-sha256",
        keyId: "plaintext-v1",
        digestJson: vi.fn(() => originalSentinel as never),
      },
    });
    const host = new CodexShadowHost(fixture.options);

    const result = await host.run({
      id: "turn-plaintext",
      input: originalSentinel,
    });

    expect(JSON.stringify(result.evidence)).not.toContain(originalSentinel);
    expect(result.envelope).toBeNull();
  });

  it("never signs or emits evidence when the scope binding digest failed", async () => {
    const real = createHmacOpaqueDigester(secret, "stateful-v1");
    let calls = 0;
    const sink = vi.fn(async () => undefined);
    const fixture = hostOptions({
      digester: {
        kind: "keyed-hmac-sha256",
        keyId: real.keyId,
        digestJson(value) {
          calls += 1;
          if (calls === 1) throw new Error("binding unavailable");
          return real.digestJson(value);
        },
      },
      evidenceSink: { emit: sink },
    });
    const host = new CodexShadowHost(fixture.options);

    const result = await host.run({
      id: "turn-unbound",
      input: originalSentinel,
    });

    expect(result.evidence.bindingDigest).toBe("unavailable:binding-digest");
    expect(result.envelope).toBeNull();
    expect(sink).not.toHaveBeenCalled();
  });

  it("does not coerce a malicious non-string digest", async () => {
    let coercions = 0;
    const fixture = hostOptions({
      digester: {
        kind: "keyed-hmac-sha256",
        keyId: "object-v1",
        digestJson: vi.fn(
          () =>
            ({
              toString() {
                coercions += 1;
                return originalSentinel;
              },
            }) as never,
        ),
      },
    });
    const host = new CodexShadowHost(fixture.options);

    const result = await host.run({
      id: "turn-object",
      input: originalSentinel,
    });

    expect(coercions).toBe(0);
    expect(result.envelope).toBeNull();
    expect(JSON.stringify(result.evidence)).not.toContain(originalSentinel);
  });

  it("binds content digests to execution and deployment scope", async () => {
    const first = hostOptions();
    const second = hostOptions({
      preparationBinding: {
        ...first.options.preparationBinding,
        deploymentScopeDigest: digest("9"),
      },
      preparer: {
        prepare: vi.fn(async () => ({
          ...appliedPreparation(),
          deploymentScopeDigest: digest("9"),
        })),
      },
    });

    const firstResult = await new CodexShadowHost(first.options).run({
      id: "turn-scope-a",
      input: originalSentinel,
    });
    const secondResult = await new CodexShadowHost(second.options).run({
      id: "turn-scope-b",
      input: originalSentinel,
    });

    expect(firstResult.evidence.originalDigest).not.toBe(
      secondResult.evidence.originalDigest,
    );
    expect(firstResult.evidence.preparation.candidateDigest).not.toBe(
      secondResult.evidence.preparation.candidateDigest,
    );
    expect(firstResult.evidence.preparation.selectedCodecDigest).not.toBe(
      secondResult.evidence.preparation.selectedCodecDigest,
    );
    expect(firstResult.evidence.preparation.reasonSetDigest).not.toBe(
      secondResult.evidence.preparation.reasonSetDigest,
    );
    expect(firstResult.evidence.preparation.promotionBindingDigest).not.toBe(
      secondResult.evidence.preparation.promotionBindingDigest,
    );
  });

  it("snapshots transport-owned bindings before caller mutation", async () => {
    const fixture = hostOptions();
    const mutable = fixture.options.transport.executionBinding.thread as {
      model: string;
    };
    const host = new CodexShadowHost(fixture.options);
    mutable.model = "mutated-model";

    const result = await host.run({
      id: "turn-binding",
      input: originalSentinel,
    });

    const baseline = hostOptions();
    const baselineResult = await new CodexShadowHost(baseline.options).run({
      id: "turn-binding",
      input: originalSentinel,
    });
    expect(result.evidence.bindingDigest).toBe(
      baselineResult.evidence.bindingDigest,
    );
  });

  it("rejects accessor-based binding configuration without invoking it", () => {
    let getterCalls = 0;
    const binding = executionBinding();
    Object.defineProperty(binding, "sdkVersion", {
      enumerable: true,
      get() {
        getterCalls += 1;
        return getterCalls === 1 ? "0.144.4" : "INVALID\0UNVALIDATED";
      },
    });
    const fixture = hostOptions({
      transport: {
        executionBinding: binding,
        runExact: vi.fn(async () => ({ finalResponse: "ordinary-result" })),
      },
    });

    expect(() => new CodexShadowHost(fixture.options)).toThrow(/data-only/u);
    expect(getterCalls).toBe(0);
  });

  it("times out an uncancellable preparer and still returns the original path", async () => {
    const fixture = hostOptions({
      preparer: { prepare: vi.fn(() => new Promise(() => undefined)) },
      limits: {
        maximumInputBytes: 16_384,
        maximumCandidateBytes: 16_384,
        preparationMs: 5,
        evidenceSinkMs: 50,
      },
    });
    const host = new CodexShadowHost(fixture.options);

    const result = await host.run({
      id: "turn-timeout",
      input: originalSentinel,
    });

    expect(fixture.submitted.input).toBe(originalSentinel);
    expect(result.evidence.preparation).toMatchObject({
      outcome: "preparer-timeout",
      reason: "PREPARATION_TIMEOUT_UNCANCELLED",
    });
  });

  it("keeps the ordinary result when the evidence sink fails", async () => {
    const fixture = hostOptions({
      evidenceSink: {
        emit: vi.fn(async () => Promise.reject(new Error("sink unavailable"))),
      },
    });
    const host = new CodexShadowHost(fixture.options);

    const result = await host.run({ id: "turn-sink", input: originalSentinel });

    expect(result.output.finalResponse).toBe("ordinary-result");
    expect(result.evidenceDelivery).toBe("unacknowledged");
    expect(result.envelope).not.toBeNull();
  });

  it("returns the same authenticated event when a sink stores then rejects", async () => {
    const stored: AuthenticatedCodexShadowEvidence[] = [];
    const fixture = hostOptions({
      evidenceSink: {
        emit: vi.fn(async (envelope) => {
          stored.push(envelope);
          throw new Error("acknowledgement lost");
        }),
      },
    });
    const host = new CodexShadowHost(fixture.options);

    const result = await host.run({
      id: "turn-ack-lost",
      input: originalSentinel,
    });

    expect(result.evidenceDelivery).toBe("unacknowledged");
    expect(stored).toHaveLength(1);
    expect(result.envelope).toBe(stored[0]);
  });

  it("freezes evidence before an untrusted sink receives it", async () => {
    const fixture = hostOptions({
      evidenceSink: {
        emit: vi.fn(async (envelope) => {
          (envelope.evidence.preparation as { reason: string }).reason =
            "SINK_MUTATION";
        }),
      },
    });
    const host = new CodexShadowHost(fixture.options);

    const result = await host.run({
      id: "turn-frozen",
      input: originalSentinel,
    });

    expect(result.evidenceDelivery).toBe("unacknowledged");
    expect(result.evidence.preparation.reason).toBe("CANDIDATE_ATTESTED");
  });

  it("bypasses non-text SDK input and preserves its exact identity", async () => {
    const structured = [{ type: "local_image", path: "/private/image.png" }];
    let received: unknown;
    const fixture = hostOptions();
    const host = new CodexShadowHost<unknown, RunOptions, TurnOutput>({
      ...fixture.options,
      transport: {
        executionBinding: executionBinding(),
        runExact: vi.fn(async (input) => {
          received = input;
          return { finalResponse: "ordinary-result" };
        }),
      },
    });

    const result = await host.run({ id: "turn-non-text", input: structured });

    expect(received).toBe(structured);
    expect(result.evidence).toMatchObject({
      inputKind: "non-text",
      originalDigest: "unavailable:non-text-input",
      preparation: { outcome: "bypass", reason: "NON_TEXT_INPUT" },
    });
    expect(fixture.options.preparer.prepare).not.toHaveBeenCalled();
  });

  it("does not reflect on a non-text input Proxy", async () => {
    let observations = 0;
    const structured = new Proxy(
      [{ type: "local_image", path: "/private/image.png" }],
      {
        getOwnPropertyDescriptor() {
          observations += 1;
          throw new Error("input observed");
        },
        ownKeys() {
          observations += 1;
          throw new Error("input observed");
        },
      },
    );
    let received: unknown;
    const fixture = hostOptions();
    const host = new CodexShadowHost<unknown, RunOptions, TurnOutput>({
      ...fixture.options,
      transport: {
        executionBinding: executionBinding(),
        runExact: vi.fn(async (input) => {
          received = input;
          return { finalResponse: "ordinary-result" };
        }),
      },
    });

    await host.run({ id: "turn-proxy-input", input: structured });

    expect(received).toBe(structured);
    expect(observations).toBe(0);
  });

  it.each([undefined, null, false, 0, Symbol("transport-error")])(
    "rethrows the exact transport error without waiting for shadow work: %s",
    async (transportError) => {
      const sink = vi.fn(async () => undefined);
      const fixture = hostOptions({
        preparer: { prepare: vi.fn(() => new Promise(() => undefined)) },
        transport: {
          executionBinding: executionBinding(),
          runExact: vi.fn(async () => Promise.reject(transportError)),
        },
        evidenceSink: { emit: sink },
        limits: {
          maximumInputBytes: 16_384,
          maximumCandidateBytes: 16_384,
          preparationMs: 30_000,
          evidenceSinkMs: 30_000,
        },
      });
      const host = new CodexShadowHost(fixture.options);

      const settled = await host
        .run({ id: "turn-error", input: originalSentinel })
        .then(
          () => ({ status: "fulfilled" as const }),
          (reason: unknown) => ({ status: "rejected" as const, reason }),
        );

      expect(settled).toEqual({ status: "rejected", reason: transportError });
      expect(sink).not.toHaveBeenCalled();
    },
  );

  it.each(["succeeded", "failed"])(
    "settles malformed request metadata without unhandled rejection when transport %s",
    async (outcome) => {
      const unhandled = vi.fn();
      process.on("unhandledRejection", unhandled);
      try {
        const transportError = new Error("transport failed");
        const fixture = hostOptions({
          transport: {
            executionBinding: executionBinding(),
            runExact: vi.fn(
              async () =>
                new Promise<TurnOutput>((resolve, reject) => {
                  setTimeout(() => {
                    if (outcome === "succeeded") {
                      resolve({ finalResponse: "ordinary-result" });
                    } else {
                      reject(transportError);
                    }
                  }, 5);
                }),
            ),
          },
        });
        const host = new CodexShadowHost(fixture.options);
        const settled = await host
          .run({ id: Symbol("invalid-id") as never, input: originalSentinel })
          .then(
            (value) => ({ status: "fulfilled" as const, value }),
            (reason: unknown) => ({ status: "rejected" as const, reason }),
          );
        await new Promise((resolve) => setImmediate(resolve));

        if (outcome === "succeeded") {
          expect(settled.status).toBe("fulfilled");
        } else {
          expect(settled).toEqual({
            status: "rejected",
            reason: transportError,
          });
        }
        expect(unhandled).not.toHaveBeenCalled();
      } finally {
        process.off("unhandledRejection", unhandled);
      }
    },
  );

  it("composes the real SemWitness preparer without claiming promotion", async () => {
    const storeRoot = await mkdtemp(join(tmpdir(), "intentabi-semwitness-"));
    try {
      const core = createSemWitness({ storeRoot });
      const fixture = hostOptions({
        preparer: createVerifiedTextRequestPreparer(core, core.policy),
      });
      const host = new CodexShadowHost(fixture.options);

      const result = await host.run({
        id: "turn-real-semwitness",
        input: originalSentinel,
      });

      expect(fixture.submitted.input).toBe(originalSentinel);
      expect(result.evidence.preparation).toMatchObject({
        outcome: "identity",
        reason: "IDENTITY_ATTESTED",
        proof: "not-observed",
      });
      expect(result.evidence.preparation.reasonSetDigest).toMatch(
        /^hmac-sha256:evidence:[a-f0-9]{64}$/u,
      );
      expect(JSON.stringify(result.evidence)).not.toContain(
        "PROMOTION_MISSING",
      );
    } finally {
      await rm(storeRoot, { recursive: true, force: true });
    }
  });
});

describe("Codex shadow evidence verification", () => {
  it("rejects tamper, splice, schema extras, key mismatch, and replay", async () => {
    const fixture = hostOptions();
    const context = verificationContext(fixture.options);
    const result = await new CodexShadowHost(fixture.options).run({
      id: "turn-envelope",
      input: originalSentinel,
    });
    expect(result.envelope).not.toBeNull();
    const envelope = result.envelope as AuthenticatedCodexShadowEvidence;
    const tampered = {
      ...envelope,
      evidence: { ...envelope.evidence, submitted: "candidate" },
    };
    const spliced = { ...envelope, eventId: crypto.randomUUID() };
    const extra = { ...envelope, raw: originalSentinel };
    const otherKey = createHmacOpaqueDigester(
      "another-intentabi-test-secret-32-bytes",
      "other-v1",
    );

    expect(verifyCodexShadowEvidenceEnvelope(envelope, context)).not.toBeNull();
    expect(verifyCodexShadowEvidenceEnvelope(tampered, context)).toBeNull();
    expect(verifyCodexShadowEvidenceEnvelope(spliced, context)).toBeNull();
    expect(verifyCodexShadowEvidenceEnvelope(extra, context)).toBeNull();
    expect(
      verifyCodexShadowEvidenceEnvelope(envelope, {
        ...context,
        digester: otherKey,
      }),
    ).toBeNull();
    const otherScope = hostOptions({
      preparationBinding: {
        ...fixture.options.preparationBinding,
        deploymentScopeDigest: digest("9"),
      },
    });
    expect(
      verifyCodexShadowEvidenceEnvelope(
        envelope,
        verificationContext(otherScope.options),
      ),
    ).toBeNull();
    expect(
      verifyCodexShadowEvidenceEnvelope(envelope, {
        ...context,
        expectedBindingDigest:
          "hmac-sha256:evidence:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      }),
    ).toBeNull();

    const claimed = new Set<string>();
    const guard = {
      claim: vi.fn(async (claim: { eventId: string }) => {
        if (claimed.has(claim.eventId)) return false;
        claimed.add(claim.eventId);
        return true;
      }),
    };
    expect(
      await verifyAndClaimCodexShadowEvidenceEnvelope(envelope, {
        ...context,
        replayGuard: guard,
      }),
    ).not.toBeNull();
    expect(
      await verifyAndClaimCodexShadowEvidenceEnvelope(envelope, {
        ...context,
        replayGuard: guard,
      }),
    ).toBeNull();
  });

  it("rejects accessor envelopes without invoking the accessor", () => {
    let getterCalls = 0;
    const hostile = Object.defineProperty({}, "schema", {
      enumerable: true,
      get() {
        getterCalls += 1;
        return "anything";
      },
    });

    expect(
      verifyCodexShadowEvidenceEnvelope(hostile, {
        digester: createHmacOpaqueDigester(secret, "codex-test-v1"),
        expectedBindingDigest:
          "hmac-sha256:evidence:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      }),
    ).toBeNull();
    expect(getterCalls).toBe(0);
  });

  it("rejects incoherent evidence even when it has a valid MAC", async () => {
    const fixture = hostOptions();
    const context = verificationContext(fixture.options);
    const result = await new CodexShadowHost(fixture.options).run({
      id: "turn-coherence",
      input: originalSentinel,
    });
    const envelope = result.envelope as AuthenticatedCodexShadowEvidence;
    const invalidEvidence = [
      {
        ...envelope.evidence,
        inputKind: "non-text",
        originalDigest: envelope.evidence.originalDigest,
      },
      {
        ...envelope.evidence,
        preparation: {
          outcome: "bypass",
          reason: "CANDIDATE_ATTESTED",
          proof: "not-observed",
        },
      },
      {
        ...envelope.evidence,
        preparation: {
          outcome: "bypass",
          reason: "NON_TEXT_INPUT",
          proof: "not-observed",
        },
      },
    ];

    for (const evidence of invalidEvidence) {
      expect(
        verifyCodexShadowEvidenceEnvelope(
          resignEnvelope(envelope, evidence, fixture.options.digester),
          context,
        ),
      ).toBeNull();
    }
  });

  it("returns a detached frozen snapshot and claims a replay only once concurrently", async () => {
    const fixture = hostOptions();
    const context = verificationContext(fixture.options);
    const result = await new CodexShadowHost(fixture.options).run({
      id: "turn-detached",
      input: originalSentinel,
    });
    const mutable = structuredClone(
      result.envelope as AuthenticatedCodexShadowEvidence,
    );
    const verified = verifyCodexShadowEvidenceEnvelope(mutable, context);
    expect(verified).not.toBeNull();
    mutable.evidence.preparation = {
      outcome: "preparer-fault",
      reason: "PREPARER_FAULT",
      proof: "not-observed",
    };
    expect(verified?.evidence.preparation.outcome).toBe("candidate-observed");
    expect(Object.isFrozen(verified?.evidence.preparation)).toBe(true);

    const claimed = new Set<string>();
    const replayGuard = {
      async claim(claim: { eventId: string }) {
        if (claimed.has(claim.eventId)) return false;
        claimed.add(claim.eventId);
        await Promise.resolve();
        return true;
      },
    };
    const accepted = await Promise.all([
      verifyAndClaimCodexShadowEvidenceEnvelope(result.envelope, {
        ...context,
        replayGuard,
      }),
      verifyAndClaimCodexShadowEvidenceEnvelope(result.envelope, {
        ...context,
        replayGuard,
      }),
    ]);
    expect(accepted.filter((entry) => entry !== null)).toHaveLength(1);
  });

  it("does not coerce a malicious verifier digest or poison replay state", async () => {
    const fixture = hostOptions();
    const trustedContext = verificationContext(fixture.options);
    const result = await new CodexShadowHost(fixture.options).run({
      id: "turn-verifier-digest",
      input: originalSentinel,
    });
    const envelope = result.envelope as AuthenticatedCodexShadowEvidence;
    let coercions = 0;
    const replayGuard = { claim: vi.fn(async () => true) };
    const verified = await verifyAndClaimCodexShadowEvidenceEnvelope(envelope, {
      digester: {
        kind: "keyed-hmac-sha256",
        keyId: fixture.options.digester.keyId,
        digestJson: vi.fn(
          () =>
            ({
              toString() {
                coercions += 1;
                return "malicious";
              },
            }) as never,
        ),
      },
      expectedBindingDigest: trustedContext.expectedBindingDigest,
      replayGuard,
    });

    expect(verified).toBeNull();
    expect(coercions).toBe(0);
    expect(replayGuard.claim).not.toHaveBeenCalled();
  });
});

function resignEnvelope(
  envelope: AuthenticatedCodexShadowEvidence,
  evidence: unknown,
  digester: KeyedHmacDigester,
): unknown {
  const unsigned = {
    schema: envelope.schema,
    eventId: envelope.eventId,
    keyId: envelope.keyId,
    evidence,
  };
  return {
    ...unsigned,
    mac: digester.digestJson({
      domain: "io.github.aantenore.intentabi/codex-evidence-envelope/v1",
      ...unsigned,
    }),
  };
}
