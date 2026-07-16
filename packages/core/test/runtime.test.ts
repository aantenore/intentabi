import { describe, expect, it, vi } from "vitest";

import {
  createHmacOpaqueDigester,
  ShadowRuntime,
  verifyEvidenceEnvelope,
  type AuthenticatedShadowEvidence,
  type IntentInspector,
  type OrdinaryRoute,
  type ShadowCandidateStore,
} from "../src/index.js";

const secret = "a".repeat(32);
const sourceDigest = `hmac-sha256:intent-source:${"a".repeat(64)}` as const;
const intentKey = `hmac-sha256:shadow-intent:${"b".repeat(64)}` as const;
const witnessKey = `hmac-sha256:shadow-witness:${"c".repeat(64)}` as const;
const scopeDigest = `hmac-sha256:shadow-scope:${"d".repeat(64)}` as const;
const bindingDigest = `hmac-sha256:shadow-binding:${"e".repeat(64)}` as const;
const routeInputDigest = `hmac-sha256:route-input:${"f".repeat(64)}` as const;
const revisionDigest = `sha256:${"1".repeat(64)}` as const;

describe("ShadowRuntime", () => {
  it("returns only ordinary output and authenticates unverified nomination evidence", async () => {
    const execute = vi.fn(async () => ({ origin: "ordinary", value: 42 }));
    const observe = vi.fn(async () => undefined);
    const digester = createHmacOpaqueDigester(secret, "test-v1");
    const runtime = new ShadowRuntime({
      inspector: eligibleInspector(),
      store: {
        probe: async () => ({ found: true }),
        observe,
      },
      route: route(execute),
      digester,
    });

    const result = await runtime.run(request());

    expect(execute).toHaveBeenCalledOnce();
    expect(result.output).toEqual({ origin: "ordinary", value: 42 });
    expect(result.evidence.candidate).toMatchObject({
      outcome: "unverified-candidate-observed",
      applied: false,
      intentKey,
    });
    expect(observe).toHaveBeenCalledOnce();
    expect(result.envelope).not.toBeNull();
    expect(
      result.envelope === null
        ? false
        : verifyEvidenceEnvelope(result.envelope, digester),
    ).toBe(true);
  });

  it("fails open on a shadow store fault", async () => {
    const runtime = new ShadowRuntime({
      inspector: eligibleInspector(),
      store: {
        probe: async () => {
          throw new Error("offline");
        },
        observe: async () => undefined,
      },
      route: route(async () => ({ ok: true })),
      digester: createHmacOpaqueDigester(secret),
    });

    const result = await runtime.run(request());

    expect(result.output).toEqual({ ok: true });
    expect(result.evidence.candidate).toMatchObject({
      outcome: "store-fault",
      applied: false,
      reasons: ["STORE_UNAVAILABLE"],
    });
  });

  it("turns null, unknown status, and write-effect inspector results into faults", async () => {
    const malformed = [
      null,
      { ...eligibleInspection(), status: "bogus" },
      { ...eligibleInspection(), effect: "write" },
    ];
    for (const value of malformed) {
      const runtime = new ShadowRuntime({
        inspector: { inspect: async () => value as never },
        store: emptyStore(),
        route: route(async () => ({ ok: true })),
        digester: createHmacOpaqueDigester(secret),
      });

      const result = await runtime.run(request());

      expect(result.output).toEqual({ ok: true });
      expect(result.evidence.candidate.outcome).toBe("normalizer-fault");
    }
  });

  it("strictly rejects store extras without forwarding plaintext", async () => {
    const plaintext = "TOP_SECRET_RESPONSE";
    const observe = vi.fn(async () => undefined);
    const runtime = new ShadowRuntime({
      inspector: eligibleInspector(),
      store: {
        probe: async () => ({ found: "yes", responseBody: plaintext }) as never,
        observe,
      },
      route: route(async () => ({ ok: true })),
      digester: createHmacOpaqueDigester(secret),
    });

    const result = await runtime.run(request());

    expect(result.evidence.candidate.outcome).toBe("store-fault");
    expect(observe).not.toHaveBeenCalled();
    expect(JSON.stringify(result.evidence)).not.toContain(plaintext);
  });

  it("bounds a stalled inspector without blocking indefinitely", async () => {
    const runtime = new ShadowRuntime({
      inspector: { inspect: async () => new Promise(() => undefined) },
      store: emptyStore(),
      route: route(async () => ({ ok: true })),
      digester: createHmacOpaqueDigester(secret),
      timeouts: { inspectionMs: 5, storeMs: 5, evidenceSinkMs: 5 },
    });

    const result = await runtime.run(request());

    expect(result.output).toEqual({ ok: true });
    expect(result.evidence.candidate).toMatchObject({
      outcome: "shadow-timeout",
      applied: false,
      reasons: ["INSPECTION_TIMEOUT"],
    });
  });

  it("signals sink cancellation and reports a timeout as unacknowledged", async () => {
    let lateSideEffect = false;
    const runtime = new ShadowRuntime({
      inspector: eligibleInspector(),
      store: emptyStore(),
      route: route(async () => ({ ok: true })),
      digester: createHmacOpaqueDigester(secret),
      evidenceSink: {
        emit: async (_envelope, signal) =>
          await new Promise<void>((resolvePromise, rejectPromise) => {
            const timer = setTimeout(() => {
              lateSideEffect = true;
              resolvePromise();
            }, 30);
            signal.addEventListener(
              "abort",
              () => {
                clearTimeout(timer);
                rejectPromise(new DOMException("Aborted", "AbortError"));
              },
              { once: true },
            );
          }),
      },
      timeouts: { inspectionMs: 20, storeMs: 20, evidenceSinkMs: 5 },
    });

    const result = await runtime.run(request());
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 40));

    expect(result.evidenceDelivery).toBe("unacknowledged");
    expect(lateSideEffect).toBe(false);
  });

  it("drops telemetry when keyed envelope authentication is unavailable", async () => {
    const emit = vi.fn(async () => undefined);
    const runtime = new ShadowRuntime({
      inspector: eligibleInspector(),
      store: emptyStore(),
      route: route(async () => ({ ok: true })),
      digester: {
        kind: "keyed-hmac-sha256",
        keyId: "broken-v1",
        digestJson: () => {
          throw new Error("key provider unavailable");
        },
      },
      evidenceSink: { emit },
    });

    const result = await runtime.run(request());

    expect(result.output).toEqual({ ok: true });
    expect(result.envelope).toBeNull();
    expect(result.evidenceDigest).toBeNull();
    expect(result.evidenceDelivery).toBe("dropped");
    expect(emit).not.toHaveBeenCalled();
  });

  it("rejects fake keyed digest plaintext", async () => {
    const plaintext = "ordinary output in plaintext";
    const runtime = new ShadowRuntime({
      inspector: eligibleInspector(),
      store: emptyStore(),
      route: route(async () => ({ ok: true })),
      digester: {
        kind: "keyed-hmac-sha256",
        keyId: "fake-v1",
        digestJson: () => plaintext as never,
      },
    });

    const result = await runtime.run(request());

    expect(JSON.stringify(result.evidence)).not.toContain(plaintext);
    expect(result.envelope).toBeNull();
  });

  it("emits authenticated failure evidence before rethrowing an ordinary error", async () => {
    let emitted: AuthenticatedShadowEvidence | undefined;
    const runtime = new ShadowRuntime({
      inspector: eligibleInspector(),
      store: emptyStore(),
      route: route((() => {
        throw new Error("sync failure");
      }) as () => Promise<never>),
      digester: createHmacOpaqueDigester(secret),
      evidenceSink: {
        emit: async (envelope) => {
          emitted = envelope;
        },
      },
    });

    await expect(runtime.run(request())).rejects.toThrow("sync failure");
    expect(emitted?.evidence.execution.status).toBe("failed");
  });

  it("detects tampering and envelope splicing", async () => {
    const digester = createHmacOpaqueDigester(secret, "test-v1");
    const result = await new ShadowRuntime({
      inspector: eligibleInspector(),
      store: emptyStore(),
      route: route(async () => ({ ok: true })),
      digester,
    }).run(request());
    expect(result.envelope).not.toBeNull();
    if (result.envelope === null) return;

    const tampered = structuredClone(result.envelope);
    (tampered.evidence.candidate as { outcome: string }).outcome = "bypass";
    const replaySplice = { ...result.envelope, eventId: crypto.randomUUID() };
    const schemaSmuggling = { ...result.envelope, unsigned: "extra" };

    expect(verifyEvidenceEnvelope(tampered, digester)).toBe(false);
    expect(verifyEvidenceEnvelope(replaySplice, digester)).toBe(false);
    expect(verifyEvidenceEnvelope(schemaSmuggling as never, digester)).toBe(
      false,
    );
  });

  it("snapshots route identity and JSON input before concurrent execution", async () => {
    const originalInput = { task: "status" };
    let inspectedTask: unknown;
    let inspectedRouteId: unknown;
    const mutableRoute = route(async () => ({ ok: true }));
    const runtime = new ShadowRuntime({
      inspector: {
        inspect: async (inspectionRequest) => {
          await new Promise((resolvePromise) => setTimeout(resolvePromise, 5));
          inspectedTask = (
            inspectionRequest.routeInput as { readonly task: string }
          ).task;
          inspectedRouteId = inspectionRequest.route.id;
          return eligibleInspection();
        },
      },
      store: emptyStore(),
      route: mutableRoute,
      digester: createHmacOpaqueDigester(secret),
    });

    const resultPromise = runtime.run({
      ...request(),
      routeInput: originalInput,
    });
    originalInput.task = "mutated";
    (mutableRoute as { id: string }).id = "mutated-route";
    const result = await resultPromise;

    expect(result.output).toEqual({ ok: true });
    expect(inspectedTask).toBe("status");
    expect(inspectedRouteId).toBe("ordinary");
  });

  it("keeps a non-JSON ordinary route available but excludes it from measurement", async () => {
    const inspect = vi.fn(async () => eligibleInspection());
    const routeInput = new Date(0);
    const runtime = new ShadowRuntime({
      inspector: { inspect },
      store: emptyStore(),
      route: {
        id: "ordinary",
        revisionDigest,
        execute: async (input: Date) => input.toISOString(),
      },
      digester: createHmacOpaqueDigester(secret),
    });

    const result = await runtime.run({
      ...request(),
      routeInput,
    });

    expect(result.output).toBe("1970-01-01T00:00:00.000Z");
    expect(result.evidence.candidate.outcome).toBe("normalizer-fault");
    expect(inspect).not.toHaveBeenCalled();
  });

  it("rejects unbounded timeout and unversioned route configuration", () => {
    expect(
      () =>
        new ShadowRuntime({
          inspector: eligibleInspector(),
          store: emptyStore(),
          route: route(async () => ({ ok: true })),
          digester: createHmacOpaqueDigester(secret),
          timeouts: { inspectionMs: 0, storeMs: 5, evidenceSinkMs: 5 },
        }),
    ).toThrow("Shadow timeouts");
    expect(
      () =>
        new ShadowRuntime({
          inspector: eligibleInspector(),
          store: emptyStore(),
          route: {
            id: "ordinary",
            revisionDigest: "latest" as never,
            execute: async () => ({ ok: true }),
          },
          digester: createHmacOpaqueDigester(secret),
        }),
    ).toThrow("route binding");
  });
});

function eligibleInspection() {
  return {
    status: "eligible" as const,
    sourceDigest,
    intentKey,
    witnessKey,
    scopeDigest,
    bindingDigest,
    routeInputDigest,
    effect: "read" as const,
    reasons: ["INTENT_NORMALIZATION_ELIGIBLE"] as const,
  };
}

function eligibleInspector(): IntentInspector {
  return { inspect: async () => eligibleInspection() };
}

function emptyStore(): ShadowCandidateStore {
  return {
    probe: async () => ({ found: false }),
    observe: async () => undefined,
  };
}

function route<Output>(
  execute: () => Promise<Output>,
): OrdinaryRoute<{ task: string }, Output> {
  return { id: "ordinary", revisionDigest, execute };
}

function request() {
  return {
    source: "status",
    locale: "en-US",
    scope: { tenant: "demo", authorization: "reader" },
    scopeEpoch: "test-v1",
    routeInput: { task: "status" },
  };
}
