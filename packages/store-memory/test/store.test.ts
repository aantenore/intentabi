import { describe, expect, it } from "vitest";

import { MemoryShadowStore } from "../src/index.js";

const intentKey = `hmac-sha256:shadow-intent:${"b".repeat(64)}` as const;

describe("MemoryShadowStore", () => {
  it("stores only reconstructed opaque observation metadata", async () => {
    const store = new MemoryShadowStore({ candidates: [intentKey] });
    const signal = new AbortController().signal;
    const probe = await store.probe(intentKey, signal);
    await store.observe(observation(probe), signal);

    expect(probe).toEqual({ found: true });
    expect(store.observations()).toHaveLength(1);
    expect(JSON.stringify(store.observations())).not.toContain("responseBody");
  });

  it("rejects malformed or plaintext-bearing direct observations", async () => {
    const store = new MemoryShadowStore();
    const malicious = {
      ...observation({ found: true }),
      responseBody: "TOP_SECRET",
    };

    await expect(
      store.observe(malicious as never, new AbortController().signal),
    ).rejects.toThrow("malformed");
    expect(store.observations()).toHaveLength(0);
  });

  it("honors cancellation before mutation", async () => {
    const store = new MemoryShadowStore();
    const controller = new AbortController();
    controller.abort();

    await expect(
      store.observe(observation({ found: false }), controller.signal),
    ).rejects.toMatchObject({ name: "AbortError" });
    expect(store.observations()).toHaveLength(0);
  });

  it("supports deterministic fault injection", async () => {
    const store = new MemoryShadowStore({ faultMode: "probe" });
    await expect(
      store.probe(intentKey, new AbortController().signal),
    ).rejects.toThrow("Configured probe fault");
  });
});

function observation(probe: { readonly found: boolean }) {
  return {
    observationId: "123e4567-e89b-42d3-a456-426614174000",
    sourceDigest: `hmac-sha256:intent-source:${"a".repeat(64)}` as const,
    intentKey,
    witnessKey: `hmac-sha256:shadow-witness:${"c".repeat(64)}` as const,
    scopeDigest: `hmac-sha256:shadow-scope:${"d".repeat(64)}` as const,
    bindingDigest: `hmac-sha256:shadow-binding:${"e".repeat(64)}` as const,
    routeInputDigest: `hmac-sha256:route-input:${"f".repeat(64)}` as const,
    probe: probe.found
      ? ({ found: true } as const)
      : ({ found: false } as const),
  };
}
