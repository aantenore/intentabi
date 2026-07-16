import { describe, expect, it } from "vitest";

import { parseIntentAbiConfig } from "../src/index.js";

const valid = {
  schema: "io.github.aantenore.intentabi/config/v1alpha1",
  mode: "shadow",
  semwitness: {
    registryPath: "fixtures/intent-registry.json",
    policyDigest: `sha256:${"a".repeat(64)}`,
    hmacSecretEnv: "INTENTABI_HMAC_SECRET",
    scopeEpoch: "test-v1",
    expectedScope: { tenant: "demo", authorization: "reader" },
    routeBindings: { "read-status": { command: "status" } },
  },
  agenticSdlc: {
    kind: "fixture",
    fixturePath: "fixtures/agentic-sdlc-route.json",
  },
  store: { kind: "memory", faultMode: "none" },
  timeouts: { inspectionMs: 500, storeMs: 250, evidenceSinkMs: 100 },
  evidence: { sink: "stderr", keyId: "test-v1" },
} as const;

describe("parseIntentAbiConfig", () => {
  it("accepts the strict shadow host composition", () => {
    expect(parseIntentAbiConfig(valid)).toEqual(valid);
  });

  it("rejects unknown fields and any non-shadow mode", () => {
    expect(() =>
      parseIntentAbiConfig({ ...valid, activeCache: true }),
    ).toThrow();
    expect(() => parseIntentAbiConfig({ ...valid, mode: "active" })).toThrow();
  });

  it("rejects an HMAC environment name that can propagate to the child", () => {
    expect(() =>
      parseIntentAbiConfig({
        ...valid,
        semwitness: { ...valid.semwitness, hmacSecretEnv: "PATH" },
      }),
    ).toThrow();
  });
});
