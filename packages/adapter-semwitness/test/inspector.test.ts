import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { SemWitnessIntentInspector } from "../src/index.js";

const registrySource = readFileSync(
  new URL("../../../fixtures/intent-registry.json", import.meta.url),
  "utf8",
);
const secret = "intentabi-test-secret-32-bytes-minimum";
const inspector = new SemWitnessIntentInspector({
  registrySource,
  policyDigest: `sha256:${"b".repeat(64)}`,
  hmacSecret: secret,
  expectedScope: { tenant: "demo", authorization: "reader" },
  routeBindings: {
    "read-project-status": { command: "status", project: "demo" },
  },
});

const scope = { tenant: "demo", authorization: "reader" };
const route = {
  id: "agentic-sdlc.fixture",
  revisionDigest: `sha256:${"1".repeat(64)}` as const,
};
const routeInput = { command: "status", project: "demo" };

function inspectionRequest(source: string) {
  return {
    source,
    locale: "en-US",
    scope,
    scopeEpoch: "test-v1",
    route,
    routeInput,
  };
}

describe("SemWitnessIntentInspector", () => {
  it("converges configured paraphrases through SemWitness-owned IntentIR", async () => {
    const first = await inspector.inspect(
      inspectionRequest("Show the current Agentic SDLC project status."),
    );
    const second = await inspector.inspect(
      inspectionRequest("What is the status of this SDLC project?"),
    );

    expect(first.status).toBe("eligible");
    expect(second.status).toBe("eligible");
    expect(first.status === "eligible" && second.status === "eligible").toBe(
      true,
    );
    if (first.status === "eligible" && second.status === "eligible") {
      expect(first.intentKey).toBe(second.intentKey);
      expect(first.sourceDigest).not.toBe(second.sourceDigest);
      expect(first.routeInputDigest).toBe(second.routeInputDigest);
    }
  });

  it("bypasses a negated near-match", async () => {
    const result = await inspector.inspect(
      inspectionRequest("Do not show the current Agentic SDLC project status."),
    );

    expect(result).toMatchObject({
      status: "bypass",
      reasons: ["INTENT_NO_MATCH"],
    });
  });

  it("bypasses a normalized side-effecting operation", async () => {
    const result = await inspector.inspect(
      inspectionRequest("Delete the current Agentic SDLC project."),
    );

    expect(result).toMatchObject({
      status: "bypass",
      reasons: ["EFFECT_NOT_SHADOW_ELIGIBLE"],
    });
  });

  it("bypasses a cross-scope request before candidate lookup", async () => {
    const result = await inspector.inspect({
      ...inspectionRequest("Show the current Agentic SDLC project status."),
      scope: { tenant: "other", authorization: "reader" },
    });

    expect(result).toMatchObject({
      status: "bypass",
      reasons: ["SCOPE_MISMATCH"],
    });
  });

  it("bypasses measurement when the normalized operation and route input diverge", async () => {
    const result = await inspector.inspect({
      ...inspectionRequest("Show the current Agentic SDLC project status."),
      routeInput: {
        root: "/tmp/project",
        intent: { requested_action: "implement_story" },
      },
    });

    expect(result).toMatchObject({
      status: "bypass",
      reasons: ["ROUTE_INPUT_MISMATCH"],
    });
  });

  it("emits only keyed semantic and route bindings", async () => {
    const result = await inspector.inspect(
      inspectionRequest("Show the current Agentic SDLC project status."),
    );

    expect(result).toMatchObject({
      status: "eligible",
      intentKey: expect.stringMatching(/^hmac-sha256:shadow-intent:/u),
      witnessKey: expect.stringMatching(/^hmac-sha256:shadow-witness:/u),
      scopeDigest: expect.stringMatching(/^hmac-sha256:shadow-scope:/u),
      bindingDigest: expect.stringMatching(/^hmac-sha256:shadow-binding:/u),
      routeInputDigest: expect.stringMatching(/^hmac-sha256:route-input:/u),
    });
  });
});
