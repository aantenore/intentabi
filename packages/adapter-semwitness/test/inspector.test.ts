import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";
import {
  digestIntentCachePromotionAdversarialCorpus,
  digestIntentCachePromotionPopulationCorpus,
  evaluateIntentCachePromotionEvidence,
  parseIntentCachePromotionEvidenceJsonl,
  recomputeIntentCachePromotionEvidenceBindingDigest,
} from "semwitness/intent/host";

import {
  SemWitnessIntentInspector,
  exportIntentCachePromotionEvidenceJsonl,
} from "../src/index.js";

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

describe("SemWitness promotion evidence exporter", () => {
  it("emits deterministic JSONL accepted by the real fail-closed evaluator", () => {
    const fixture = emptyPromotionFixture();
    const first = exportIntentCachePromotionEvidenceJsonl(fixture);
    const reordered = exportIntentCachePromotionEvidenceJsonl(
      reverseJsonObjectKeys(fixture),
    );

    expect(first).toBe(reordered);
    expect(first.endsWith("\n")).toBe(true);
    expect(parseIntentCachePromotionEvidenceJsonl(first).cases).toEqual([]);

    const result = evaluateIntentCachePromotionEvidence(first);
    expect(result.qualified).toBe(false);
    expect(result.report.gateReasons).toContain("INSUFFICIENT_OPERATION_HITS");
    expect("qualification" in result).toBe(false);
  });

  it("rejects fields that could smuggle candidate payloads", () => {
    const fixture = emptyPromotionFixture();
    const privateCandidate = "PRIVATE_CANDIDATE_MUST_NOT_LEAVE_HOST";

    expect(() =>
      exportIntentCachePromotionEvidenceJsonl({
        ...fixture,
        binding: { ...fixture.binding, candidatePayload: privateCandidate },
      }),
    ).toThrow();
  });
});

function emptyPromotionFixture() {
  const digest = (character: string) =>
    `sha256:${character.repeat(64)}` as const;
  const dependency = (id: string, character: string) => ({
    status: "enabled" as const,
    artifact: { id, version: "1", digest: digest(character) },
  });
  const binding: Record<string, unknown> = {
    schema: "semwitness.dev/intent-cache-promotion-evidence/v1alpha1",
    kind: "binding",
    artifact: {
      id: "semwitness-intent-cache-promotion-evidence",
      version: "1",
    },
    provenance: "host-attested-unsigned",
    evidenceAuthentication: "none",
    activationCeiling: "shadow-only",
    mode: "shadow",
    tier: "plan",
    qualifiedOperation: {
      operation: `hmac-sha256:operation:${"1".repeat(64)}`,
      domain: `hmac-sha256:intent-domain:${"2".repeat(64)}`,
      effect: "read",
    },
    scope: {
      cacheNamespace: `hmac-sha256:cache-namespace:${"3".repeat(64)}`,
      tenant: `hmac-sha256:tenant:${"4".repeat(64)}`,
      deploymentScopeDigest: digest("5"),
    },
    validity: {
      notBeforeEpochMs: 1,
      notAfterEpochMs: 2,
      revocationId: `hmac-sha256:revocation:${"6".repeat(64)}`,
    },
    intentContract: {
      intentIrSchema: "semwitness.dev/intent-ir/v1alpha1",
      ontology: { id: "ontology", version: "1", digest: digest("7") },
      normalizer: {
        id: "normalizer",
        version: "1",
        artifactDigest: digest("8"),
        configDigest: digest("9"),
      },
      operationRegistry: {
        id: "operation-registry",
        version: "1",
        digest: digest("a"),
      },
      resolver: { id: "resolver", version: "1", digest: digest("b") },
      normalizationPolicyDigest: digest("c"),
      cacheAdmissionPolicyDigest: digest("d"),
      sourceHmacKeyVersionDigest: digest("e"),
    },
    dependencies: {
      prompt: dependency("prompt", "1"),
      tool: dependency("tool", "2"),
      planner: dependency("planner", "3"),
      provider: dependency("provider", "4"),
      model: dependency("model", "5"),
      output: dependency("output", "6"),
      safety: dependency("safety", "7"),
      personalization: dependency("personalization", "8"),
      determinism: dependency("determinism", "9"),
      tokenizer: dependency("tokenizer", "a"),
      embedding: dependency("embedding", "b"),
      candidateIndex: dependency("candidate-index", "c"),
      store: dependency("store", "d"),
      recordAuthentication: dependency("record-authentication", "e"),
      freshness: dependency("freshness", "f"),
      invalidation: dependency("invalidation", "0"),
      key: dependency("key", "1"),
    },
    population: {
      populationFrameDigest: digest("2"),
      corpusDigest: digestIntentCachePromotionPopulationCorpus([]),
      sourceLogRootDigest: digest("3"),
      samplingProtocolDigest: digest("4"),
      inclusionPolicyDigest: digest("5"),
      samplingWindowDigest: digest("6"),
      independenceUnit: "cluster",
      attempted: 0,
      emitted: 0,
      dropped: 0,
      complete: 0,
      failed: 0,
    },
    adversarial: {
      corpusDigest: digestIntentCachePromotionAdversarialCorpus([]),
      coverageDigest: digest("7"),
      expected: 0,
      emitted: 0,
      complete: 0,
      failed: 0,
    },
    evaluation: {
      split: "held-out",
      evaluationProtocolDigest: digest("8"),
      evaluatorDigest: digest("9"),
      oracleDigest: digest("a"),
      accountingContractDigest: digest("b"),
      costModel: { id: "cost-model", version: "1", digest: digest("c") },
      currencyUnitDigest: digest("d"),
    },
    bindingDigest: digest("0"),
  };
  binding.bindingDigest =
    recomputeIntentCachePromotionEvidenceBindingDigest(binding);
  return { binding, cases: [] };
}

function reverseJsonObjectKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(reverseJsonObjectKeys);
  if (value === null || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value as Readonly<Record<string, unknown>>)
      .reverse()
      .map(([key, entry]) => [key, reverseJsonObjectKeys(entry)]),
  );
}
