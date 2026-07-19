import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";
import {
  ConsensusIntentCompiler,
  DeclarativeIntentNormalizer,
  type IntentCompilerResult,
  type IntentProposalCompiler,
} from "semwitness/intent";
import {
  evaluateIntentCachePromotionEvidence,
  parseIntentCachePromotionEvidenceJsonl,
} from "semwitness/intent/host";

import {
  SEMWITNESS_INTENT_INSPECTOR_IMPLEMENTATION,
  SemWitnessIntentInspector,
  exportIntentCachePromotionEvidenceJsonl,
} from "../src/index.js";
import { createEmptyPromotionFixture } from "./support/promotion-fixture.js";

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

function digest(value: string): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}

function fixedCompiler(
  id: string,
  result: IntentCompilerResult | (() => IntentCompilerResult),
): IntentProposalCompiler {
  const registry = new DeclarativeIntentNormalizer(registrySource);
  return Object.freeze({
    manifest: Object.freeze({
      normalizer: Object.freeze({
        id,
        version: "1.0.0",
        artifactDigest: digest(`${id}-artifact`),
        configDigest: digest(`${id}-config`),
      }),
      ontology: registry.ontology,
    }),
    compile: () => (typeof result === "function" ? result() : result),
  });
}

function externalInspector(
  compiler: IntentProposalCompiler,
  source = registrySource,
): SemWitnessIntentInspector {
  return new SemWitnessIntentInspector({
    registrySource: source,
    compiler,
    policyDigest: `sha256:${"b".repeat(64)}`,
    hmacSecret: secret,
    expectedScope: scope,
    routeBindings: { "read-project-status": routeInput },
  });
}

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
  it("keeps the public implementation binding aligned with the pinned dependency", () => {
    const manifest = JSON.parse(
      readFileSync(new URL("../package.json", import.meta.url), "utf8"),
    );
    const dependency = String(manifest.dependencies?.semwitness ?? "");
    const revision = /#([a-f0-9]{40})$/u.exec(dependency)?.[1];

    expect(revision).toBeDefined();
    if (revision === undefined) throw new Error("dependency revision missing");
    expect(SEMWITNESS_INTENT_INSPECTOR_IMPLEMENTATION).toContain(
      "semwitness-intent-inspector/v2+",
    );
    expect(SEMWITNESS_INTENT_INSPECTOR_IMPLEMENTATION.endsWith(revision)).toBe(
      true,
    );
  });

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

  it("accepts an external compiler proposal while the declarative registry remains authoritative", async () => {
    const source = "Could you give me the current project status?";
    const compiler = fixedCompiler("external-project-intent", {
      status: "proposed",
      operationId: "read-project-status",
      confidencePpm: 1_000_000,
      ambiguous: false,
    });
    const external = externalInspector(compiler);

    const result = await external.inspect(inspectionRequest(source));
    const baseline = await inspector.inspect(inspectionRequest(source));

    expect(result).toMatchObject({ status: "eligible", effect: "read" });
    expect(baseline).toMatchObject({
      status: "bypass",
      reasons: ["INTENT_NO_MATCH"],
    });
    expect(result.bindingDigest).not.toBe(baseline.bindingDigest);
  });

  it("binds registry configuration independently from the compiler manifest", async () => {
    const compiler = fixedCompiler("registry-binding-probe", {
      status: "proposed",
      operationId: "read-project-status",
      confidencePpm: 1_000_000,
      ambiguous: false,
    });
    const document = JSON.parse(registrySource) as {
      operations: Array<{ aliases: Array<{ locale: string; text: string }> }>;
    };
    document.operations[0]!.aliases.push({
      locale: "en-US",
      text: "Read this project's status.",
    });
    const first = await externalInspector(compiler).inspect(
      inspectionRequest("Show the current Agentic SDLC project status."),
    );
    const second = await externalInspector(
      compiler,
      JSON.stringify(document),
    ).inspect(
      inspectionRequest("Show the current Agentic SDLC project status."),
    );

    expect(first.status).toBe("eligible");
    expect(second.status).toBe("eligible");
    expect(first.bindingDigest).not.toBe(second.bindingDigest);
  });

  it("rejects accessor-bearing compiler manifests without invoking them", () => {
    let invoked = false;
    const hostile = Object.defineProperty(
      { compile: () => ({ status: "bypass", reason: "INTENT_NO_MATCH" }) },
      "manifest",
      {
        enumerable: true,
        get: () => {
          invoked = true;
          throw new Error("private manifest getter");
        },
      },
    ) as unknown as IntentProposalCompiler;

    expect(() => externalInspector(hostile)).toThrow(
      "SemWitness intent compiler is invalid",
    );
    expect(invoked).toBe(false);
  });

  it("fails closed on compiler exceptions, malformed output, disagreement, unknown operations and effects", async () => {
    const throwing = fixedCompiler("throwing-project-intent", () => {
      throw new Error("private compiler failure");
    });
    const malformed = fixedCompiler("malformed-project-intent", {
      status: "proposed",
      operationId: "read-project-status",
      confidencePpm: 1_000_000,
      ambiguous: false,
      unauthorized: true,
    } as unknown as IntentCompilerResult);
    const disagreement = new ConsensusIntentCompiler({
      members: [
        fixedCompiler("read-project-intent", {
          status: "proposed",
          operationId: "read-project-status",
          confidencePpm: 1_000_000,
          ambiguous: false,
        }),
        fixedCompiler("delete-project-intent", {
          status: "proposed",
          operationId: "delete-project",
          confidencePpm: 1_000_000,
          ambiguous: false,
        }),
      ],
      policy: { strategy: "all-agree", maxCandidateEvidence: 4 },
    });
    const unknown = fixedCompiler("unknown-project-intent", {
      status: "proposed",
      operationId: "unknown-operation",
      confidencePpm: 1_000_000,
      ambiguous: false,
    });
    const irreversible = fixedCompiler("irreversible-project-intent", {
      status: "proposed",
      operationId: "delete-project",
      confidencePpm: 1_000_000,
      ambiguous: false,
    });

    await expect(
      externalInspector(throwing).inspect(inspectionRequest("private source")),
    ).resolves.toMatchObject({
      status: "bypass",
      reasons: ["INTENT_COMPILER_FAILURE"],
    });
    await expect(
      externalInspector(malformed).inspect(inspectionRequest("private source")),
    ).resolves.toMatchObject({
      status: "bypass",
      reasons: ["INTENT_COMPILER_FAILURE"],
    });
    await expect(
      externalInspector(disagreement).inspect(
        inspectionRequest("ambiguous source"),
      ),
    ).resolves.toMatchObject({
      status: "bypass",
      reasons: ["INTENT_AMBIGUOUS"],
    });
    await expect(
      externalInspector(unknown).inspect(inspectionRequest("unknown source")),
    ).resolves.toMatchObject({
      status: "bypass",
      reasons: ["INTENT_REGISTRY_MISMATCH"],
    });
    await expect(
      externalInspector(irreversible).inspect(
        inspectionRequest("destructive source"),
      ),
    ).resolves.toMatchObject({
      status: "bypass",
      reasons: ["EFFECT_NOT_SHADOW_ELIGIBLE"],
    });
  });
});

describe("SemWitness promotion evidence exporter", () => {
  it("emits deterministic JSONL accepted by the real fail-closed evaluator", () => {
    const fixture = createEmptyPromotionFixture();
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
    const fixture = createEmptyPromotionFixture();
    const privateCandidate = "PRIVATE_CANDIDATE_MUST_NOT_LEAVE_HOST";

    expect(() =>
      exportIntentCachePromotionEvidenceJsonl({
        ...fixture,
        binding: { ...fixture.binding, candidatePayload: privateCandidate },
      }),
    ).toThrow();
  });
});

function reverseJsonObjectKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(reverseJsonObjectKeys);
  if (value === null || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value as Readonly<Record<string, unknown>>)
      .reverse()
      .map(([key, entry]) => [key, reverseJsonObjectKeys(entry)]),
  );
}
