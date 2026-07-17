import { createHash } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  AgenticSdlcQualificationRunner,
  HmacAgenticSdlcQualificationAuthenticator,
  NodeAgenticSdlcQualificationBoundary,
  type AgenticSdlcQualificationBoundary,
  type AgenticSdlcQualificationBoundaryRequest,
  type AgenticSdlcQualificationBoundaryResult,
  type QualificationExecFile,
} from "../src/index.js";

const temporaryRoots: string[] = [];

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

describe("NodeAgenticSdlcQualificationBoundary", () => {
  it("uses execFile with shell disabled and preserves the fixed argv", async () => {
    let captured:
      | {
          file: string;
          args: string[];
          options: Parameters<QualificationExecFile>[2];
        }
      | undefined;
    const boundary = new NodeAgenticSdlcQualificationBoundary(((
      file,
      args,
      options,
      callback,
    ) => {
      captured = { file, args, options };
      callback(null, "{}", "");
    }) as QualificationExecFile);
    const controller = new AbortController();
    const request: AgenticSdlcQualificationBoundaryRequest = {
      executablePath: process.execPath,
      argv: ["plugin.mjs", "task", "start", "--json"],
      cwd: process.cwd(),
      environment: {},
      timeoutMs: 100,
      maxOutputBytes: 1_024,
      signal: controller.signal,
      shell: false,
    };

    await expect(boundary.execute(request)).resolves.toEqual({
      stdout: "{}",
      stderr: "",
    });
    expect(captured).toMatchObject({
      file: process.execPath,
      args: ["plugin.mjs", "task", "start", "--json"],
      options: { shell: false, encoding: "utf8", windowsHide: true },
    });
  });
});

describe("AgenticSdlcQualificationRunner", () => {
  it("proves exact route-contract-outcome equivalence in both orders", async () => {
    const harness = createHarness();
    const result = await harness.runner.run(
      qualificationCase({
        roots: harness.roots,
        baselineIntent: routeIntent("implement_story", "ST-Q-001"),
        candidateIntent: routeIntent("start_implementation", "ST-Q-001"),
        expectation: { relation: "equivalent" },
      }),
    );

    expect(result).toMatchObject({
      status: "passed",
      reasons: [],
      repeatable: true,
      equivalentChannels: {
        route: true,
        contract: true,
        outcome: true,
      },
    });
    expect(harness.boundary.requests).toHaveLength(4);
    for (const request of harness.boundary.requests) {
      expect(request.shell).toBe(false);
      expect(request.argv.slice(1, 3)).toEqual(["task", "start"]);
      expect(request.argv).toContain("--intent-json");
      expect(request.argv).not.toContain("--confirm-start");
      expect(request.argv).not.toContain("--authorization");
      expect(request.argv).not.toContain("--text");
    }
    const evidence = JSON.stringify(result);
    expect(evidence).not.toContain("ST-Q-001");
    expect(evidence).not.toContain("implement_story");
    expect(evidence).not.toContain(harness.root);
    expect(result.observations.abBaseline.observationDigest).toMatch(
      /^hmac-sha256:qualification-observation:[a-f0-9]{64}$/u,
    );
  });

  it("accepts a declared contract discriminator while route and outcome match", async () => {
    const harness = createHarness();
    const result = await harness.runner.run(
      qualificationCase({
        roots: harness.roots,
        baselineIntent: routeIntent("implement_story", "ST-Q-001"),
        candidateIntent: routeIntent("implement_story", "ST-Q-002"),
        expectation: {
          relation: "different",
          mustDifferAnyOf: ["contract"],
        },
      }),
    );

    expect(result).toMatchObject({
      status: "passed",
      reasons: [],
      equivalentChannels: {
        route: true,
        contract: false,
        outcome: true,
      },
    });
  });

  it("runs the candidate-first pair first for BA while preserving canonical observations", async () => {
    const harness = createHarness();
    const result = await harness.runner.run(
      qualificationCase({
        roots: harness.roots,
        primaryOrder: "BA",
        baselineIntent: routeIntent("implement_story", "ST-Q-001"),
        candidateIntent: routeIntent("implement_story", "ST-Q-002"),
        expectation: {
          relation: "different",
          mustDifferAnyOf: ["contract"],
        },
      }),
    );

    expect(harness.boundary.requests.map((request) => request.cwd)).toEqual([
      realpathSync(harness.roots.candidateFirst.candidate),
      realpathSync(harness.roots.candidateFirst.baseline),
      realpathSync(harness.roots.baselineFirst.baseline),
      realpathSync(harness.roots.baselineFirst.candidate),
    ]);
    expect(result.primaryOrder).toBe("BA");
    expect(result.observations.baCandidate.contractDigest).toBe(
      result.observations.abCandidate.contractDigest,
    );
    expect(result.observations.baBaseline.contractDigest).toBe(
      result.observations.abBaseline.contractDigest,
    );
    expect(result.observations.abBaseline.contractDigest).not.toBe(
      result.observations.abCandidate.contractDigest,
    );
  });

  it("fails an equivalence claim when only the selected contract changes", async () => {
    const harness = createHarness();
    const result = await harness.runner.run(
      qualificationCase({
        roots: harness.roots,
        baselineIntent: routeIntent("implement_story", "ST-Q-001"),
        candidateIntent: routeIntent("implement_story", "ST-Q-002"),
        expectation: { relation: "equivalent" },
      }),
    );

    expect(result.status).toBe("failed");
    expect(result.reasons).toContain("SEMANTIC_DIVERGENCE");
  });

  it("fails closed when an arm depends on execution order", async () => {
    const harness = createHarness({
      transformOutput(output, call) {
        return call === 4 ? { ...output, status: "ready_to_execute" } : output;
      },
    });
    const result = await harness.runner.run(
      qualificationCase({
        roots: harness.roots,
        baselineIntent: routeIntent("implement_story", "ST-Q-001"),
        candidateIntent: routeIntent("start_implementation", "ST-Q-001"),
        expectation: { relation: "equivalent" },
      }),
    );

    expect(result.status).toBe("failed");
    expect(result.repeatable).toBe(false);
    expect(result.reasons).toContain("ORDER_EFFECT");
  });

  it("rejects a child that mutates the isolated project", async () => {
    const harness = createHarness({
      onExecute(request, call) {
        if (call === 1) {
          writeFileSync(join(request.cwd, ".sdlc", "mutation.json"), "{}");
        }
      },
    });

    await expect(
      harness.runner.run(
        qualificationCase({
          roots: harness.roots,
          baselineIntent: routeIntent("implement_story", "ST-Q-001"),
          candidateIntent: routeIntent("start_implementation", "ST-Q-001"),
          expectation: { relation: "equivalent" },
        }),
      ),
    ).rejects.toMatchObject({ code: "PROJECT_MUTATED" });
  });

  it("enforces host timeout and output bounds around injected boundaries", async () => {
    const timed = createHarness({ neverResolve: true, timeoutMs: 20 });
    await expect(
      timed.runner.run(
        qualificationCase({
          roots: timed.roots,
          baselineIntent: routeIntent("implement_story", "ST-Q-001"),
          candidateIntent: routeIntent("start_implementation", "ST-Q-001"),
          expectation: { relation: "equivalent" },
        }),
      ),
    ).rejects.toMatchObject({ code: "TIMEOUT" });

    const oversized = createHarness({ oversized: true, maxOutputBytes: 1_024 });
    await expect(
      oversized.runner.run(
        qualificationCase({
          roots: oversized.roots,
          baselineIntent: routeIntent("implement_story", "ST-Q-001"),
          candidateIntent: routeIntent("start_implementation", "ST-Q-001"),
          expectation: { relation: "equivalent" },
        }),
      ),
    ).rejects.toMatchObject({ code: "OUTPUT_LIMIT" });
  });

  it("rejects a mismatched CLI version without exposing its output", async () => {
    const harness = createHarness({ sdlcVersion: "0.9.1" });
    await expect(
      harness.runner.run(
        qualificationCase({
          roots: harness.roots,
          baselineIntent: routeIntent("implement_story", "ST-Q-001"),
          candidateIntent: routeIntent("start_implementation", "ST-Q-001"),
          expectation: { relation: "equivalent" },
        }),
      ),
    ).rejects.toMatchObject({ code: "MALFORMED_OUTPUT" });
  });

  it("rejects accessors at each input envelope without invoking them", async () => {
    const harness = createHarness();
    let reads = 0;
    const createInput = () =>
      qualificationCase({
        roots: harness.roots,
        baselineIntent: routeIntent("implement_story", "ST-Q-001"),
        candidateIntent: routeIntent("start_implementation", "ST-Q-001"),
        expectation: { relation: "equivalent" },
      });

    const topLevel = createInput();
    Object.defineProperty(topLevel, "caseRef", {
      enumerable: true,
      get() {
        reads += 1;
        return `hmac-sha256:qualification-case:${"a".repeat(64)}`;
      },
    });

    const workspaceBase = createInput();
    const workspace = { ...workspaceBase.workspaceRoots };
    Object.defineProperty(workspace, "baselineFirst", {
      enumerable: true,
      get() {
        reads += 1;
        return workspaceBase.workspaceRoots.baselineFirst;
      },
    });
    const workspaceInput = { ...workspaceBase, workspaceRoots: workspace };

    const expectationBase = createInput();
    const expectation = {};
    Object.defineProperty(expectation, "relation", {
      enumerable: true,
      get() {
        reads += 1;
        return "equivalent";
      },
    });
    const expectationInput = { ...expectationBase, expectation };

    for (const malicious of [topLevel, workspaceInput, expectationInput]) {
      await expect(
        harness.runner.run(malicious as never),
      ).rejects.toMatchObject({ code: "INVALID_INPUT" });
    }
    expect(reads).toBe(0);
    expect(harness.boundary.requests).toHaveLength(0);
  });

  it("rejects proxies at each input envelope without invoking traps", async () => {
    const harness = createHarness();
    let traps = 0;
    const handler: ProxyHandler<object> = {
      get() {
        traps += 1;
        throw new Error("proxy get trap must not run");
      },
      getOwnPropertyDescriptor() {
        traps += 1;
        throw new Error("proxy descriptor trap must not run");
      },
      getPrototypeOf() {
        traps += 1;
        throw new Error("proxy prototype trap must not run");
      },
      ownKeys() {
        traps += 1;
        throw new Error("proxy ownKeys trap must not run");
      },
    };
    const createInput = () =>
      qualificationCase({
        roots: harness.roots,
        baselineIntent: routeIntent("implement_story", "ST-Q-001"),
        candidateIntent: routeIntent("start_implementation", "ST-Q-001"),
        expectation: { relation: "equivalent" },
      });

    const topLevel = new Proxy(createInput(), handler);
    const workspaceBase = createInput();
    const workspaceInput = {
      ...workspaceBase,
      workspaceRoots: new Proxy(workspaceBase.workspaceRoots, handler),
    };
    const expectationBase = createInput();
    const expectationInput = {
      ...expectationBase,
      expectation: new Proxy(expectationBase.expectation, handler),
    };

    for (const malicious of [topLevel, workspaceInput, expectationInput]) {
      await expect(
        harness.runner.run(malicious as never),
      ).rejects.toMatchObject({ code: "INVALID_INPUT" });
    }
    expect(traps).toBe(0);
    expect(harness.boundary.requests).toHaveLength(0);
  });

  it("rejects unknown envelope fields before execution", async () => {
    const harness = createHarness();
    const base = qualificationCase({
      roots: harness.roots,
      baselineIntent: routeIntent("implement_story", "ST-Q-001"),
      candidateIntent: routeIntent("start_implementation", "ST-Q-001"),
      expectation: { relation: "equivalent" },
    });
    const inputs = [
      { ...base, unknown: true },
      {
        ...base,
        workspaceRoots: { ...base.workspaceRoots, unknown: true },
      },
      { ...base, expectation: { ...base.expectation, unknown: true } },
    ];

    for (const malicious of inputs) {
      await expect(
        harness.runner.run(malicious as never),
      ).rejects.toMatchObject({ code: "INVALID_INPUT" });
    }
    expect(harness.boundary.requests).toHaveLength(0);
  });

  it("rejects sparse and extended discriminator arrays", async () => {
    const harness = createHarness();
    const base = qualificationCase({
      roots: harness.roots,
      baselineIntent: routeIntent("implement_story", "ST-Q-001"),
      candidateIntent: routeIntent("implement_story", "ST-Q-002"),
      expectation: {
        relation: "different",
        mustDifferAnyOf: ["contract"],
      },
    });
    const sparse: unknown[] = [];
    sparse.length = 1;
    const extended: unknown[] = ["contract"];
    Object.defineProperty(extended, "extra", {
      enumerable: true,
      value: "route",
    });

    for (const mustDifferAnyOf of [sparse, extended]) {
      await expect(
        harness.runner.run({
          ...base,
          expectation: { relation: "different", mustDifferAnyOf },
        } as never),
      ).rejects.toMatchObject({ code: "INVALID_INPUT" });
    }
    expect(harness.boundary.requests).toHaveLength(0);
  });
});

class FakeBoundary implements AgenticSdlcQualificationBoundary {
  readonly requests: AgenticSdlcQualificationBoundaryRequest[] = [];
  readonly #options: HarnessOptions;

  constructor(options: HarnessOptions) {
    this.#options = options;
  }

  async execute(
    request: AgenticSdlcQualificationBoundaryRequest,
  ): Promise<AgenticSdlcQualificationBoundaryResult> {
    this.requests.push(request);
    const call = this.requests.length;
    this.#options.onExecute?.(request, call);
    if (this.#options.neverResolve === true) {
      return await new Promise(() => undefined);
    }
    if (this.#options.oversized === true) {
      return { stdout: "x".repeat(2_048), stderr: "" };
    }
    const intentIndex = request.argv.indexOf("--intent-json");
    const intent = JSON.parse(request.argv[intentIndex + 1] ?? "null") as {
      referenced_entities: { id?: string; identifier?: string }[];
    };
    const storyId =
      intent.referenced_entities[0]?.id ??
      intent.referenced_entities[0]?.identifier ??
      "ST-Q-001";
    const contractId = `contract-${storyId}-implementation`;
    const output = taskStartOutput(
      storyId,
      contractId,
      this.#options.sdlcVersion ?? "0.9.0",
    );
    return {
      stdout: JSON.stringify(
        this.#options.transformOutput?.(output, call) ?? output,
      ),
      stderr: "",
    };
  }
}

interface HarnessOptions {
  readonly maxOutputBytes?: number;
  readonly neverResolve?: boolean;
  readonly onExecute?: (
    request: AgenticSdlcQualificationBoundaryRequest,
    call: number,
  ) => void;
  readonly oversized?: boolean;
  readonly sdlcVersion?: string;
  readonly timeoutMs?: number;
  readonly transformOutput?: (
    output: ReturnType<typeof taskStartOutput>,
    call: number,
  ) => ReturnType<typeof taskStartOutput>;
}

function createHarness(options: HarnessOptions = {}) {
  const root = mkdtempSync(join(tmpdir(), "intentabi-qualification-"));
  temporaryRoots.push(root);
  const entrypointPath = join(root, "agentic-sdlc.mjs");
  writeFileSync(entrypointPath, "// deterministic fixture entrypoint\n");
  const roots = ["ab-a", "ab-b", "ba-b", "ba-a"].map((name) => {
    const fixtureRoot = join(root, name);
    const contracts = join(fixtureRoot, ".sdlc", "contracts");
    mkdirSync(contracts, { recursive: true });
    writeFileSync(join(fixtureRoot, ".sdlc", "project.json"), "{}\n");
    writeFileSync(
      join(contracts, "contract-ST-Q-001-implementation.json"),
      '{"id":"contract-ST-Q-001-implementation","story":"ST-Q-001"}\n',
    );
    writeFileSync(
      join(contracts, "contract-ST-Q-002-implementation.json"),
      '{"id":"contract-ST-Q-002-implementation","story":"ST-Q-002"}\n',
    );
    return fixtureRoot;
  });
  const boundary = new FakeBoundary(options);
  const runner = new AgenticSdlcQualificationRunner({
    entrypointPath,
    expectedEntrypointDigest: sha256(readFileSync(entrypointPath)),
    expectedSdlcVersion: "0.9.0",
    timeoutMs: options.timeoutMs ?? 1_000,
    maxOutputBytes: options.maxOutputBytes ?? 16_384,
    authenticator: new HmacAgenticSdlcQualificationAuthenticator({
      keyId: "test-key-v1",
      secret: "qualification-test-secret-material-32-bytes",
    }),
    boundary,
    environment: {
      PATH: process.env.PATH,
      INTENTABI_PRIVATE_SECRET: "must-not-cross",
    },
    blockedEnvironmentKeys: ["INTENTABI_PRIVATE_SECRET"],
  });
  return {
    root,
    roots: {
      baselineFirst: { baseline: roots[0]!, candidate: roots[1]! },
      candidateFirst: { candidate: roots[2]!, baseline: roots[3]! },
    },
    boundary,
    runner,
  };
}

function qualificationCase(input: {
  roots: ReturnType<typeof createHarness>["roots"];
  primaryOrder?: "AB" | "BA";
  baselineIntent: ReturnType<typeof routeIntent>;
  candidateIntent: ReturnType<typeof routeIntent>;
  expectation:
    | { relation: "equivalent" }
    | {
        relation: "different";
        mustDifferAnyOf: ["route" | "contract" | "outcome"];
      };
}) {
  return {
    caseRef: `hmac-sha256:qualification-case:${"a".repeat(64)}` as const,
    primaryOrder: input.primaryOrder ?? ("AB" as const),
    baselineIntent: input.baselineIntent,
    candidateIntent: input.candidateIntent,
    expectation: input.expectation,
    workspaceRoots: input.roots,
  };
}

function routeIntent(requestedAction: string, storyId: string) {
  return {
    requested_action: requestedAction,
    confidence: 1,
    referenced_entities: [{ type: "story", id: storyId }],
    provided_artifacts: [],
    missing_context: [],
    proposed_phase: "implementation",
    artifact_type: null,
    skip_phases: [],
  };
}

function taskStartOutput(
  storyId: string,
  contractId: string,
  sdlcVersion: string,
) {
  return {
    sdlc_version: sdlcVersion,
    status: "needs_user_input",
    execution_allowed: false,
    route: "claim_and_implement",
    phase: "implementation",
    story_id: storyId,
    contract_id: contractId,
    contract_action: "confirm_start",
    requires_confirmation: true,
    blocking_reasons: ["route_requires_confirmation"],
    contract: {
      id: contractId,
      phase: "implementation",
      story_id: storyId,
      status: "approved",
      approved: true,
      readiness_gaps: [],
      freshness_gaps: [],
      path: `.sdlc/contracts/${contractId}.json`,
    },
    route_decision: {
      route: "claim_and_implement",
      status: "needs_confirmation",
      requires_confirmation: true,
      blocking_reasons: [],
      deterministic_checks: [
        { check: "canonical_intent", status: "passed", details: "ignored" },
        { check: "story_contract_approved", status: "passed" },
      ],
    },
  };
}

function sha256(value: Uint8Array) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}` as const;
}
