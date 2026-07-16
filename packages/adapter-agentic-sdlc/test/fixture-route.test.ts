import { copyFileSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  AgenticSdlcCliRoute,
  AgenticSdlcRouteError,
  FixtureAgenticSdlcRoute,
} from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const root = realpathSync(resolve(here, "../../.."));
const fixtureEntrypoint = resolve(
  here,
  "../../../fixtures/agentic-sdlc-cli-fixture.mjs",
);
const deploymentRevisionDigest = `sha256:${"a".repeat(64)}` as const;
const fixture = JSON.stringify({
  schema: "io.github.aantenore.intentabi/agentic-sdlc-fixture/v1alpha1",
  routeId: "agentic-sdlc.fixture",
  cases: [
    {
      input: { command: "status", project: "demo" },
      output: { phase: "implementation", source: "ordinary-route" },
    },
  ],
});

describe("AgenticSdlcCliRoute", () => {
  it("constructs a fixed, read-only route-decide invocation", async () => {
    const route = createRoute();

    const result = await route.execute({ root, intent: routeIntent() });

    const child = JSON.parse(result.stdout);
    expect(child.args.slice(0, 2)).toEqual(["route", "decide"]);
    expect(child.args).toContain("--intent-json");
    expect(child.args).not.toContain("--text");
    expect(child.hmacSecret).toBeNull();
    expect(result.stderr).toBe("");
  });

  it("accepts the current Agentic SDLC object entity and artifact contract", async () => {
    const route = createRoute();

    const result = await route.execute({
      root,
      intent: routeIntent({
        referenced_entities: [{ type: "story", id: "ST-001" }],
        provided_artifacts: [{ type: "baseline", id: "BASELINE-001" }],
        missing_context: [{ question: "Which environment" }],
      }),
    });

    const intent = childIntent(result.stdout);
    expect(intent.referenced_entities).toEqual([
      { type: "story", id: "ST-001" },
    ]);
    expect(intent.provided_artifacts).toEqual([
      { type: "baseline", id: "BASELINE-001" },
    ]);
  });

  it("rejects arbitrary or mutating command arguments", async () => {
    const route = createRoute();

    await expect(
      route.execute({ args: ["archive", "closed", "--apply"] } as never),
    ).rejects.toThrow();
    await expect(
      route.execute({ root, intent: routeIntent(), apply: true } as never),
    ).rejects.toThrow();
  });

  it("redacts nonzero child errors including canonical intent content", async () => {
    const route = createRoute();
    const secretMarker = "SUPER_SECRET_MARKER";

    const promise = route.execute({
      root,
      intent: routeIntent({
        requested_action: "fixture_fail",
        referenced_entities: [{ type: "story", id: secretMarker }],
      }),
    });

    await expect(promise).rejects.toMatchObject({
      name: "AgenticSdlcRouteError",
      code: "EXECUTION_FAILED",
    });
    await promise.catch((error: unknown) => {
      expect(error).toBeInstanceOf(AgenticSdlcRouteError);
      expect(String(error)).not.toContain(secretMarker);
    });
  });

  it("classifies timeout and output overflow without child output leakage", async () => {
    await expect(
      createRoute({ timeoutMs: 20 }).execute({
        root,
        intent: routeIntent({ requested_action: "fixture_timeout" }),
      }),
    ).rejects.toMatchObject({ code: "TIMEOUT" });
    await expect(
      createRoute({ maxOutputBytes: 1_024 }).execute({
        root,
        intent: routeIntent({ requested_action: "fixture_overflow" }),
      }),
    ).rejects.toMatchObject({ code: "OUTPUT_LIMIT" });
  });

  it("snapshots validated options instead of retaining a mutable reference", async () => {
    const options = routeOptions();
    const route = new AgenticSdlcCliRoute(options);
    (options as { entrypointPath: string }).entrypointPath = "relative.mjs";

    await expect(
      route.execute({ root, intent: routeIntent() }),
    ).resolves.toMatchObject({ exitCode: 0 });
  });

  it("runs an entrypoint whose filesystem path contains spaces", async () => {
    const directory = mkdtempSync(join(tmpdir(), "intentabi space "));
    const copied = join(directory, "agentic fixture.mjs");
    copyFileSync(fixtureEntrypoint, copied);
    try {
      const route = new AgenticSdlcCliRoute({
        ...routeOptions(),
        entrypointPath: copied,
      });
      await expect(
        route.execute({ root, intent: routeIntent() }),
      ).resolves.toMatchObject({ exitCode: 0 });
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});

function createRoute(overrides: Partial<ReturnType<typeof routeOptions>> = {}) {
  return new AgenticSdlcCliRoute({ ...routeOptions(), ...overrides });
}

function routeOptions() {
  return {
    entrypointPath: fixtureEntrypoint,
    allowedRoot: root,
    deploymentRevisionDigest,
    timeoutMs: 1_000,
    maxOutputBytes: 4_096,
    environment: {
      PATH: process.env.PATH,
      INTENTABI_HMAC_SECRET: "must-not-reach-child",
    },
    blockedEnvironmentKeys: ["INTENTABI_HMAC_SECRET"],
  };
}

function childIntent(stdout: string) {
  const child = JSON.parse(stdout) as { args: string[] };
  const index = child.args.indexOf("--intent-json");
  return JSON.parse(child.args[index + 1] ?? "null");
}

function routeIntent(
  overrides: Partial<ReturnType<typeof baseRouteIntent>> = {},
) {
  return { ...baseRouteIntent(), ...overrides };
}

function baseRouteIntent() {
  return {
    requested_action: "technical_analysis",
    confidence: 1,
    referenced_entities: [] as { type: string; id: string }[],
    provided_artifacts: [] as { type: string; id: string }[],
    missing_context: [] as ({ question: string } | string)[],
    proposed_phase: "analysis",
    artifact_type: "technical-analysis",
    skip_phases: [] as string[],
  };
}

describe("FixtureAgenticSdlcRoute", () => {
  it("executes the ordinary route fixture", async () => {
    const route = new FixtureAgenticSdlcRoute(fixture);

    const result = await route.execute({ project: "demo", command: "status" });

    expect(result).toEqual({
      phase: "implementation",
      source: "ordinary-route",
    });
    expect(route.executionCount()).toBe(1);
    expect(route.revisionDigest).toMatch(/^sha256:[a-f0-9]{64}$/u);
  });

  it("strictly rejects unknown fixture fields", () => {
    expect(
      () =>
        new FixtureAgenticSdlcRoute(
          JSON.stringify({ ...JSON.parse(fixture), activeCache: true }),
        ),
    ).toThrow();
  });
});
