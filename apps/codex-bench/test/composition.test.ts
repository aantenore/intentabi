import { createHash } from "node:crypto";
import {
  access,
  chmod,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { BenchmarkInvariantFailure } from "@intentabi/benchmark-core";
import type { CodexOptions } from "@openai/codex-sdk";
import { describe, expect, it, vi } from "vitest";

import {
  CodexSdkArmRunner,
  FAIL_CLOSED_CODEX_BASE_URL,
  LOCKED_CODEX_MODEL_POLICY,
  createIsolatedBenchmarkRuntime,
  executeCodexBenchmark,
  parseCodexBenchConfig,
  parseCodexBenchDataset,
  preflightCodexExecutable,
  projectPlatformRuntimeEnvironment,
  projectSdkUsage,
  resolveCodexBenchConfig,
  reserveBenchmarkReceipt,
  scavengeAbandonedCodexArtifacts,
  type CodexClientLike,
  type ExecutablePreflightDependencies,
} from "../src/index.js";

const expectedPlatformEnvironment =
  process.platform === "win32"
    ? { SystemRoot: "/safe/system-root" }
    : ({} as const);

describe("CodexSdkArmRunner", () => {
  it("allocates a constrained total output budget evenly across planned arms", async () => {
    const caps: number[] = [];
    const runner = new CodexSdkArmRunner({
      executablePath: "/not-executed/codex",
      threadOptions: {
        model: "gpt-codex-test",
        workingDirectory: "/isolated/workspace",
      },
      timeoutMs: 10_000,
      apiKey: "codex-api-key-for-test",
      sdkEnvironment: {},
      maxOutputTokensPerCall: 256,
      maxProviderCalls: 2,
      maxTotalOutputTokens: 32,
      maxRunDurationMs: 20_000,
      maxRequestBytes: 65_536,
      maxResponseBytes: 65_536,
      createClient: () => ({
        startThread: () => ({
          run: async () => ({
            items: [],
            finalResponse: "OK",
            usage: null,
          }),
        }),
      }),
      createGateway: async (options) => {
        caps.push(options.maxOutputTokens);
        return {
          baseUrl: "http://127.0.0.1:43123/v1",
          proxyApiKey: "intentabi-proxy-test",
          assertConformant: () => undefined,
          close: async () => undefined,
        };
      },
    });

    await expect(runner.run("FIRST")).resolves.toBeDefined();
    await expect(runner.run("SECOND")).resolves.toBeDefined();
    expect(caps).toEqual([16, 16]);
  });

  it("creates fresh clients with a minimal env and locked tool policy", async () => {
    const starts: string[] = [];
    const optionsSeen: CodexOptions[] = [];
    const closeGateway = vi.fn(async () => undefined);
    const factory = vi.fn((options: CodexOptions): CodexClientLike => {
      optionsSeen.push(options);
      return {
        startThread: vi.fn(() => {
          starts.push("thread");
          return {
            run: vi.fn(async (input) => ({
              items: [],
              finalResponse: `opaque:${input.length}`,
              usage: {
                input_tokens: 10,
                cached_input_tokens: 2,
                output_tokens: 3,
                reasoning_output_tokens: 1,
              },
            })),
          };
        }),
      };
    });
    const runner = new CodexSdkArmRunner({
      executablePath: "/not-executed/codex",
      threadOptions: {
        model: "gpt-codex-test",
        workingDirectory: "/isolated/ephemeral-workspace",
        sandboxMode: "read-only",
        skipGitRepoCheck: false,
        modelReasoningEffort: "medium",
        networkAccessEnabled: false,
        webSearchMode: "disabled",
        webSearchEnabled: false,
        approvalPolicy: "never",
      },
      timeoutMs: 10_000,
      apiKey: "codex-api-key-for-test",
      sdkEnvironment: {
        CODEX_HOME: "/isolated/codex-home",
        HOME: "/isolated/home",
        PATH: "/isolated/bin",
      },
      maxOutputTokensPerCall: 256,
      maxProviderCalls: 2,
      maxTotalOutputTokens: 512,
      maxRunDurationMs: 20_000,
      maxRequestBytes: 1_048_576,
      maxResponseBytes: 1_048_576,
      createClient: factory,
      createGateway: vi.fn(async () => ({
        baseUrl: "http://127.0.0.1:43123/v1",
        proxyApiKey: "intentabi-proxy-test",
        assertConformant: () => undefined,
        close: closeGateway,
      })),
    });

    const baseline = await runner.run("PRIVATE ORIGINAL", {
      caseRef: `hmac-sha256:evidence:${"a".repeat(64)}`,
      arm: "baseline",
    });
    const candidate = await runner.run("PRIVATE CANDIDATE", {
      caseRef: `hmac-sha256:evidence:${"a".repeat(64)}`,
      arm: "candidate",
    });
    await expect(runner.run("PRIVATE THIRD INPUT")).rejects.toBeInstanceOf(
      BenchmarkInvariantFailure,
    );

    expect(factory).toHaveBeenCalledTimes(2);
    expect(starts).toHaveLength(2);
    expect(baseline.usage).toMatchObject({
      provenance: "host-observed-codex-sdk-run-result",
      inputTokens: 10,
    });
    expect(candidate.usage).not.toBeNull();
    expect(optionsSeen[0]).toMatchObject({
      codexPathOverride: "/not-executed/codex",
      apiKey: "intentabi-proxy-test",
      baseUrl: "http://127.0.0.1:43123/v1",
      env: {
        CODEX_HOME: "/isolated/codex-home",
        HOME: "/isolated/home",
        PATH: "/isolated/bin",
      },
    });
    expect(JSON.stringify(optionsSeen)).not.toContain("codex-api-key-for-test");
    expect(closeGateway).toHaveBeenCalledTimes(2);
    expect(optionsSeen[0]?.config).toMatchObject({
      allow_login_shell: false,
      analytics: { enabled: false },
      check_for_update_on_startup: false,
      cli_auth_credentials_store: "ephemeral",
      history: { persistence: "none" },
      orchestrator: {
        mcp: { enabled: false },
        skills: { enabled: false },
      },
      skills: {
        bundled: { enabled: false },
        include_instructions: false,
      },
      include_environment_context: false,
      include_permissions_instructions: false,
      model_provider: "intentabi_benchmark",
      model_providers: {
        intentabi_benchmark: {
          base_url: "http://127.0.0.1:43123/v1",
          env_key: "CODEX_API_KEY",
          supports_websockets: false,
          request_max_retries: 0,
          stream_max_retries: 0,
        },
      },
      notify: [],
      openai_base_url: "http://127.0.0.1:43123/v1",
      shell_environment_policy: {
        inherit: "none",
        experimental_use_profile: false,
        ignore_default_excludes: false,
        set: {},
      },
      features: { shell_tool: false, unified_exec: false },
    });
  });

  it("projects only own data counters without invoking hostile accessors", () => {
    let getterCalls = 0;
    const usage = Object.create({
      inherited_secret: "do-not-copy",
      get inherited_counter() {
        getterCalls += 1;
        return 999;
      },
    }) as Record<string, unknown>;
    Object.defineProperties(usage, {
      input_tokens: { value: 10, enumerable: true },
      cached_input_tokens: { value: 2, enumerable: true },
      output_tokens: { value: 3, enumerable: true },
      reasoning_output_tokens: { value: 1, enumerable: true },
      raw_prompt: {
        enumerable: true,
        get: () => {
          getterCalls += 1;
          return "PRIVATE";
        },
      },
      toJSON: {
        enumerable: true,
        value: () => {
          throw new Error("must not serialize source");
        },
      },
    });

    const projected = projectSdkUsage(usage);

    expect(getterCalls).toBe(0);
    expect(Object.keys(projected ?? {})).toEqual([
      "provenance",
      "inputTokens",
      "cachedInputTokens",
      "outputTokens",
      "reasoningOutputTokens",
    ]);
    expect(JSON.stringify(projected)).not.toContain("PRIVATE");
    expect(JSON.stringify(projected)).not.toContain("raw_prompt");

    const hostileKnownField = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(hostileKnownField, "input_tokens", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return 10;
      },
    });
    expect(projectSdkUsage(hostileKnownField)).toMatchObject({
      inputTokens: -1,
    });
    expect(getterCalls).toBe(0);
  });
});

describe("Codex executable and runtime isolation", () => {
  it("does not delete a different file swapped into a receipt reservation path", async () => {
    const parent = await mkdtemp(join(tmpdir(), "intentabi-receipt-swap-"));
    const path = join(parent, "receipt.json");
    const moved = join(parent, "moved-reservation.json");
    try {
      const reservation = await reserveBenchmarkReceipt(path);
      await rename(path, moved);
      await writeFile(path, "DO NOT DELETE", { mode: 0o600 });

      await reservation.abort();

      expect(await readFile(path, "utf8")).toBe("DO NOT DELETE");
      await expect(access(moved)).resolves.toBeUndefined();
    } finally {
      await rm(parent, { recursive: true, force: true });
    }
  });

  it("scavenges dead private runtime leases without touching a live run", async () => {
    const parent = await mkdtemp(join(tmpdir(), "intentabi-scavenger-test-"));
    const dead = await mkdtemp(join(parent, "intentabi-codex-runtime-"));
    const deadBinary = await mkdtemp(join(parent, "intentabi-codex-bin-"));
    const live = await mkdtemp(join(parent, "intentabi-codex-runtime-"));
    try {
      await Promise.all([
        chmod(dead, 0o700),
        chmod(deadBinary, 0o700),
        chmod(live, 0o700),
      ]);
      const lease = (pid: number) =>
        `${JSON.stringify({
          schema: "io.github.aantenore.intentabi/codex-runtime-lease/v1",
          pid,
          createdAt: new Date(0).toISOString(),
        })}\n`;
      await Promise.all([
        writeFile(
          join(dead, ".intentabi-runtime-lease.json"),
          lease(2_147_483_647),
          {
            mode: 0o600,
          },
        ),
        writeFile(
          join(deadBinary, ".intentabi-runtime-lease.json"),
          lease(2_147_483_647),
          { mode: 0o600 },
        ),
        writeFile(
          join(live, ".intentabi-runtime-lease.json"),
          lease(process.pid),
          {
            mode: 0o600,
          },
        ),
        mkdir(join(dead, "codex-home", "sessions"), { recursive: true }),
      ]);
      await writeFile(
        join(dead, "codex-home", "sessions", "raw-private-session.jsonl"),
        "PRIVATE",
      );

      await expect(scavengeAbandonedCodexArtifacts(parent)).resolves.toBe(2);
      await expect(access(dead)).rejects.toThrow();
      await expect(access(deadBinary)).rejects.toThrow();
      await expect(access(live)).resolves.toBeUndefined();
    } finally {
      await rm(parent, { recursive: true, force: true });
    }
  });

  it("stages a digest-pinned copy and detects source swaps or staged tampering", async () => {
    const sourceDirectory = await mkdtemp(join(tmpdir(), "intentabi-source-"));
    const sourcePath = join(sourceDirectory, "codex-source");
    await writeFile(sourcePath, "trusted-binary", { mode: 0o700 });
    const expectedDigest = digest("trusted-binary");
    const dependencies = filesystemPreflightDependencies(
      expectedPlatformEnvironment,
    );
    let prepared: Awaited<ReturnType<typeof preflightCodexExecutable>> | null =
      null;
    try {
      prepared = await preflightCodexExecutable(
        sourcePath,
        "0.144.4",
        expectedDigest,
        {
          GH_TOKEN: "must-not-pass",
          INTENTABI_BENCH_HMAC_SECRET: "must-not-pass",
          AWS_SECRET_ACCESS_KEY: "must-not-pass",
          SystemRoot: "/safe/system-root",
        },
        dependencies,
      );
      const stagedPath = prepared.path;
      await writeFile(sourcePath, "attacker-swap");
      expect(await readFile(stagedPath, "utf8")).toBe("trusted-binary");
      await expect(prepared.verifyIntegrity()).resolves.toBeUndefined();

      await chmod(stagedPath, 0o700);
      await writeFile(stagedPath, "attacker-tamper");
      await expect(prepared.verifyIntegrity()).rejects.toBeInstanceOf(
        BenchmarkInvariantFailure,
      );

      const stagingDirectory = dirname(stagedPath);
      await prepared.release();
      await expect(access(stagingDirectory)).rejects.toThrow();
      prepared = null;
    } finally {
      await prepared?.release();
      await rm(sourceDirectory, { recursive: true, force: true });
    }
  });

  it("rejects a CLI version that differs from the pinned SDK", async () => {
    const sourceDirectory = await mkdtemp(join(tmpdir(), "intentabi-source-"));
    const sourcePath = join(sourceDirectory, "codex-source");
    await writeFile(sourcePath, "trusted-binary", { mode: 0o700 });
    try {
      await expect(
        preflightCodexExecutable(
          sourcePath,
          "0.144.5",
          digest("trusted-binary"),
          {},
          filesystemPreflightDependencies(),
        ),
      ).rejects.toThrow(/does not match/u);
    } finally {
      await rm(sourceDirectory, { recursive: true, force: true });
    }
  });

  it("creates only an ephemeral Git workspace and drops host secrets", async () => {
    const projected = projectPlatformRuntimeEnvironment({
      INTENTABI_BENCH_HMAC_SECRET: "hmac-secret",
      INTENTABI_CODEX_API_KEY: "api-secret",
      GH_TOKEN: "github-secret",
      AWS_SECRET_ACCESS_KEY: "cloud-secret",
      SystemRoot: "/safe/system-root",
    });
    expect(projected).toEqual(expectedPlatformEnvironment);

    const model = "gpt-codex-test";
    const runtime = await createIsolatedBenchmarkRuntime(projected, model);
    const root = dirname(runtime.workspaceDirectory);
    try {
      expect(runtime.sdkEnvironment).not.toHaveProperty("GH_TOKEN");
      expect(runtime.sdkEnvironment).not.toHaveProperty(
        "INTENTABI_BENCH_HMAC_SECRET",
      );
      expect(runtime.sdkEnvironment).not.toHaveProperty(
        "INTENTABI_CODEX_API_KEY",
      );
      expect(runtime.sdkEnvironment).not.toHaveProperty(
        "AWS_SECRET_ACCESS_KEY",
      );
      expect(
        await readFile(
          join(runtime.workspaceDirectory, ".git", "HEAD"),
          "utf8",
        ),
      ).toBe("ref: refs/heads/main\n");
      const configToml = await readFile(
        join(runtime.sdkEnvironment.CODEX_HOME!, "config.toml"),
        "utf8",
      );
      const modelCatalogPath = join(
        runtime.sdkEnvironment.CODEX_HOME!,
        "model-catalog.json",
      );
      const modelCatalog = JSON.parse(
        await readFile(modelCatalogPath, "utf8"),
      ) as { models: Array<Record<string, unknown>> };
      expect(modelCatalog.models).toHaveLength(1);
      expect(modelCatalog.models[0]).toMatchObject({
        slug: model,
        display_name: model,
        shell_type: LOCKED_CODEX_MODEL_POLICY.shellType,
        apply_patch_tool_type: null,
        experimental_supported_tools: [],
        input_modalities: ["text"],
      });
      expect(modelCatalog.models[0]?.input_modalities).not.toContain("image");
      expect(
        await readFile(
          join(runtime.sdkEnvironment.CODEX_HOME!, "environments.toml"),
          "utf8",
        ),
      ).toBe('default = "none"\ninclude_local = false\n');
      expect(configToml).toContain("check_for_update_on_startup = false");
      expect(configToml).toContain('cli_auth_credentials_store = "ephemeral"');
      expect(configToml).toContain("[analytics]\nenabled = false");
      expect(configToml).toContain("[orchestrator.skills]\nenabled = false");
      expect(configToml).toContain("[skills.bundled]\nenabled = false");
      expect(configToml).toContain("include_environment_context = false");
      expect(configToml).toContain("include_permissions_instructions = false");
      expect(configToml).toContain('model_provider = "intentabi_benchmark"');
      expect(configToml).toContain("[model_providers.intentabi_benchmark]");
      expect(configToml).toContain("supports_websockets = false");
      expect(configToml).toContain("notify = []");
      expect(configToml).toContain(
        `openai_base_url = ${JSON.stringify(FAIL_CLOSED_CODEX_BASE_URL)}`,
      );
      expect(configToml).toContain('[history]\npersistence = "none"');
      expect(configToml).toContain(
        `model_catalog_json = ${JSON.stringify(modelCatalogPath)}`,
      );
      expect(configToml).toContain('inherit = "none"');
      expect(configToml).toContain("experimental_use_profile = false");
      expect(configToml).toContain("ignore_default_excludes = false");
      expect(configToml).toContain("set = {}");
      expect(configToml).toContain("shell_tool = false");
      expect(configToml).toContain("unified_exec = false");
      expect(runtime.workspaceDirectory).not.toContain("intentabi/intentabi");
    } finally {
      await runtime.release();
    }
    await expect(access(root)).rejects.toThrow();
  });

  it("binds execution to the generated workspace and cleans it up", async () => {
    const digestPin = `sha256:${"a".repeat(64)}` as const;
    const config = resolveCodexBenchConfig(
      parseCodexBenchConfig({
        schema: "io.github.aantenore.intentabi/codex-bench-config/v1alpha1",
        classification: "research-conformance",
        codex: {
          codexPathOverride: "vendor/codex",
          expectedCliVersion: "0.144.4",
          expectedExecutableDigest: digestPin,
          authentication: { apiKeyEnv: "INTENTABI_CODEX_API_KEY" },
          thread: {
            model: "gpt-codex-test",
            sandboxMode: "read-only",
            skipGitRepoCheck: false,
            modelReasoningEffort: "medium",
            networkAccessEnabled: false,
            webSearchMode: "disabled",
            webSearchEnabled: false,
            approvalPolicy: "never",
          },
          turnTimeoutMs: 10_000,
        },
        benchmark: {
          seed: "test-v1",
          maxCases: 1,
          maxProviderCalls: 16,
          maxInputBytes: 1_024,
          maxDatasetBytes: 4_096,
          maxOutputTokensPerCall: 256,
          maxTotalOutputTokens: 4_096,
          maxRunDurationMs: 20_000,
          maxGatewayResponseBytes: 1_048_576,
        },
        evidence: {
          hmacSecretEnv: "INTENTABI_BENCH_HMAC_SECRET",
          keyId: "test-v1",
        },
      }),
      "/configured",
    );
    const dataset = parseCodexBenchDataset({
      schema: "io.github.aantenore.intentabi/codex-bench-dataset/v1alpha1",
      classification: "research-conformance",
      id: "test-v1",
      split: "conformance",
      cases: [
        {
          id: "case-1",
          stratum: "simple",
          cacheRegime: "cold",
          original: "PRIVATE ORIGINAL",
          candidate: "PRIVATE CANDIDATE",
        },
      ],
    });
    const releaseRuntime = vi.fn(async () => undefined);
    const verifyIntegrity = vi.fn(async () => undefined);
    const createRuntime = vi.fn(
      async (
        _environment: Readonly<Record<string, string>>,
        _model: string,
      ) => ({
        workspaceDirectory: "/private/ephemeral-workspace",
        sdkEnvironment: {
          CODEX_HOME: "/private/codex-home",
          HOME: "/private/home",
          PATH: "/private/bin",
        },
        release: releaseRuntime,
      }),
    );
    const createRunner = vi.fn((input) => {
      expect(input.threadOptions.workingDirectory).toBe(
        "/private/ephemeral-workspace",
      );
      expect(input.threadOptions.workingDirectory).not.toContain("configured");
      expect(input.maxProviderCalls).toBe(2);
      expect(input.maxTotalOutputTokens).toBe(512);
      return {
        run: vi.fn(async () => ({
          usage: {
            provenance: "host-observed-codex-sdk-run-result" as const,
            inputTokens: 10,
            cachedInputTokens: 0,
            outputTokens: 1,
            reasoningOutputTokens: 0,
          },
          latencyMicros: 1,
        })),
      };
    });
    const attestBoundary = vi.fn(async () => undefined);

    const receipt = await executeCodexBenchmark({
      config,
      dataset,
      secret: "x".repeat(32),
      apiKey: "codex-api-key-for-test",
      platformEnvironment: {},
      executable: {
        path: "/private/staged/codex",
        version: "0.144.4",
        digest: digestPin,
        verifyIntegrity,
        release: vi.fn(async () => undefined),
      },
      runId: "00000000-0000-4000-8000-000000000001",
      createRuntime,
      createRunner,
      attestBoundary,
    });

    expect(receipt.summary.completePairs).toBe(1);
    expect(receipt.executionMode).toBe("injected-test-boundary");
    expect(createRuntime).toHaveBeenCalledWith({}, "gpt-codex-test");
    expect(createRunner).toHaveBeenCalledTimes(1);
    expect(attestBoundary).toHaveBeenCalledTimes(1);
    expect(verifyIntegrity).toHaveBeenCalledTimes(6);
    expect(releaseRuntime).toHaveBeenCalledTimes(1);
  });
});

function filesystemPreflightDependencies(
  expectedEnvironment: Readonly<Record<string, string>> = {},
): ExecutablePreflightDependencies {
  return {
    resolvePath: realpath,
    assertExecutable: async () => undefined,
    inspectFile: stat,
    readVersion: async (_path, environment) => {
      expect(environment).toEqual(expectedEnvironment);
      return "codex-cli 0.144.4\n";
    },
    digestFile: async (path) => digest(await readFile(path)),
    createPrivateDirectory: async () =>
      mkdtemp(join(tmpdir(), "intentabi-staged-")),
    stageFile: async (source, destination) => copyFile(source, destination),
    protectFile: async (path) => chmod(path, 0o500),
    removeDirectory: async (path) => rm(path, { recursive: true, force: true }),
  };
}

function digest(value: string | Uint8Array): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}
