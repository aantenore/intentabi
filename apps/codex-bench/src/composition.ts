import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { constants, createReadStream } from "node:fs";
import {
  access,
  chmod,
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  realpath,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { promisify } from "node:util";

import { VERIFIED_CODEX_SDK_VERSION } from "@intentabi/adapter-codex-sdk";
import {
  BENCHMARK_CORE_IMPLEMENTATION,
  BenchmarkArmFailure,
  BenchmarkInvariantFailure,
  createCounterbalancedPlan,
  runPairedBenchmark,
  type BenchmarkArmRunner,
  type BenchmarkCase,
  type BenchmarkPlan,
  type BenchmarkReceipt,
  type ProviderUsageObservation,
} from "@intentabi/benchmark-core";
import { createHmacOpaqueDigester } from "@intentabi/core";
import {
  Codex,
  type CodexOptions,
  type RunResult,
  type ThreadOptions,
} from "@openai/codex-sdk";

import {
  assertCodexBenchDatasetBudget,
  type CodexBenchConfig,
  type CodexBenchDataset,
} from "./config.js";
import {
  CODEX_GATEWAY_IMPLEMENTATION,
  LOCKED_CODEX_UPDATE_PLAN_TOOL,
  createBoundedResponsesGateway,
  type BoundedResponsesGateway,
  type BoundedResponsesGatewayOptions,
} from "./gateway.js";

const execFileAsync = promisify(execFile);
const SHA_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024;
const GATEWAY_REQUEST_OVERHEAD_BYTES = 2 * 1024 * 1024;
const RUNTIME_DIRECTORY_PREFIX = "intentabi-codex-runtime-";
const BINARY_DIRECTORY_PREFIX = "intentabi-codex-bin-";
const ARTIFACT_DIRECTORY_PATTERN =
  /^intentabi-codex-(?:runtime|bin)-[A-Za-z0-9_-]{6,64}$/u;
const RUNTIME_LEASE_FILE = ".intentabi-runtime-lease.json";
const RUNTIME_LEASE_SCHEMA =
  "io.github.aantenore.intentabi/codex-runtime-lease/v1";
const UNLEASED_RUNTIME_GRACE_MS = 24 * 60 * 60 * 1_000;
const BOUNDARY_ATTESTATION_INPUT =
  "IntentABI public boundary canary. Respond with exactly OK.";
export const CODEX_BENCH_IMPLEMENTATION =
  "io.github.aantenore.intentabi/codex-bench/0.1.0-alpha.1" as const;
const SAFE_PLATFORM_ENVIRONMENT_KEYS = new Set(["SYSTEMROOT", "WINDIR"]);
const preparedExecutableProvenance = new WeakMap<
  PreparedExecutable,
  "pinned-preflight" | "injected-preflight"
>();
export const PINNED_OPENAI_BASE_URL = "https://api.openai.com/v1";
export const LOCKED_CODEX_PROVIDER_ID = "intentabi_benchmark";
export const FAIL_CLOSED_CODEX_BASE_URL = "http://127.0.0.1:0/v1";
export const LOCKED_CODEX_BASE_INSTRUCTIONS =
  "You are a text-only benchmark worker. Do not request or use tools. Respond directly to the user input.";

/**
 * Locked process policy for the exact Codex CLI contract pinned by this app.
 * The same policy is written to the isolated CODEX_HOME because SDK 0.144.4
 * omits empty nested objects such as `set = {}` when flattening overrides.
 */
export const LOCKED_CODEX_PROCESS_CONFIG: NonNullable<CodexOptions["config"]> =
  freezeRecursively({
    allow_login_shell: false,
    analytics: { enabled: false },
    check_for_update_on_startup: false,
    cli_auth_credentials_store: "ephemeral",
    history: {
      persistence: "none",
    },
    hooks: {},
    mcp_servers: {},
    orchestrator: {
      mcp: { enabled: false },
      skills: { enabled: false },
    },
    skills: {
      bundled: { enabled: false },
      config: [],
      include_instructions: false,
    },
    include_apps_instructions: false,
    include_collaboration_mode_instructions: false,
    include_environment_context: false,
    include_permissions_instructions: false,
    model_provider: LOCKED_CODEX_PROVIDER_ID,
    model_providers: {
      [LOCKED_CODEX_PROVIDER_ID]: lockedCodexProviderConfig(
        FAIL_CLOSED_CODEX_BASE_URL,
      ),
    },
    notify: [],
    openai_base_url: FAIL_CLOSED_CODEX_BASE_URL,
    tools: {
      experimental_request_user_input: { enabled: false },
    },
    shell_environment_policy: {
      inherit: "none",
      experimental_use_profile: false,
      ignore_default_excludes: false,
      exclude: [],
      include_only: [],
      set: {},
    },
    features: {
      apps: false,
      browser_use: false,
      browser_use_external: false,
      browser_use_full_cdp_access: false,
      code_mode: false,
      code_mode_host: false,
      collab: false,
      collaboration_modes: false,
      computer_use: false,
      connectors: false,
      enable_request_compression: false,
      goals: false,
      hooks: false,
      image_generation: false,
      in_app_browser: false,
      js_repl: false,
      multi_agent: false,
      multi_agent_mode: false,
      plugins: false,
      plugin_sharing: false,
      remote_plugin: false,
      responses_websockets: false,
      responses_websockets_v2: false,
      realtime_conversation: false,
      search_tool: false,
      shell_snapshot: false,
      shell_tool: false,
      skill_mcp_dependency_install: false,
      standalone_web_search: false,
      tool_call_mcp_elicitation: false,
      tool_search: false,
      tool_suggest: false,
      unified_exec: false,
      unified_exec_zsh_fork: false,
      web_search: false,
      web_search_cached: false,
      web_search_request: false,
      workspace_dependencies: false,
    },
  });

function lockedCodexProviderConfig(baseUrl: string) {
  return freezeRecursively({
    name: "IntentABI bounded Responses",
    base_url: baseUrl,
    env_key: "CODEX_API_KEY",
    wire_api: "responses",
    requires_openai_auth: false,
    supports_websockets: false,
    request_max_retries: 0,
    stream_max_retries: 0,
  });
}

export function createLockedCodexArmProcessConfig(
  baseUrl: string,
): NonNullable<CodexOptions["config"]> {
  let parsed: URL;
  try {
    parsed = new URL(baseUrl);
  } catch {
    throw new TypeError("Codex arm provider URL is invalid");
  }
  if (
    parsed.protocol !== "http:" ||
    parsed.hostname !== "127.0.0.1" ||
    parsed.port === "" ||
    parsed.port === "0" ||
    parsed.pathname !== "/v1" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.search !== "" ||
    parsed.hash !== ""
  ) {
    throw new TypeError("Codex arm provider must be an exact loopback URL");
  }
  return freezeRecursively({
    ...LOCKED_CODEX_PROCESS_CONFIG,
    openai_base_url: baseUrl,
    model_providers: {
      [LOCKED_CODEX_PROVIDER_ID]: lockedCodexProviderConfig(baseUrl),
    },
  });
}

export const LOCKED_CODEX_MODEL_POLICY = freezeRecursively({
  schema: "io.github.aantenore.intentabi/codex-model-policy/v1alpha1",
  catalog: "authoritative-static",
  inputModalities: ["text"],
  shellType: "disabled",
  applyPatchToolType: null,
  experimentalSupportedTools: [],
});

export const LOCKED_CODEX_ENVIRONMENT_POLICY = freezeRecursively({
  default: "none",
  includeLocal: false,
});

const LOCKED_CODEX_ENVIRONMENTS_TOML = `default = "none"
include_local = false
`;

function lockedCodexConfigToml(modelCatalogPath: string): string {
  return `allow_login_shell = false
check_for_update_on_startup = false
cli_auth_credentials_store = "ephemeral"
include_apps_instructions = false
include_collaboration_mode_instructions = false
include_environment_context = false
include_permissions_instructions = false
model_catalog_json = ${JSON.stringify(modelCatalogPath)}
model_provider = ${JSON.stringify(LOCKED_CODEX_PROVIDER_ID)}
notify = []
openai_base_url = ${JSON.stringify(FAIL_CLOSED_CODEX_BASE_URL)}
hooks = {}
mcp_servers = {}

[model_providers.${LOCKED_CODEX_PROVIDER_ID}]
name = "IntentABI bounded Responses"
base_url = ${JSON.stringify(FAIL_CLOSED_CODEX_BASE_URL)}
env_key = "CODEX_API_KEY"
wire_api = "responses"
requires_openai_auth = false
supports_websockets = false
request_max_retries = 0
stream_max_retries = 0

[analytics]
enabled = false

[orchestrator.mcp]
enabled = false

[orchestrator.skills]
enabled = false

[skills]
config = []
include_instructions = false

[skills.bundled]
enabled = false

[history]
persistence = "none"

[tools.experimental_request_user_input]
enabled = false

[shell_environment_policy]
inherit = "none"
experimental_use_profile = false
ignore_default_excludes = false
exclude = []
include_only = []
set = {}

[features]
apps = false
browser_use = false
browser_use_external = false
browser_use_full_cdp_access = false
code_mode = false
code_mode_host = false
collab = false
collaboration_modes = false
computer_use = false
connectors = false
enable_request_compression = false
goals = false
hooks = false
image_generation = false
in_app_browser = false
js_repl = false
multi_agent = false
multi_agent_mode = false
plugins = false
plugin_sharing = false
remote_plugin = false
responses_websockets = false
responses_websockets_v2 = false
realtime_conversation = false
search_tool = false
shell_snapshot = false
shell_tool = false
skill_mcp_dependency_install = false
standalone_web_search = false
tool_call_mcp_elicitation = false
tool_search = false
tool_suggest = false
unified_exec = false
unified_exec_zsh_fork = false
web_search = false
web_search_cached = false
web_search_request = false
workspace_dependencies = false
`;
}

const MINIMAL_GIT_CONFIG = `[core]
repositoryformatversion = 0
filemode = true
bare = false
logallrefupdates = true
`;

export interface ResolvedCodexBenchConfig {
  readonly source: CodexBenchConfig;
  readonly codexPathOverride: string;
  readonly threadOptions: Readonly<Omit<ThreadOptions, "workingDirectory">>;
}

export interface ExecutableIdentity {
  readonly path: string;
  readonly version: string;
  readonly digest: `sha256:${string}`;
}

export interface PreparedExecutable extends ExecutableIdentity {
  verifyIntegrity(): Promise<void>;
  release(): Promise<void>;
}

export interface BenchmarkReceiptReservation {
  commit(receipt: BenchmarkReceipt): Promise<void>;
  abort(): Promise<void>;
}

export interface ExecutablePreflightDependencies {
  readonly resolvePath: (path: string) => Promise<string>;
  readonly assertExecutable: (path: string) => Promise<void>;
  readonly inspectFile: (
    path: string,
  ) => Promise<Readonly<{ size: number; isFile(): boolean }>>;
  readonly readVersion: (
    path: string,
    environment: Readonly<Record<string, string>>,
  ) => Promise<string>;
  readonly digestFile: (path: string) => Promise<`sha256:${string}`>;
  readonly createPrivateDirectory: () => Promise<string>;
  readonly stageFile: (source: string, destination: string) => Promise<void>;
  readonly protectFile: (path: string) => Promise<void>;
  readonly removeDirectory: (path: string) => Promise<void>;
}

export interface CodexThreadLike {
  run(input: string, options: { signal: AbortSignal }): Promise<RunResult>;
}

export interface CodexClientLike {
  startThread(options: ThreadOptions): CodexThreadLike;
}

export type CodexClientFactory = (
  options: Readonly<CodexOptions>,
) => CodexClientLike;

export interface IsolatedBenchmarkRuntime {
  readonly workspaceDirectory: string;
  readonly sdkEnvironment: Readonly<Record<string, string>>;
  release(): Promise<void>;
}

export interface CodexArmRunnerInput {
  readonly executablePath: string;
  readonly threadOptions: Readonly<ThreadOptions>;
  readonly timeoutMs: number;
  readonly apiKey: string;
  readonly sdkEnvironment: Readonly<Record<string, string>>;
  readonly maxOutputTokensPerCall: number;
  readonly maxProviderCalls: number;
  readonly maxTotalOutputTokens: number;
  readonly maxRunDurationMs: number;
  readonly maxRequestBytes: number;
  readonly maxResponseBytes: number;
}

export type CodexArmRunnerFactory = (
  input: CodexArmRunnerInput,
) => BenchmarkArmRunner;

export type ResponsesGatewayFactory = (
  options: BoundedResponsesGatewayOptions,
) => Promise<BoundedResponsesGateway>;

export interface CodexBoundaryAttestationInput {
  readonly executablePath: string;
  readonly threadOptions: Readonly<Omit<ThreadOptions, "workingDirectory">>;
  readonly timeoutMs: number;
  readonly maxOutputTokensPerCall: number;
  readonly maxRequestBytes: number;
  readonly maxResponseBytes: number;
  readonly createRuntime: (
    environment: Readonly<Record<string, string>>,
    model: string,
  ) => Promise<IsolatedBenchmarkRuntime>;
  readonly platformEnvironment: Readonly<Record<string, string>>;
}

export type CodexBoundaryAttestor = (
  input: CodexBoundaryAttestationInput,
) => Promise<void>;

export function resolveCodexBenchConfig(
  config: CodexBenchConfig,
  configDirectory: string,
): ResolvedCodexBenchConfig {
  return Object.freeze({
    source: config,
    codexPathOverride: resolve(configDirectory, config.codex.codexPathOverride),
    threadOptions: Object.freeze({ ...config.codex.thread }),
  });
}

export function createBenchmarkPlan(input: {
  readonly config: ResolvedCodexBenchConfig;
  readonly dataset: CodexBenchDataset;
  readonly secret: string;
}): Readonly<{ plan: BenchmarkPlan; cases: readonly BenchmarkCase[] }> {
  assertCodexBenchDatasetBudget(input.config.source, input.dataset);
  const digester = createHmacOpaqueDigester(
    input.secret,
    input.config.source.evidence.keyId,
  );
  const cases = input.dataset.cases.map((entry) =>
    Object.freeze({
      caseRef: digester.digestJson({
        domain: "io.github.aantenore.intentabi/codex-bench-case/v1",
        keyId: input.config.source.evidence.keyId,
        datasetId: input.dataset.id,
        caseId: entry.id,
        original: entry.original,
        candidate: entry.candidate,
      }),
      stratum: entry.stratum,
      cacheRegime: entry.cacheRegime,
      original: entry.original,
      candidate: entry.candidate,
    }),
  );
  const datasetDigest = digester.digestJson({
    domain: "io.github.aantenore.intentabi/codex-bench-dataset/v1",
    keyId: input.config.source.evidence.keyId,
    dataset: input.dataset,
  });
  const protocolDigest = sha256(
    canonicalJson({
      schema: "io.github.aantenore.intentabi/codex-bench-protocol/v1alpha2",
      implementation: {
        app: CODEX_BENCH_IMPLEMENTATION,
        core: BENCHMARK_CORE_IMPLEMENTATION,
        gateway: CODEX_GATEWAY_IMPLEMENTATION,
        armsPerCase: 2,
        outputAllocation: "equal-floor-per-planned-arm-v1",
        requestOverheadBytes: GATEWAY_REQUEST_OVERHEAD_BYTES,
        publicCanaryDigest: sha256(BOUNDARY_ATTESTATION_INPUT),
        receiptMacDomain:
          "io.github.aantenore.intentabi/codex-bench-receipt-mac/v1",
      },
      sdkVersion: VERIFIED_CODEX_SDK_VERSION,
      expectedCliVersion: input.config.source.codex.expectedCliVersion,
      expectedExecutableDigest:
        input.config.source.codex.expectedExecutableDigest,
      threadOptions: input.config.threadOptions,
      workspace: "ephemeral-minimal-git-v1",
      codexProcessPolicy: LOCKED_CODEX_PROCESS_CONFIG,
      codexModelPolicy: LOCKED_CODEX_MODEL_POLICY,
      codexModelCatalog: createLockedModelCatalog(
        input.config.source.codex.thread.model,
      ),
      codexEnvironmentPolicy: LOCKED_CODEX_ENVIRONMENT_POLICY,
      codexProviderPolicy: {
        modelProvider: LOCKED_CODEX_PROVIDER_ID,
        upstreamBaseUrl: PINNED_OPENAI_BASE_URL,
        supportsWebsockets: false,
        projectedTool: LOCKED_CODEX_UPDATE_PLAN_TOOL,
      },
      turnTimeoutMs: input.config.source.codex.turnTimeoutMs,
      benchmarkPolicy: input.config.source.benchmark,
      evidenceKeyId: input.config.source.evidence.keyId,
      classification: "research-conformance",
      promotionEligible: false,
    }),
  );
  return Object.freeze({
    cases,
    plan: createCounterbalancedPlan({
      cases,
      seed: input.config.source.benchmark.seed,
      keyId: input.config.source.evidence.keyId,
      datasetDigest,
      protocolDigest,
    }),
  });
}

export class CodexSdkArmRunner implements BenchmarkArmRunner {
  readonly #executablePath: string;
  readonly #threadOptions: Readonly<ThreadOptions>;
  readonly #timeoutMs: number;
  readonly #upstreamApiKey: string;
  readonly #sdkEnvironment: Readonly<Record<string, string>>;
  readonly #reservedOutputTokensPerCall: number;
  #remainingProviderCalls: number;
  readonly #deadlineMs: number;
  readonly #maxRequestBytes: number;
  readonly #maxResponseBytes: number;
  readonly #createClient: CodexClientFactory;
  readonly #createGateway: ResponsesGatewayFactory;

  constructor(
    input: CodexArmRunnerInput & {
      readonly createClient?: CodexClientFactory;
      readonly createGateway?: ResponsesGatewayFactory;
    },
  ) {
    if (
      typeof input.apiKey !== "string" ||
      Buffer.byteLength(input.apiKey) < 16 ||
      !Number.isSafeInteger(input.timeoutMs) ||
      input.timeoutMs <= 0 ||
      input.timeoutMs > 120_000 ||
      !Number.isSafeInteger(input.maxOutputTokensPerCall) ||
      input.maxOutputTokensPerCall < 16 ||
      input.maxOutputTokensPerCall > 4_096 ||
      !Number.isSafeInteger(input.maxProviderCalls) ||
      input.maxProviderCalls <= 0 ||
      input.maxProviderCalls > 200 ||
      !Number.isSafeInteger(input.maxTotalOutputTokens) ||
      input.maxTotalOutputTokens < input.maxProviderCalls * 16 ||
      input.maxTotalOutputTokens >
        input.maxProviderCalls * input.maxOutputTokensPerCall ||
      !Number.isSafeInteger(input.maxRunDurationMs) ||
      input.maxRunDurationMs <= 0 ||
      input.maxRunDurationMs > 3_600_000 ||
      !Number.isSafeInteger(input.maxRequestBytes) ||
      input.maxRequestBytes < 1_024 ||
      input.maxRequestBytes > 3_097_152 ||
      !Number.isSafeInteger(input.maxResponseBytes) ||
      input.maxResponseBytes < 65_536 ||
      input.maxResponseBytes > 16_777_216
    ) {
      throw new TypeError("Codex arm runner policy is invalid");
    }
    this.#executablePath = input.executablePath;
    this.#threadOptions = input.threadOptions;
    this.#timeoutMs = input.timeoutMs;
    this.#upstreamApiKey = input.apiKey;
    this.#sdkEnvironment = Object.freeze({ ...input.sdkEnvironment });
    this.#reservedOutputTokensPerCall = Math.min(
      input.maxOutputTokensPerCall,
      Math.floor(input.maxTotalOutputTokens / input.maxProviderCalls),
    );
    this.#remainingProviderCalls = input.maxProviderCalls;
    this.#deadlineMs = Date.now() + input.maxRunDurationMs;
    this.#maxRequestBytes = input.maxRequestBytes;
    this.#maxResponseBytes = input.maxResponseBytes;
    this.#createClient =
      input.createClient ??
      ((options) => new Codex(options) as CodexClientLike);
    this.#createGateway = input.createGateway ?? createBoundedResponsesGateway;
  }

  async run(input: string) {
    const model = this.#threadOptions.model;
    if (typeof model !== "string" || model.length === 0) {
      throw new BenchmarkInvariantFailure("Codex benchmark model is unbound");
    }
    const remainingDurationMs = this.#deadlineMs - Date.now();
    const reservedOutputTokens = this.#reservedOutputTokensPerCall;
    if (
      this.#remainingProviderCalls <= 0 ||
      reservedOutputTokens < 16 ||
      remainingDurationMs <= 0
    ) {
      throw new BenchmarkInvariantFailure(
        "Codex benchmark resource budget was exhausted",
      );
    }
    this.#remainingProviderCalls -= 1;

    let gateway: BoundedResponsesGateway;
    try {
      gateway = await this.#createGateway({
        upstreamBaseUrl: PINNED_OPENAI_BASE_URL,
        upstreamApiKey: this.#upstreamApiKey,
        expectedModel: model,
        expectedInstructions: LOCKED_CODEX_BASE_INSTRUCTIONS,
        expectedInput: input,
        maxOutputTokens: reservedOutputTokens,
        maxRequestBytes: this.#maxRequestBytes,
        maxResponseBytes: this.#maxResponseBytes,
      });
    } catch {
      throw new BenchmarkInvariantFailure(
        "Codex loopback gateway could not be established",
      );
    }

    const options = Object.freeze({
      codexPathOverride: this.#executablePath,
      apiKey: gateway.proxyApiKey,
      baseUrl: gateway.baseUrl,
      env: this.#sdkEnvironment,
      config: createLockedCodexArmProcessConfig(gateway.baseUrl),
    });
    const controller = new AbortController();
    const timer = setTimeout(
      () => controller.abort(),
      Math.min(this.#timeoutMs, remainingDurationMs),
    );
    const started = process.hrtime.bigint();
    let result: RunResult | undefined;
    let executionError: unknown;
    try {
      // A new client and thread are created for every arm. No conversation
      // state can flow from baseline to candidate or between cases.
      const thread = this.#createClient(options).startThread({
        ...this.#threadOptions,
      });
      result = await thread.run(input, { signal: controller.signal });
    } catch (error) {
      executionError = error;
    } finally {
      clearTimeout(timer);
    }

    let boundaryError: unknown;
    try {
      gateway.assertConformant();
    } catch (error) {
      boundaryError = error;
    }
    try {
      await gateway.close();
    } catch {
      boundaryError ??= new BenchmarkInvariantFailure(
        "Codex loopback gateway did not close cleanly",
      );
    }
    if (boundaryError !== undefined) {
      throw boundaryError instanceof BenchmarkInvariantFailure
        ? boundaryError
        : new BenchmarkInvariantFailure(
            "Codex provider boundary attestation failed",
          );
    }
    if (executionError !== undefined || result === undefined) {
      throw new BenchmarkArmFailure(
        controller.signal.aborted ? "timeout" : "execution-failed",
      );
    }
    const elapsed = Number((process.hrtime.bigint() - started) / 1_000n);
    return {
      usage: projectSdkUsage(result.usage),
      latencyMicros: elapsed,
    };
  }
}

export function projectPlatformRuntimeEnvironment(
  environment: Readonly<Record<string, string | undefined>>,
): Readonly<Record<string, string>> {
  if (process.platform !== "win32") return Object.freeze({});
  const projected: Record<string, string> = {};
  for (const [key, value] of Object.entries(environment)) {
    if (
      SAFE_PLATFORM_ENVIRONMENT_KEYS.has(key.toUpperCase()) &&
      value !== undefined &&
      value.length > 0 &&
      value.length <= 4_096 &&
      !value.includes("\0")
    ) {
      projected[key] = value;
    }
  }
  return Object.freeze(projected);
}

export async function preflightCodexExecutable(
  configuredPath: string,
  expectedVersion: string,
  expectedDigest: string,
  platformEnvironment: Readonly<Record<string, string>> = {},
  dependencies: ExecutablePreflightDependencies = defaultPreflightDependencies,
): Promise<PreparedExecutable> {
  if (!SHA_PATTERN.test(expectedDigest)) {
    throw new TypeError("Expected Codex CLI digest is invalid");
  }
  const safeEnvironment =
    projectPlatformRuntimeEnvironment(platformEnvironment);
  const sourcePath = await dependencies.resolvePath(configuredPath);
  await assertBoundedExecutable(sourcePath, dependencies);

  const stagingDirectory = await dependencies.createPrivateDirectory();
  const stagedPath = join(
    stagingDirectory,
    process.platform === "win32" ? "codex.exe" : "codex",
  );
  let released = false;
  const release = async () => {
    if (released) return;
    await dependencies.removeDirectory(stagingDirectory);
    released = true;
  };

  try {
    await dependencies.stageFile(sourcePath, stagedPath);
    await dependencies.protectFile(stagedPath);
    const canonicalStagedPath = await dependencies.resolvePath(stagedPath);
    await assertBoundedExecutable(canonicalStagedPath, dependencies);
    const digestBeforeVersion =
      await dependencies.digestFile(canonicalStagedPath);
    if (digestBeforeVersion !== expectedDigest) {
      throw new TypeError("Codex CLI digest does not match the configured pin");
    }
    const stdout = await dependencies.readVersion(
      canonicalStagedPath,
      safeEnvironment,
    );
    const digestAfterVersion =
      await dependencies.digestFile(canonicalStagedPath);
    if (digestAfterVersion !== expectedDigest) {
      throw new TypeError("Staged Codex CLI changed during version inspection");
    }
    const match =
      /^codex-cli ([0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?)\s*$/u.exec(
        stdout,
      );
    if (match?.[1] !== expectedVersion) {
      throw new TypeError("Codex CLI version does not match the pinned SDK");
    }

    const verifyIntegrity = async () => {
      if (released) {
        throw new BenchmarkInvariantFailure("Executable lease was released");
      }
      try {
        const currentPath = await dependencies.resolvePath(canonicalStagedPath);
        if (currentPath !== canonicalStagedPath) throw new Error();
        await assertBoundedExecutable(currentPath, dependencies);
        if ((await dependencies.digestFile(currentPath)) !== expectedDigest) {
          throw new Error();
        }
      } catch {
        throw new BenchmarkInvariantFailure(
          "Staged Codex CLI integrity check failed",
        );
      }
    };

    const prepared = Object.freeze({
      path: canonicalStagedPath,
      version: match[1],
      digest: expectedDigest as `sha256:${string}`,
      verifyIntegrity,
      release,
    });
    preparedExecutableProvenance.set(
      prepared,
      dependencies === defaultPreflightDependencies
        ? "pinned-preflight"
        : "injected-preflight",
    );
    return prepared;
  } catch (error) {
    await release();
    throw error;
  }
}

const defaultPreflightDependencies: ExecutablePreflightDependencies = {
  resolvePath: realpath,
  assertExecutable: async (path) => access(path, constants.X_OK),
  inspectFile: stat,
  readVersion: async (path, environment) => {
    const { stdout } = await execFileAsync(path, ["--version"], {
      cwd: dirname(path),
      env: { ...environment },
      timeout: 5_000,
      maxBuffer: 16_384,
      encoding: "utf8",
    });
    return stdout;
  },
  digestFile: hashFile,
  createPrivateDirectory: async () => {
    await scavengeAbandonedCodexArtifacts();
    const directory = await mkdtemp(join(tmpdir(), BINARY_DIRECTORY_PREFIX));
    await chmod(directory, 0o700);
    await writeArtifactLease(directory);
    return directory;
  },
  stageFile: async (source, destination) => {
    await copyFile(source, destination, constants.COPYFILE_EXCL);
  },
  protectFile: async (path) => chmod(path, 0o500),
  removeDirectory: async (path) => rm(path, { recursive: true, force: true }),
};

/**
 * Removes only abandoned private runtime/binary artifacts owned by this user.
 * Live leases are preserved; an invalid or missing lease gets a 24-hour grace
 * window so concurrent creators cannot be mistaken for crash residue.
 */
export async function scavengeAbandonedCodexArtifacts(
  rootDirectory = tmpdir(),
  nowMs = Date.now(),
): Promise<number> {
  if (!Number.isSafeInteger(nowMs) || nowMs < 0) {
    throw new TypeError("Runtime scavenger clock is invalid");
  }
  const entries = await readdir(rootDirectory, { withFileTypes: true });
  let removed = 0;
  for (const entry of entries) {
    if (!entry.isDirectory() || !ARTIFACT_DIRECTORY_PATTERN.test(entry.name)) {
      continue;
    }
    const candidate = join(rootDirectory, entry.name);
    let before;
    try {
      before = await lstat(candidate);
    } catch {
      continue;
    }
    if (
      !before.isDirectory() ||
      (process.platform !== "win32" && (before.mode & 0o077) !== 0) ||
      (typeof process.getuid === "function" && before.uid !== process.getuid())
    ) {
      continue;
    }

    const lease = await readRuntimeLease(candidate);
    const abandoned =
      lease === null
        ? nowMs - before.mtimeMs >= UNLEASED_RUNTIME_GRACE_MS
        : !isProcessAlive(lease.pid);
    if (!abandoned) continue;

    let current;
    try {
      current = await lstat(candidate);
    } catch {
      continue;
    }
    if (
      !current.isDirectory() ||
      current.dev !== before.dev ||
      current.ino !== before.ino
    ) {
      continue;
    }
    try {
      await rm(candidate, { recursive: true, force: true });
      removed += 1;
    } catch {
      throw new BenchmarkInvariantFailure(
        "Abandoned Codex benchmark artifact could not be removed",
      );
    }
  }
  return removed;
}

export async function createIsolatedBenchmarkRuntime(
  platformEnvironment: Readonly<Record<string, string>> = {},
  model = "intentabi-benchmark-text-only",
): Promise<IsolatedBenchmarkRuntime> {
  await scavengeAbandonedCodexArtifacts();
  const root = await mkdtemp(join(tmpdir(), RUNTIME_DIRECTORY_PREFIX));
  await chmod(root, 0o700);
  const workspaceDirectory = join(root, "workspace");
  const codexHomeDirectory = join(root, "codex-home");
  const homeDirectory = join(root, "home");
  const tempDirectory = join(root, "tmp");
  const binDirectory = join(root, "bin");
  const modelCatalogPath = join(codexHomeDirectory, "model-catalog.json");
  try {
    await writeArtifactLease(root);
    await Promise.all(
      [
        workspaceDirectory,
        codexHomeDirectory,
        homeDirectory,
        tempDirectory,
        binDirectory,
        join(homeDirectory, ".cache"),
        join(homeDirectory, ".config"),
        join(homeDirectory, ".local", "share"),
        join(homeDirectory, ".local", "state"),
        join(workspaceDirectory, ".git", "objects", "info"),
        join(workspaceDirectory, ".git", "objects", "pack"),
        join(workspaceDirectory, ".git", "refs", "heads"),
        join(workspaceDirectory, ".git", "refs", "tags"),
      ].map((path) => mkdir(path, { recursive: true, mode: 0o700 })),
    );
    await Promise.all([
      writeFile(
        join(codexHomeDirectory, "config.toml"),
        lockedCodexConfigToml(modelCatalogPath),
        { encoding: "utf8", flag: "wx", mode: 0o600 },
      ),
      writeFile(
        modelCatalogPath,
        `${JSON.stringify(createLockedModelCatalog(model), null, 2)}\n`,
        { encoding: "utf8", flag: "wx", mode: 0o600 },
      ),
      writeFile(
        join(codexHomeDirectory, "environments.toml"),
        LOCKED_CODEX_ENVIRONMENTS_TOML,
        { encoding: "utf8", flag: "wx", mode: 0o600 },
      ),
      writeFile(
        join(workspaceDirectory, ".git", "HEAD"),
        "ref: refs/heads/main\n",
        {
          encoding: "utf8",
          flag: "wx",
          mode: 0o600,
        },
      ),
      writeFile(
        join(workspaceDirectory, ".git", "config"),
        MINIMAL_GIT_CONFIG,
        { encoding: "utf8", flag: "wx", mode: 0o600 },
      ),
    ]);

    const sdkEnvironment = Object.freeze({
      ...projectPlatformRuntimeEnvironment(platformEnvironment),
      CODEX_HOME: codexHomeDirectory,
      CODEX_EXEC_SERVER_URL: "none",
      HOME: homeDirectory,
      USERPROFILE: homeDirectory,
      PATH: binDirectory,
      TMPDIR: tempDirectory,
      TMP: tempDirectory,
      TEMP: tempDirectory,
      XDG_CACHE_HOME: join(homeDirectory, ".cache"),
      XDG_CONFIG_HOME: join(homeDirectory, ".config"),
      XDG_DATA_HOME: join(homeDirectory, ".local", "share"),
      XDG_STATE_HOME: join(homeDirectory, ".local", "state"),
    });
    let released = false;
    return Object.freeze({
      workspaceDirectory,
      sdkEnvironment,
      release: async () => {
        if (released) return;
        await rm(root, { recursive: true, force: true });
        released = true;
      },
    });
  } catch (error) {
    await rm(root, { recursive: true, force: true });
    throw error;
  }
}

async function writeArtifactLease(directory: string): Promise<void> {
  await writeFile(
    join(directory, RUNTIME_LEASE_FILE),
    `${JSON.stringify({
      schema: RUNTIME_LEASE_SCHEMA,
      pid: process.pid,
      createdAt: new Date().toISOString(),
    })}\n`,
    { encoding: "utf8", flag: "wx", mode: 0o600 },
  );
}

async function readRuntimeLease(
  directory: string,
): Promise<Readonly<{ pid: number }> | null> {
  const path = join(directory, RUNTIME_LEASE_FILE);
  try {
    const file = await lstat(path);
    if (!file.isFile() || file.size <= 0 || file.size > 4_096) return null;
    const parsed = JSON.parse(await readFile(path, "utf8")) as unknown;
    if (
      !isPlainRuntimeLease(parsed) ||
      parsed.schema !== RUNTIME_LEASE_SCHEMA ||
      !Number.isSafeInteger(parsed.pid) ||
      parsed.pid <= 0 ||
      parsed.pid > 2_147_483_647 ||
      typeof parsed.createdAt !== "string" ||
      !Number.isFinite(Date.parse(parsed.createdAt))
    ) {
      return null;
    }
    return Object.freeze({ pid: parsed.pid });
  } catch {
    return null;
  }
}

function isPlainRuntimeLease(value: unknown): value is Readonly<{
  schema: string;
  pid: number;
  createdAt: string;
}> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  const keys = Object.keys(value).sort();
  return (
    keys.length === 3 &&
    keys[0] === "createdAt" &&
    keys[1] === "pid" &&
    keys[2] === "schema"
  );
}

function isProcessAlive(pid: number): boolean {
  if (pid === process.pid) return true;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return !(
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      error.code === "ESRCH"
    );
  }
}

/**
 * Runs the staged CLI against an in-process fake Responses upstream using only
 * public canary text. This proves the effective binary reaches the loopback
 * policy boundary before any benchmark content is submitted.
 */
export async function attestCodexBoundary(
  input: CodexBoundaryAttestationInput,
): Promise<void> {
  const model = input.threadOptions.model;
  if (typeof model !== "string" || model.length === 0) {
    throw new BenchmarkInvariantFailure("Codex attestation model is unbound");
  }
  const runtime = await input.createRuntime(input.platformEnvironment, model);
  try {
    const fakeUpstream: typeof fetch = async () =>
      new Response(completedAttestationSse(), {
        status: 200,
        headers: { "content-type": "text/event-stream" },
      });
    const runner = new CodexSdkArmRunner({
      executablePath: input.executablePath,
      threadOptions: Object.freeze({
        ...input.threadOptions,
        workingDirectory: runtime.workspaceDirectory,
      }),
      timeoutMs: input.timeoutMs,
      apiKey: "intentabi-public-attestation-key",
      sdkEnvironment: runtime.sdkEnvironment,
      maxOutputTokensPerCall: input.maxOutputTokensPerCall,
      maxProviderCalls: 1,
      maxTotalOutputTokens: input.maxOutputTokensPerCall,
      maxRunDurationMs: input.timeoutMs,
      maxRequestBytes: input.maxRequestBytes,
      maxResponseBytes: input.maxResponseBytes,
      createGateway: (options) =>
        createBoundedResponsesGateway({ ...options, fetchImpl: fakeUpstream }),
    });
    await runner.run(BOUNDARY_ATTESTATION_INPUT);
  } catch (error) {
    if (error instanceof BenchmarkInvariantFailure) throw error;
    throw new BenchmarkInvariantFailure(
      "Staged Codex CLI failed its public boundary attestation",
    );
  } finally {
    await runtime.release();
  }
}

export async function executeCodexBenchmark(input: {
  readonly config: ResolvedCodexBenchConfig;
  readonly dataset: CodexBenchDataset;
  readonly secret: string;
  readonly apiKey: string;
  readonly platformEnvironment: Readonly<Record<string, string>>;
  readonly executable: PreparedExecutable;
  readonly runner?: BenchmarkArmRunner;
  readonly runId?: string;
  readonly createRuntime?: (
    environment: Readonly<Record<string, string>>,
    model: string,
  ) => Promise<IsolatedBenchmarkRuntime>;
  readonly createRunner?: CodexArmRunnerFactory;
  readonly attestBoundary?: CodexBoundaryAttestor;
}): Promise<BenchmarkReceipt> {
  if (
    !SHA_PATTERN.test(input.executable.digest) ||
    input.executable.digest !==
      input.config.source.codex.expectedExecutableDigest ||
    input.executable.version !== input.config.source.codex.expectedCliVersion ||
    typeof input.apiKey !== "string" ||
    Buffer.byteLength(input.apiKey) < 16
  ) {
    throw new TypeError("Codex benchmark execution binding is invalid");
  }
  const materialized = createBenchmarkPlan(input);
  const receiptDigester = createHmacOpaqueDigester(
    input.secret,
    input.config.source.evidence.keyId,
  );
  const executionMode =
    input.runner === undefined &&
    input.createRuntime === undefined &&
    input.createRunner === undefined &&
    input.attestBoundary === undefined &&
    preparedExecutableProvenance.get(input.executable) === "pinned-preflight"
      ? ("pinned-provider-boundary" as const)
      : ("injected-test-boundary" as const);
  const createRuntime = input.createRuntime ?? createIsolatedBenchmarkRuntime;
  const maxRequestBytes =
    input.config.source.benchmark.maxInputBytes +
    GATEWAY_REQUEST_OVERHEAD_BYTES;
  const plannedProviderCalls = input.dataset.cases.length * 2;
  if (input.runner === undefined) {
    await assertPreparedExecutableIntegrity(input.executable);
    await (input.attestBoundary ?? attestCodexBoundary)({
      executablePath: input.executable.path,
      threadOptions: input.config.threadOptions,
      timeoutMs: input.config.source.codex.turnTimeoutMs,
      maxOutputTokensPerCall:
        input.config.source.benchmark.maxOutputTokensPerCall,
      maxRequestBytes,
      maxResponseBytes: input.config.source.benchmark.maxGatewayResponseBytes,
      createRuntime,
      platformEnvironment: projectPlatformRuntimeEnvironment(
        input.platformEnvironment,
      ),
    });
    await assertPreparedExecutableIntegrity(input.executable);
  }
  const runtime = await createRuntime(
    projectPlatformRuntimeEnvironment(input.platformEnvironment),
    input.config.source.codex.thread.model,
  );
  try {
    const runner =
      input.runner ??
      (
        input.createRunner ??
        ((runnerInput) => new CodexSdkArmRunner(runnerInput))
      )({
        executablePath: input.executable.path,
        threadOptions: Object.freeze({
          ...input.config.threadOptions,
          workingDirectory: runtime.workspaceDirectory,
        }),
        timeoutMs: input.config.source.codex.turnTimeoutMs,
        apiKey: input.apiKey,
        sdkEnvironment: runtime.sdkEnvironment,
        maxOutputTokensPerCall:
          input.config.source.benchmark.maxOutputTokensPerCall,
        maxProviderCalls: plannedProviderCalls,
        maxTotalOutputTokens: Math.min(
          input.config.source.benchmark.maxTotalOutputTokens,
          plannedProviderCalls *
            input.config.source.benchmark.maxOutputTokensPerCall,
        ),
        maxRunDurationMs: input.config.source.benchmark.maxRunDurationMs,
        maxRequestBytes,
        maxResponseBytes: input.config.source.benchmark.maxGatewayResponseBytes,
      });
    const integrityBoundRunner: BenchmarkArmRunner = {
      run: async (content, context) => {
        await assertPreparedExecutableIntegrity(input.executable);
        try {
          return await runner.run(content, context);
        } finally {
          await assertPreparedExecutableIntegrity(input.executable);
        }
      },
    };
    return await runPairedBenchmark({
      ...materialized,
      runner: integrityBoundRunner,
      runId: input.runId ?? randomUUID(),
      executionMode,
      executableDigest: input.executable.digest,
      sdkVersion: VERIFIED_CODEX_SDK_VERSION,
      cliVersion: input.executable.version,
      keyId: input.config.source.evidence.keyId,
      authenticateReceipt: (receipt) =>
        receiptDigester.digestJson({
          domain: "io.github.aantenore.intentabi/codex-bench-receipt-mac/v1",
          keyId: input.config.source.evidence.keyId,
          receipt,
        }),
    });
  } finally {
    await runtime.release();
  }
}

export async function writeBenchmarkReceipt(
  path: string,
  receipt: BenchmarkReceipt,
): Promise<void> {
  const reservation = await reserveBenchmarkReceipt(path);
  try {
    await reservation.commit(receipt);
  } catch (error) {
    await reservation.abort();
    throw error;
  }
}

export async function reserveBenchmarkReceipt(
  path: string,
): Promise<BenchmarkReceiptReservation> {
  const absolutePath = resolve(path);
  const canonicalParent = await realpath(dirname(absolutePath));
  const canonicalPath = join(canonicalParent, basename(absolutePath));
  const parent = await lstat(canonicalParent);
  if (
    !parent.isDirectory() ||
    (process.platform !== "win32" && (parent.mode & 0o022) !== 0) ||
    (typeof process.getuid === "function" && parent.uid !== process.getuid())
  ) {
    throw new BenchmarkInvariantFailure(
      "Receipt output directory is not a trusted canonical directory",
    );
  }
  const handle = await open(canonicalPath, "wx", 0o600);
  const identity = await handle.stat();
  let settled = false;
  return Object.freeze({
    commit: async (receipt: BenchmarkReceipt) => {
      if (settled) throw new TypeError("Receipt reservation is already closed");
      try {
        if (!(await isSameReservedFile(canonicalPath, identity))) {
          throw new BenchmarkInvariantFailure(
            "Receipt reservation path changed before commit",
          );
        }
        await handle.writeFile(`${JSON.stringify(receipt, null, 2)}\n`, {
          encoding: "utf8",
        });
        await handle.sync();
        if (!(await isSameReservedFile(canonicalPath, identity))) {
          throw new BenchmarkInvariantFailure(
            "Receipt reservation path changed during commit",
          );
        }
        await handle.close();
        settled = true;
      } catch (error) {
        settled = true;
        await handle.close().catch(() => undefined);
        await removeSameReservedFile(canonicalPath, identity);
        throw error;
      }
    },
    abort: async () => {
      if (settled) return;
      settled = true;
      await handle.close().catch(() => undefined);
      await removeSameReservedFile(canonicalPath, identity);
    },
  });
}

async function isSameReservedFile(
  path: string,
  identity: Readonly<{ dev: number; ino: number }>,
): Promise<boolean> {
  try {
    const current = await lstat(path);
    return (
      current.isFile() &&
      current.dev === identity.dev &&
      current.ino === identity.ino
    );
  } catch {
    return false;
  }
}

async function removeSameReservedFile(
  path: string,
  identity: Readonly<{ dev: number; ino: number }>,
): Promise<void> {
  if (await isSameReservedFile(path, identity)) {
    await rm(path, { force: true });
  }
}

export function projectSdkUsage(
  usage: unknown,
): ProviderUsageObservation | null {
  if (usage === null) return null;
  if (typeof usage !== "object") return invalidUsageObservation();
  try {
    const descriptors = Object.getOwnPropertyDescriptors(usage);
    const counters = [
      ownEnumerableDataNumber(descriptors, "input_tokens"),
      ownEnumerableDataNumber(descriptors, "cached_input_tokens"),
      ownEnumerableDataNumber(descriptors, "output_tokens"),
      ownEnumerableDataNumber(descriptors, "reasoning_output_tokens"),
    ] as const;
    if (counters.some((value) => value === undefined)) {
      return invalidUsageObservation();
    }
    return Object.freeze({
      provenance: "host-observed-codex-sdk-run-result",
      inputTokens: counters[0]!,
      cachedInputTokens: counters[1]!,
      outputTokens: counters[2]!,
      reasoningOutputTokens: counters[3]!,
    });
  } catch {
    return invalidUsageObservation();
  }
}

function ownEnumerableDataNumber(
  descriptors: PropertyDescriptorMap,
  key: string,
): number | undefined {
  const descriptor = descriptors[key];
  return descriptor !== undefined &&
    descriptor.enumerable === true &&
    "value" in descriptor &&
    typeof descriptor.value === "number"
    ? descriptor.value
    : undefined;
}

function invalidUsageObservation(): ProviderUsageObservation {
  return Object.freeze({
    provenance: "host-observed-codex-sdk-run-result",
    inputTokens: -1,
    cachedInputTokens: -1,
    outputTokens: -1,
    reasoningOutputTokens: -1,
  });
}

function completedAttestationSse(): string {
  const id = "resp-intentabi-boundary-attestation";
  const events = [
    { type: "response.created", response: { id } },
    {
      type: "response.output_item.done",
      item: {
        type: "message",
        role: "assistant",
        id: "msg-intentabi-boundary-attestation",
        content: [{ type: "output_text", text: "OK" }],
      },
    },
    {
      type: "response.completed",
      response: {
        id,
        usage: {
          input_tokens: 1,
          input_tokens_details: null,
          output_tokens: 1,
          output_tokens_details: null,
          total_tokens: 2,
        },
      },
    },
  ] as const;
  return events
    .map((event) => `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`)
    .join("");
}

function createLockedModelCatalog(model: string): Readonly<{
  models: readonly Readonly<Record<string, unknown>>[];
}> {
  return freezeRecursively({
    models: [
      {
        slug: model,
        display_name: model,
        description: null,
        default_reasoning_level: "medium",
        supported_reasoning_levels: [
          { effort: "minimal", description: "Pinned benchmark effort" },
          { effort: "low", description: "Pinned benchmark effort" },
          { effort: "medium", description: "Pinned benchmark effort" },
          { effort: "high", description: "Pinned benchmark effort" },
          { effort: "xhigh", description: "Pinned benchmark effort" },
        ],
        shell_type: LOCKED_CODEX_MODEL_POLICY.shellType,
        visibility: "list",
        supported_in_api: true,
        priority: 0,
        additional_speed_tiers: [],
        service_tiers: [],
        default_service_tier: null,
        availability_nux: null,
        upgrade: null,
        base_instructions: LOCKED_CODEX_BASE_INSTRUCTIONS,
        model_messages: null,
        include_skills_usage_instructions: false,
        supports_reasoning_summaries: false,
        default_reasoning_summary: "none",
        support_verbosity: false,
        default_verbosity: null,
        apply_patch_tool_type: LOCKED_CODEX_MODEL_POLICY.applyPatchToolType,
        web_search_tool_type: "text",
        truncation_policy: { mode: "bytes", limit: 10_000 },
        supports_parallel_tool_calls: false,
        prefer_websockets: false,
        supports_image_detail_original: false,
        context_window: null,
        max_context_window: null,
        auto_compact_token_limit: null,
        comp_hash: null,
        effective_context_window_percent: 95,
        experimental_supported_tools:
          LOCKED_CODEX_MODEL_POLICY.experimentalSupportedTools,
        input_modalities: LOCKED_CODEX_MODEL_POLICY.inputModalities,
        supports_search_tool: false,
        use_responses_lite: false,
        auto_review_model_override: null,
        tool_mode: "direct",
        multi_agent_version: null,
      },
    ],
  });
}

async function assertPreparedExecutableIntegrity(
  executable: PreparedExecutable,
): Promise<void> {
  try {
    await executable.verifyIntegrity();
  } catch (error) {
    if (error instanceof BenchmarkInvariantFailure) throw error;
    throw new BenchmarkInvariantFailure(
      "Staged Codex CLI integrity check failed",
    );
  }
}

async function assertBoundedExecutable(
  path: string,
  dependencies: Pick<
    ExecutablePreflightDependencies,
    "inspectFile" | "assertExecutable"
  >,
): Promise<void> {
  const file = await dependencies.inspectFile(path);
  if (!file.isFile() || file.size <= 0 || file.size > MAX_EXECUTABLE_BYTES) {
    throw new TypeError("Codex CLI executable is not a bounded regular file");
  }
  await dependencies.assertExecutable(path);
}

function sha256(value: string | Uint8Array): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

async function hashFile(path: string): Promise<`sha256:${string}`> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) {
    hash.update(chunk as Buffer);
  }
  return `sha256:${hash.digest("hex")}`;
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalValue(value));
}

function canonicalValue(value: unknown): unknown {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  ) {
    return value;
  }
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
        .map(([key, child]) => [key, canonicalValue(child)]),
    );
  }
  throw new TypeError("Protocol binding must be strict JSON");
}

function freezeRecursively<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freezeRecursively(child);
    Object.freeze(value);
  }
  return value;
}
