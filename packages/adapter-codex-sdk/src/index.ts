import { createHash } from "node:crypto";

import type {
  Input,
  RunResult,
  ThreadOptions,
  TurnOptions,
  Usage,
} from "@openai/codex-sdk";
import type {
  CodexExecutionBinding,
  CodexTurnTransport,
} from "@intentabi/codex-host";

export const VERIFIED_CODEX_SDK_VERSION = "0.144.4" as const;

const ADAPTER_CONTRACT_DIGEST = sha256(
  "@intentabi/adapter-codex-sdk/thread-factory/v1alpha1",
);
const THREAD_OPTION_FIELDS = [
  "model",
  "sandboxMode",
  "workingDirectory",
  "skipGitRepoCheck",
  "modelReasoningEffort",
  "networkAccessEnabled",
  "webSearchMode",
  "webSearchEnabled",
  "approvalPolicy",
  "additionalDirectories",
] as const satisfies readonly (keyof ThreadOptions)[];
type MissingThreadOption = Exclude<
  keyof ThreadOptions,
  (typeof THREAD_OPTION_FIELDS)[number]
>;
const THREAD_OPTION_CONTRACT_IS_COMPLETE: MissingThreadOption extends never
  ? true
  : false = true;
const SANDBOX_MODES = new Set([
  "read-only",
  "workspace-write",
  "danger-full-access",
]);
const APPROVAL_POLICIES = new Set([
  "never",
  "on-request",
  "on-failure",
  "untrusted",
]);
const REASONING_EFFORTS = new Set([
  "minimal",
  "low",
  "medium",
  "high",
  "xhigh",
]);
const WEB_SEARCH_MODES = new Set(["disabled", "cached", "live"]);

export interface CodexSdkThreadLike {
  run(input: Input, options?: TurnOptions): Promise<RunResult>;
}

export interface CodexSdkClientLike {
  startThread(options?: ThreadOptions): CodexSdkThreadLike;
}

export interface HostDeclaredCodexContracts {
  readonly runtimeRevisionDigest: `sha256:${string}`;
  readonly promptContractDigest: `sha256:${string}`;
  readonly toolContractDigest: `sha256:${string}`;
  readonly agentsDigest: `sha256:${string}`;
}

export interface ProviderNeutralUsage {
  readonly provenance: "caller-supplied-sdk-shaped";
  readonly input: {
    readonly total: number;
    readonly cached: number;
  };
  readonly output: {
    readonly total: number;
    readonly reasoning: number;
  };
}

/**
 * Source-only adapter for the exact SDK 0.144.4 Thread.run contract. Construct
 * it through createCodexSdkTurnTransport so the thread and binding originate
 * from the same frozen ThreadOptions snapshot.
 */
export class CodexSdkTurnTransport implements CodexTurnTransport<
  Input,
  TurnOptions,
  RunResult
> {
  readonly executionBinding: CodexExecutionBinding;
  readonly #thread: CodexSdkThreadLike;

  private constructor(
    thread: CodexSdkThreadLike,
    executionBinding: CodexExecutionBinding,
  ) {
    this.#thread = thread;
    this.executionBinding = executionBinding;
    Object.freeze(this);
  }

  static create(
    client: CodexSdkClientLike,
    requestedThreadOptions: Readonly<ThreadOptions>,
    contracts: HostDeclaredCodexContracts,
  ): CodexSdkTurnTransport {
    const options = snapshotThreadOptions(requestedThreadOptions);
    const contractSnapshot = snapshotContracts(contracts);
    const thread = client.startThread(options);
    if (
      thread === null ||
      typeof thread !== "object" ||
      typeof thread.run !== "function"
    ) {
      throw new TypeError("Codex SDK client returned an invalid thread");
    }
    return new CodexSdkTurnTransport(
      thread,
      createExecutionBinding(options, contractSnapshot),
    );
  }

  runExact(input: Input, options?: TurnOptions): Promise<RunResult> {
    return options === undefined
      ? this.#thread.run(input)
      : this.#thread.run(input, options);
  }
}

export function createCodexSdkTurnTransport(
  client: CodexSdkClientLike,
  requestedThreadOptions: Readonly<ThreadOptions>,
  contracts: HostDeclaredCodexContracts,
): CodexSdkTurnTransport {
  return CodexSdkTurnTransport.create(
    client,
    requestedThreadOptions,
    contracts,
  );
}

/** Map provider counters without inferring totals or token savings. */
export function normalizeCodexUsage(
  usage: Usage | null,
): ProviderNeutralUsage | null {
  if (usage === null) return null;
  const values = [
    usage.input_tokens,
    usage.cached_input_tokens,
    usage.output_tokens,
    usage.reasoning_output_tokens,
  ];
  if (values.some((value) => !Number.isSafeInteger(value) || value < 0)) {
    throw new TypeError("Codex SDK usage counters are invalid");
  }
  return deepFreeze({
    provenance: "caller-supplied-sdk-shaped",
    input: {
      total: usage.input_tokens,
      cached: usage.cached_input_tokens,
    },
    output: {
      total: usage.output_tokens,
      reasoning: usage.reasoning_output_tokens,
    },
  });
}

function snapshotThreadOptions(
  value: Readonly<ThreadOptions>,
): Readonly<ThreadOptions> {
  void THREAD_OPTION_CONTRACT_IS_COMPLETE;
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("Codex thread options must be a data-only record");
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.some(
      (key) =>
        typeof key !== "string" || !THREAD_OPTION_FIELDS.includes(key as never),
    )
  ) {
    throw new TypeError("Codex thread options contain unsupported fields");
  }
  const snapshot: ThreadOptions = {};
  for (const key of keys) {
    if (typeof key !== "string") throw new TypeError("Unexpected symbol field");
    const field = key as (typeof THREAD_OPTION_FIELDS)[number];
    const raw = ownEnumerableDataValue(value, field);
    switch (field) {
      case "model":
        snapshot.model = boundedText(raw, "model", 256);
        break;
      case "workingDirectory":
        snapshot.workingDirectory = boundedPath(raw, "workingDirectory");
        break;
      case "sandboxMode":
        snapshot.sandboxMode = enumValue(raw, SANDBOX_MODES, field);
        break;
      case "approvalPolicy":
        snapshot.approvalPolicy = enumValue(raw, APPROVAL_POLICIES, field);
        break;
      case "modelReasoningEffort":
        snapshot.modelReasoningEffort = enumValue(
          raw,
          REASONING_EFFORTS,
          field,
        );
        break;
      case "webSearchMode":
        snapshot.webSearchMode = enumValue(raw, WEB_SEARCH_MODES, field);
        break;
      case "skipGitRepoCheck":
      case "networkAccessEnabled":
      case "webSearchEnabled":
        if (typeof raw !== "boolean") {
          throw new TypeError(`Codex thread option ${field} must be boolean`);
        }
        snapshot[field] = raw;
        break;
      case "additionalDirectories":
        snapshot.additionalDirectories = snapshotDirectories(raw);
        break;
    }
  }
  return deepFreeze(snapshot);
}

function snapshotContracts(
  value: HostDeclaredCodexContracts,
): HostDeclaredCodexContracts {
  const snapshot = {
    runtimeRevisionDigest: value.runtimeRevisionDigest,
    promptContractDigest: value.promptContractDigest,
    toolContractDigest: value.toolContractDigest,
    agentsDigest: value.agentsDigest,
  };
  if (Object.values(snapshot).some((entry) => !isSha256(entry))) {
    throw new TypeError("Codex host contract digests are invalid");
  }
  return Object.freeze(snapshot);
}

function createExecutionBinding(
  options: Readonly<ThreadOptions>,
  contracts: HostDeclaredCodexContracts,
): CodexExecutionBinding {
  const directories = options.additionalDirectories;
  return deepFreeze({
    provenance: "adapter-thread-factory",
    adapterId: "@intentabi/adapter-codex-sdk",
    adapterContractDigest: ADAPTER_CONTRACT_DIGEST,
    sdkVersion: VERIFIED_CODEX_SDK_VERSION,
    threadOptionsDigest: sha256(canonicalJson(options)),
    externalClientConfiguration: "unavailable:external-client",
    thread: {
      model: options.model ?? "unavailable:not-explicit",
      workingDirectory: options.workingDirectory ?? "unavailable:not-explicit",
      sandboxMode: options.sandboxMode ?? "unavailable:not-explicit",
      approvalPolicy: options.approvalPolicy ?? "unavailable:not-explicit",
      webSearchMode: options.webSearchMode ?? "unavailable:not-explicit",
      skipGitRepoCheck: options.skipGitRepoCheck ?? "unavailable:not-explicit",
      modelReasoningEffort:
        options.modelReasoningEffort ?? "unavailable:not-explicit",
      networkAccessEnabled:
        options.networkAccessEnabled ?? "unavailable:not-explicit",
      webSearchEnabled: options.webSearchEnabled ?? "unavailable:not-explicit",
      additionalDirectories: directories?.length ?? 0,
      additionalDirectoriesDigest:
        directories === undefined
          ? "unavailable:not-explicit"
          : sha256(canonicalJson(directories)),
    },
    contracts: {
      provenance: "host-declared-unverified",
      ...contracts,
    },
  });
}

function snapshotDirectories(value: unknown): string[] {
  if (
    !Array.isArray(value) ||
    Reflect.getPrototypeOf(value) !== Array.prototype
  ) {
    throw new TypeError(
      "additionalDirectories must be a dense data-only array",
    );
  }
  const keys = Reflect.ownKeys(value);
  const lengthValue = ownDataValue(value, "length", false);
  if (
    typeof lengthValue !== "number" ||
    !Number.isSafeInteger(lengthValue) ||
    lengthValue < 0 ||
    lengthValue > 64 ||
    keys.length !== lengthValue + 1
  ) {
    throw new TypeError("additionalDirectories exceeds its structural limit");
  }
  const length = lengthValue;
  const result: string[] = [];
  for (let index = 0; index < length; index += 1) {
    result.push(
      boundedPath(
        ownEnumerableDataValue(value, String(index)),
        "additionalDirectories",
      ),
    );
  }
  return result;
}

function ownEnumerableDataValue(value: object, field: string): unknown {
  return ownDataValue(value, field, true);
}

function ownDataValue(
  value: object,
  field: string,
  enumerable: boolean,
): unknown {
  const descriptor = Reflect.getOwnPropertyDescriptor(value, field);
  if (
    descriptor === undefined ||
    descriptor.enumerable !== enumerable ||
    !Object.hasOwn(descriptor, "value") ||
    Object.hasOwn(descriptor, "get") ||
    Object.hasOwn(descriptor, "set")
  ) {
    throw new TypeError("Codex options must use own data fields");
  }
  return descriptor.value;
}

function boundedText(value: unknown, field: string, maximum: number): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > maximum ||
    hasControlCharacter(value)
  ) {
    throw new TypeError(`Codex thread option ${field} is invalid`);
  }
  return value;
}

function boundedPath(value: unknown, field: string): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 4_096 ||
    value.includes("\0")
  ) {
    throw new TypeError(`Codex thread option ${field} is invalid`);
  }
  return value;
}

function enumValue<Value extends string>(
  value: unknown,
  allowed: ReadonlySet<string>,
  field: string,
): Value {
  if (typeof value !== "string" || !allowed.has(value)) {
    throw new TypeError(`Codex thread option ${field} is invalid`);
  }
  return value as Value;
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right, "en"))
      .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value: string): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function isSha256(value: unknown): value is `sha256:${string}` {
  return typeof value === "string" && /^sha256:[a-f0-9]{64}$/u.test(value);
}

function hasControlCharacter(value: string): boolean {
  return Array.from(value).some((character) => {
    const codePoint = character.codePointAt(0);
    return codePoint !== undefined && (codePoint <= 31 || codePoint === 127);
  });
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const nested of Object.values(value)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
}
