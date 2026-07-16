import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, realpathSync, statSync } from "node:fs";
import { isAbsolute } from "node:path";

import type { OrdinaryRoute, Sha256Digest } from "@intentabi/core";
import { z } from "zod";

const jsonValueSchema: z.ZodType<unknown> = z.lazy(() =>
  z.union([
    z.null(),
    z.boolean(),
    z.number().finite(),
    z.string(),
    z.array(jsonValueSchema),
    z.record(z.string(), jsonValueSchema),
  ]),
);

const fixtureSchema = z
  .object({
    schema: z.literal(
      "io.github.aantenore.intentabi/agentic-sdlc-fixture/v1alpha1",
    ),
    routeId: z.string().regex(/^[a-z0-9][a-z0-9._-]{0,127}$/u),
    cases: z
      .array(
        z
          .object({
            input: jsonValueSchema,
            output: jsonValueSchema,
          })
          .strict(),
      )
      .min(1),
  })
  .strict();

export interface AgenticSdlcFixture {
  readonly schema: "io.github.aantenore.intentabi/agentic-sdlc-fixture/v1alpha1";
  readonly routeId: string;
  readonly cases: readonly {
    readonly input: unknown;
    readonly output: unknown;
  }[];
}

/** Deterministic ordinary-route seam for tests and local conformance. */
export class FixtureAgenticSdlcRoute implements OrdinaryRoute<
  unknown,
  unknown
> {
  readonly id: string;
  readonly revisionDigest: Sha256Digest;
  #executions = 0;
  readonly #outputs: ReadonlyMap<string, unknown>;

  constructor(source: string) {
    const fixture = fixtureSchema.parse(
      JSON.parse(source),
    ) as AgenticSdlcFixture;
    this.id = fixture.routeId;
    this.revisionDigest = sha256(source);
    this.#outputs = new Map(
      fixture.cases.map((entry) => [canonicalJson(entry.input), entry.output]),
    );
  }

  async execute(input: unknown): Promise<unknown> {
    this.#executions += 1;
    const output = this.#outputs.get(canonicalJson(input));
    if (output === undefined) {
      throw new Error("No Agentic SDLC fixture case matched the route input");
    }
    return structuredClone(output);
  }

  executionCount(): number {
    return this.#executions;
  }
}

const safeRouteToken = z
  .string()
  .min(1)
  .max(256)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._ /:-]*$/u);

const referencedEntitySchema = z
  .object({
    type: safeRouteToken.optional(),
    entity_type: safeRouteToken.optional(),
    kind: safeRouteToken.optional(),
    role: safeRouteToken.optional(),
    id: safeRouteToken.optional(),
    identifier: safeRouteToken.optional(),
    value: safeRouteToken.optional(),
  })
  .strict()
  .refine(
    (value) =>
      [value.type, value.entity_type, value.kind, value.role].filter(
        (entry) => entry !== undefined,
      ).length === 1,
    { message: "Referenced entity requires exactly one type discriminator" },
  )
  .refine(
    (value) =>
      [value.id, value.identifier, value.value].filter(
        (entry) => entry !== undefined,
      ).length === 1,
    { message: "Referenced entity requires exactly one identifier" },
  );

const providedArtifactSchema = z
  .object({
    type: safeRouteToken.optional(),
    artifact_type: safeRouteToken.optional(),
    id: safeRouteToken.optional(),
    path: safeRouteToken.optional(),
    template_id: safeRouteToken.optional(),
    mode: safeRouteToken.optional(),
  })
  .strict()
  .refine(
    (value) =>
      [value.type, value.artifact_type].filter((entry) => entry !== undefined)
        .length === 1,
    { message: "Provided artifact requires exactly one type discriminator" },
  )
  .refine(
    (value) =>
      [value.id, value.path, value.template_id].some(
        (entry) => entry !== undefined,
      ),
    { message: "Provided artifact requires an id, path, or template id" },
  );

const missingContextSchema = z.union([
  safeRouteToken,
  z
    .object({
      question: safeRouteToken.optional(),
      prompt: safeRouteToken.optional(),
      label: safeRouteToken.optional(),
      id: safeRouteToken.optional(),
    })
    .strict()
    .refine(
      (value) =>
        [value.question, value.prompt, value.label, value.id].filter(
          (entry) => entry !== undefined,
        ).length === 1,
      { message: "Missing context requires exactly one display field" },
    ),
]);

export const agenticSdlcRouteIntentSchema = z
  .object({
    requested_action: safeRouteToken,
    confidence: z.number().min(0).max(1),
    referenced_entities: z.array(referencedEntitySchema).max(64),
    provided_artifacts: z.array(providedArtifactSchema).max(64),
    missing_context: z.array(missingContextSchema).max(64),
    proposed_phase: safeRouteToken.nullable(),
    artifact_type: safeRouteToken.nullable(),
    skip_phases: z.array(safeRouteToken).max(32),
  })
  .strict();

export const agenticSdlcCliInputSchema = z
  .object({
    root: z
      .string()
      .min(1)
      .max(4_096)
      .refine((value) => !value.includes("\0")),
    intent: agenticSdlcRouteIntentSchema,
  })
  .strict();

export type AgenticSdlcRouteIntent = z.infer<
  typeof agenticSdlcRouteIntentSchema
>;
export type AgenticSdlcCliInput = z.infer<typeof agenticSdlcCliInputSchema>;

export interface AgenticSdlcCliRouteOptions {
  readonly entrypointPath: string;
  readonly allowedRoot: string;
  /** Host-owned digest of plugin version plus project routing configuration. */
  readonly deploymentRevisionDigest: Sha256Digest;
  readonly timeoutMs: number;
  readonly maxOutputBytes: number;
  readonly environment?: Readonly<Record<string, string | undefined>>;
  readonly blockedEnvironmentKeys?: readonly string[];
}

export interface AgenticSdlcCliOutput {
  readonly exitCode: 0;
  readonly stdout: string;
  readonly stderr: string;
}

export type AgenticSdlcRouteErrorCode =
  "EXECUTION_FAILED" | "OUTPUT_LIMIT" | "TIMEOUT";

/** A deliberately content-free child-process failure. */
export class AgenticSdlcRouteError extends Error {
  readonly code: AgenticSdlcRouteErrorCode;

  constructor(code: AgenticSdlcRouteErrorCode) {
    super(
      code === "TIMEOUT"
        ? "Agentic SDLC route timed out"
        : code === "OUTPUT_LIMIT"
          ? "Agentic SDLC route output exceeded its configured limit"
          : "Agentic SDLC route execution failed",
    );
    this.name = "AgenticSdlcRouteError";
    this.code = code;
  }
}

/**
 * Invokes the trusted installed Agentic SDLC Node CLI directly, never through a
 * shell. This is process isolation, not an OS sandbox; the configured entrypoint
 * retains the current user's filesystem and network authority.
 */
export class AgenticSdlcCliRoute implements OrdinaryRoute<
  AgenticSdlcCliInput,
  AgenticSdlcCliOutput
> {
  readonly id = "agentic-sdlc.cli";
  readonly revisionDigest: Sha256Digest;
  readonly #entrypointPath: string;
  readonly #allowedRoot: string;
  readonly #timeoutMs: number;
  readonly #maxOutputBytes: number;
  readonly #environment: NodeJS.ProcessEnv;

  constructor(options: AgenticSdlcCliRouteOptions) {
    if (
      !isAbsolute(options.entrypointPath) ||
      !isAbsolute(options.allowedRoot)
    ) {
      throw new TypeError(
        "Agentic SDLC CLI entrypoint and allowed root must be absolute",
      );
    }
    if (
      !Number.isInteger(options.timeoutMs) ||
      options.timeoutMs < 1 ||
      options.timeoutMs > 120_000 ||
      !Number.isInteger(options.maxOutputBytes) ||
      options.maxOutputBytes < 1_024 ||
      options.maxOutputBytes > 16 * 1024 * 1024 ||
      !/^sha256:[a-f0-9]{64}$/u.test(options.deploymentRevisionDigest)
    ) {
      throw new TypeError("Agentic SDLC CLI execution bounds are invalid");
    }
    const entrypointPath = realpathSync(options.entrypointPath);
    const allowedRoot = realpathSync(options.allowedRoot);
    if (
      !statSync(entrypointPath).isFile() ||
      !statSync(allowedRoot).isDirectory()
    ) {
      throw new TypeError("Agentic SDLC CLI paths have invalid types");
    }
    const entrypointDigest = sha256(readFileSync(entrypointPath));
    this.revisionDigest = sha256(
      canonicalJson({
        deploymentRevisionDigest: options.deploymentRevisionDigest,
        entrypointDigest,
      }),
    );
    this.#entrypointPath = entrypointPath;
    this.#allowedRoot = allowedRoot;
    this.#timeoutMs = options.timeoutMs;
    this.#maxOutputBytes = options.maxOutputBytes;
    this.#environment = Object.freeze(
      sanitizeEnvironment(
        options.environment ?? {},
        new Set(options.blockedEnvironmentKeys ?? []),
      ),
    );
  }

  async execute(input: AgenticSdlcCliInput): Promise<AgenticSdlcCliOutput> {
    const request = agenticSdlcCliInputSchema.parse(input);
    let requestRoot: string;
    try {
      requestRoot = realpathSync(request.root);
    } catch {
      throw new TypeError("Agentic SDLC request root is invalid");
    }
    if (requestRoot !== this.#allowedRoot) {
      throw new TypeError("Agentic SDLC request root is outside the allowlist");
    }
    const argv = [
      this.#entrypointPath,
      "route",
      "decide",
      "--root",
      this.#allowedRoot,
      "--intent-json",
      JSON.stringify(request.intent),
      "--json",
    ];
    return await new Promise((resolvePromise, rejectPromise) => {
      execFile(
        process.execPath,
        argv,
        {
          cwd: this.#allowedRoot,
          encoding: "utf8",
          env: this.#environment,
          maxBuffer: this.#maxOutputBytes,
          shell: false,
          timeout: this.#timeoutMs,
          windowsHide: true,
        },
        (error, stdout, stderr) => {
          if (error !== null) {
            rejectPromise(redactedChildError(error));
            return;
          }
          resolvePromise({ exitCode: 0, stdout, stderr });
        },
      );
    });
  }
}

function redactedChildError(error: Error): AgenticSdlcRouteError {
  const details = error as Error & {
    readonly code?: string;
    readonly killed?: boolean;
    readonly signal?: string | null;
  };
  if (details.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER") {
    return new AgenticSdlcRouteError("OUTPUT_LIMIT");
  }
  if (details.killed === true || typeof details.signal === "string") {
    return new AgenticSdlcRouteError("TIMEOUT");
  }
  return new AgenticSdlcRouteError("EXECUTION_FAILED");
}

function sanitizeEnvironment(
  environment: Readonly<Record<string, string | undefined>>,
  blocked: ReadonlySet<string>,
): NodeJS.ProcessEnv {
  const allowed = ["PATH", "SystemRoot", "WINDIR", "TEMP", "TMP", "TMPDIR"];
  return Object.fromEntries(
    allowed.flatMap((key) =>
      blocked.has(key) || environment[key] === undefined
        ? []
        : [[key, environment[key]]],
    ),
  );
}

function sha256(value: string | Uint8Array): Sha256Digest {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalValue(value));
}

function canonicalValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return Object.fromEntries(
      Object.keys(record)
        .sort()
        .map((key) => [key, canonicalValue(record[key])]),
    );
  }
  return value;
}
