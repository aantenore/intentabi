import { execFile } from "node:child_process";
import { createHash, createHmac } from "node:crypto";
import {
  type BigIntStats,
  lstatSync,
  readFileSync,
  realpathSync,
  statSync,
} from "node:fs";
import { lstat, readFile, readdir } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, sep } from "node:path";
import { isProxy } from "node:util/types";

import type { Sha256Digest } from "@intentabi/core";
import { z } from "zod";

export const AGENTIC_SDLC_QUALIFICATION_PROFILE =
  "io.github.aantenore.intentabi/agentic-sdlc-route-contract-outcome/v1" as const;
export const AGENTIC_SDLC_QUALIFICATION_OBSERVATION_SCHEMA =
  "io.github.aantenore.intentabi/agentic-sdlc-qualification-observation/v1alpha1" as const;
export const AGENTIC_SDLC_QUALIFICATION_RESULT_SCHEMA =
  "io.github.aantenore.intentabi/agentic-sdlc-qualification-result/v1alpha1" as const;

export type AgenticSdlcQualificationChannel = "route" | "contract" | "outcome";
export type AgenticSdlcQualificationOrder = "AB" | "BA";
export type AgenticSdlcQualificationCaseRef =
  `hmac-sha256:qualification-case:${string}`;
export type AgenticSdlcQualificationDigest =
  `hmac-sha256:qualification-${string}:${string}`;

export type AgenticSdlcQualificationErrorCode =
  | "CONTRACT_UNAVAILABLE"
  | "EXECUTION_FAILED"
  | "INVALID_INPUT"
  | "MALFORMED_OUTPUT"
  | "OUTPUT_LIMIT"
  | "PROJECT_MUTATED"
  | "STATE_UNAVAILABLE"
  | "TIMEOUT"
  | "WORKSPACE_MISMATCH";

export class AgenticSdlcQualificationError extends Error {
  constructor(readonly code: AgenticSdlcQualificationErrorCode) {
    super(`Agentic SDLC qualification failed: ${code}`);
    this.name = "AgenticSdlcQualificationError";
  }
}

export interface AgenticSdlcQualificationBoundaryRequest {
  readonly executablePath: string;
  readonly argv: readonly string[];
  readonly cwd: string;
  readonly environment: Readonly<NodeJS.ProcessEnv>;
  readonly timeoutMs: number;
  readonly maxOutputBytes: number;
  readonly signal: AbortSignal;
  readonly shell: false;
}

export interface AgenticSdlcQualificationBoundaryResult {
  readonly stdout: string;
  readonly stderr: string;
}

export interface AgenticSdlcQualificationBoundary {
  execute(
    request: AgenticSdlcQualificationBoundaryRequest,
  ): Promise<AgenticSdlcQualificationBoundaryResult>;
}

interface QualificationExecFileOptions {
  readonly cwd: string;
  readonly encoding: "utf8";
  readonly env: NodeJS.ProcessEnv;
  readonly maxBuffer: number;
  readonly shell: false;
  readonly signal: AbortSignal;
  readonly timeout: number;
  readonly windowsHide: true;
}

export type QualificationExecFile = (
  file: string,
  args: string[],
  options: QualificationExecFileOptions,
  callback: (error: Error | null, stdout: string, stderr: string) => void,
) => unknown;

/** The production boundary always uses execFile with an explicit shell=false. */
export class NodeAgenticSdlcQualificationBoundary implements AgenticSdlcQualificationBoundary {
  readonly #execFile: QualificationExecFile;

  constructor(
    execFileImplementation = execFile as unknown as QualificationExecFile,
  ) {
    this.#execFile = execFileImplementation;
  }

  async execute(
    request: AgenticSdlcQualificationBoundaryRequest,
  ): Promise<AgenticSdlcQualificationBoundaryResult> {
    if (request.shell !== false) {
      throw new AgenticSdlcQualificationError("INVALID_INPUT");
    }
    return await new Promise((resolvePromise, rejectPromise) => {
      this.#execFile(
        request.executablePath,
        [...request.argv],
        {
          cwd: request.cwd,
          encoding: "utf8",
          env: { ...request.environment },
          maxBuffer: request.maxOutputBytes,
          shell: false,
          signal: request.signal,
          timeout: request.timeoutMs,
          windowsHide: true,
        },
        (error, stdout, stderr) => {
          if (error !== null) {
            rejectPromise(classifyProcessError(error));
            return;
          }
          resolvePromise({ stdout, stderr });
        },
      );
    });
  }
}

export interface AgenticSdlcProjectStateDigester {
  digest(root: string): Promise<Sha256Digest>;
}

/**
 * Hashes fixture-owned canonical files. Git metadata, dependency installs, and
 * Agentic SDLC derived cache/index directories are deliberately excluded.
 */
export class FileSystemAgenticSdlcProjectStateDigester implements AgenticSdlcProjectStateDigester {
  readonly #maximumFiles: number;
  readonly #maximumBytes: number;

  constructor(options: { maximumFiles?: number; maximumBytes?: number } = {}) {
    this.#maximumFiles = options.maximumFiles ?? 10_000;
    this.#maximumBytes = options.maximumBytes ?? 64 * 1024 * 1024;
    if (
      !Number.isSafeInteger(this.#maximumFiles) ||
      this.#maximumFiles < 1 ||
      !Number.isSafeInteger(this.#maximumBytes) ||
      this.#maximumBytes < 1
    ) {
      throw new AgenticSdlcQualificationError("INVALID_INPUT");
    }
  }

  async digest(root: string): Promise<Sha256Digest> {
    const hash = createHash("sha256").update(
      "io.github.aantenore.intentabi/agentic-sdlc-project-state/v1\0",
    );
    let files = 0;
    let bytes = 0n;

    const visit = async (directory: string, segments: readonly string[]) => {
      const entries = (await readdir(directory, { withFileTypes: true })).sort(
        (left, right) => left.name.localeCompare(right.name),
      );
      for (const entry of entries) {
        const nextSegments = [...segments, entry.name];
        const portablePath = nextSegments.join("/");
        if (excludedStatePath(portablePath)) continue;
        const target = join(directory, entry.name);
        const before = await lstat(target, { bigint: true });
        if (before.isSymbolicLink()) {
          throw new AgenticSdlcQualificationError("STATE_UNAVAILABLE");
        }
        if (before.isDirectory()) {
          hash.update(`d\0${portablePath}\0`);
          await visit(target, nextSegments);
          continue;
        }
        if (!before.isFile()) {
          throw new AgenticSdlcQualificationError("STATE_UNAVAILABLE");
        }
        files += 1;
        bytes += before.size;
        if (files > this.#maximumFiles || bytes > BigInt(this.#maximumBytes)) {
          throw new AgenticSdlcQualificationError("STATE_UNAVAILABLE");
        }
        const content = await readFile(target);
        const after = await lstat(target, { bigint: true });
        if (
          BigInt(content.byteLength) !== before.size ||
          !sameStableFileSnapshot(before, after)
        ) {
          throw new AgenticSdlcQualificationError("STATE_UNAVAILABLE");
        }
        hash.update(`f\0${portablePath}\0${content.byteLength}\0`);
        hash.update(content);
      }
    };

    try {
      await visit(root, []);
    } catch (error) {
      if (error instanceof AgenticSdlcQualificationError) throw error;
      throw new AgenticSdlcQualificationError("STATE_UNAVAILABLE");
    }
    return `sha256:${hash.digest("hex")}`;
  }
}

export interface AgenticSdlcQualificationAuthenticator {
  readonly keyId: string;
  digest(
    domain: "contract" | "observation" | "outcome" | "project" | "route",
    value: unknown,
  ): AgenticSdlcQualificationDigest;
}

export class HmacAgenticSdlcQualificationAuthenticator implements AgenticSdlcQualificationAuthenticator {
  readonly keyId: string;
  readonly #secret: Buffer;

  constructor(input: {
    readonly keyId: string;
    readonly secret: Uint8Array | string;
  }) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(input.keyId)) {
      throw new AgenticSdlcQualificationError("INVALID_INPUT");
    }
    const temporarySecret = Buffer.from(input.secret);
    try {
      if (temporarySecret.byteLength < 32) {
        throw new AgenticSdlcQualificationError("INVALID_INPUT");
      }
      this.keyId = input.keyId;
      this.#secret = Buffer.from(temporarySecret);
    } finally {
      temporarySecret.fill(0);
    }
  }

  digest(
    domain: "contract" | "observation" | "outcome" | "project" | "route",
    value: unknown,
  ): AgenticSdlcQualificationDigest {
    const mac = createHmac("sha256", this.#secret)
      .update(`io.github.aantenore.intentabi/qualification-${domain}/v1\0`)
      .update(canonicalJson(value))
      .digest("hex");
    return `hmac-sha256:qualification-${domain}:${mac}`;
  }
}

export interface AgenticSdlcQualificationProjection {
  readonly schema: typeof AGENTIC_SDLC_QUALIFICATION_OBSERVATION_SCHEMA;
  readonly profile: typeof AGENTIC_SDLC_QUALIFICATION_PROFILE;
  readonly keyId: string;
  readonly routeDigest: AgenticSdlcQualificationDigest;
  readonly contractDigest: AgenticSdlcQualificationDigest;
  readonly outcomeDigest: AgenticSdlcQualificationDigest;
  readonly projectBindingDigest: AgenticSdlcQualificationDigest;
  readonly observationDigest: AgenticSdlcQualificationDigest;
}

export type AgenticSdlcQualificationExpectation =
  | Readonly<{ relation: "equivalent" }>
  | Readonly<{
      relation: "different";
      mustDifferAnyOf: readonly [
        AgenticSdlcQualificationChannel,
        ...AgenticSdlcQualificationChannel[],
      ];
    }>;

export interface AgenticSdlcQualificationCaseInput {
  readonly caseRef: AgenticSdlcQualificationCaseRef;
  readonly primaryOrder: AgenticSdlcQualificationOrder;
  readonly baselineIntent: unknown;
  readonly candidateIntent: unknown;
  readonly expectation: AgenticSdlcQualificationExpectation;
  readonly workspaceRoots: {
    readonly baselineFirst: {
      readonly baseline: string;
      readonly candidate: string;
    };
    readonly candidateFirst: {
      readonly candidate: string;
      readonly baseline: string;
    };
  };
}

export type AgenticSdlcQualificationReason =
  | "EXPECTED_DISCRIMINANT_MISSING"
  | "ORDER_EFFECT"
  | "SEMANTIC_DIVERGENCE"
  | "UNSAFE_CONVERGENCE";

export interface AgenticSdlcQualificationResult {
  readonly schema: typeof AGENTIC_SDLC_QUALIFICATION_RESULT_SCHEMA;
  readonly profile: typeof AGENTIC_SDLC_QUALIFICATION_PROFILE;
  readonly caseRef: AgenticSdlcQualificationCaseRef;
  readonly keyId: string;
  readonly primaryOrder: AgenticSdlcQualificationOrder;
  readonly expectedRelation: AgenticSdlcQualificationExpectation["relation"];
  readonly status: "passed" | "failed";
  readonly reasons: readonly AgenticSdlcQualificationReason[];
  readonly repeatable: boolean;
  readonly equivalentChannels: Readonly<
    Record<AgenticSdlcQualificationChannel, boolean>
  >;
  readonly observations: {
    readonly abBaseline: AgenticSdlcQualificationProjection;
    readonly abCandidate: AgenticSdlcQualificationProjection;
    readonly baCandidate: AgenticSdlcQualificationProjection;
    readonly baBaseline: AgenticSdlcQualificationProjection;
  };
}

export interface AgenticSdlcQualificationRunnerOptions {
  readonly entrypointPath: string;
  readonly expectedEntrypointDigest: Sha256Digest;
  readonly expectedSdlcVersion: string;
  readonly timeoutMs: number;
  readonly maxOutputBytes: number;
  readonly authenticator: AgenticSdlcQualificationAuthenticator;
  readonly boundary?: AgenticSdlcQualificationBoundary;
  readonly stateDigester?: AgenticSdlcProjectStateDigester;
  readonly environment?: Readonly<Record<string, string | undefined>>;
  readonly blockedEnvironmentKeys?: readonly string[];
}

interface PrivateObservation {
  readonly route: unknown;
  readonly contract: unknown;
  readonly outcome: unknown;
  readonly stateDigest: Sha256Digest;
}

interface CompletedArm {
  readonly private: PrivateObservation;
  readonly public: AgenticSdlcQualificationProjection;
}

const outputToken = z
  .string()
  .min(1)
  .max(256)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/u);
const uniqueTokenArray = z
  .array(outputToken)
  .max(256)
  .refine((value) => new Set(value).size === value.length);
const contractSummarySchema = z
  .object({
    id: outputToken,
    phase: outputToken.nullable(),
    story_id: outputToken.nullable(),
    status: outputToken.nullable(),
    approved: z.boolean(),
    readiness_gaps: uniqueTokenArray,
    freshness_gaps: uniqueTokenArray,
  })
  .passthrough();
const taskStartOutputSchema = z
  .object({
    sdlc_version: outputToken,
    status: outputToken,
    execution_allowed: z.boolean(),
    route: outputToken,
    phase: outputToken.nullable(),
    story_id: outputToken.nullable(),
    contract_id: outputToken.nullable(),
    contract_action: outputToken.nullable(),
    requires_confirmation: z.boolean(),
    blocking_reasons: uniqueTokenArray,
    contract: contractSummarySchema.nullable().optional(),
    route_decision: z
      .object({
        route: outputToken,
        status: outputToken,
        requires_confirmation: z.boolean(),
        blocking_reasons: uniqueTokenArray,
        deterministic_checks: z
          .array(
            z
              .object({
                check: outputToken,
                status: outputToken,
              })
              .passthrough(),
          )
          .max(256)
          .refine(
            (value) =>
              new Set(value.map((entry) => entry.check)).size === value.length,
          ),
      })
      .passthrough(),
  })
  .passthrough();

const intentToken = z
  .string()
  .min(1)
  .max(256)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._ /:-]*$/u);
const intentEntitySchema = z
  .object({
    type: intentToken.optional(),
    entity_type: intentToken.optional(),
    kind: intentToken.optional(),
    role: intentToken.optional(),
    id: intentToken.optional(),
    identifier: intentToken.optional(),
    value: intentToken.optional(),
  })
  .strict()
  .refine(
    (value) =>
      [value.type, value.entity_type, value.kind, value.role].filter(
        (entry) => entry !== undefined,
      ).length === 1,
  )
  .refine(
    (value) =>
      [value.id, value.identifier, value.value].filter(
        (entry) => entry !== undefined,
      ).length === 1,
  );
const intentArtifactSchema = z
  .object({
    type: intentToken.optional(),
    artifact_type: intentToken.optional(),
    id: intentToken.optional(),
    path: intentToken.optional(),
    template_id: intentToken.optional(),
    mode: intentToken.optional(),
  })
  .strict()
  .refine(
    (value) =>
      [value.type, value.artifact_type].filter((entry) => entry !== undefined)
        .length === 1,
  )
  .refine((value) =>
    [value.id, value.path, value.template_id].some(
      (entry) => entry !== undefined,
    ),
  );
const intentMissingContextSchema = z.union([
  intentToken,
  z
    .object({
      question: intentToken.optional(),
      prompt: intentToken.optional(),
      label: intentToken.optional(),
      id: intentToken.optional(),
    })
    .strict()
    .refine(
      (value) =>
        [value.question, value.prompt, value.label, value.id].filter(
          (entry) => entry !== undefined,
        ).length === 1,
    ),
]);
const intentSchema = z
  .object({
    requested_action: intentToken,
    confidence: z.number().min(0).max(1),
    referenced_entities: z.array(intentEntitySchema).max(64),
    provided_artifacts: z.array(intentArtifactSchema).max(64),
    missing_context: z.array(intentMissingContextSchema).max(64),
    proposed_phase: intentToken.nullable(),
    artifact_type: intentToken.nullable(),
    skip_phases: z.array(intentToken).max(32),
  })
  .strict();

/**
 * Runs both orders on four independent, byte-identical fixture roots. It never
 * confirms or executes an SDLC task; only the read-only task-start decision is
 * observed.
 */
export class AgenticSdlcQualificationRunner {
  readonly #entrypointPath: string;
  readonly #expectedSdlcVersion: string;
  readonly #timeoutMs: number;
  readonly #maxOutputBytes: number;
  readonly #authenticator: AgenticSdlcQualificationAuthenticator;
  readonly #boundary: AgenticSdlcQualificationBoundary;
  readonly #stateDigester: AgenticSdlcProjectStateDigester;
  readonly #environment: Readonly<NodeJS.ProcessEnv>;

  constructor(options: AgenticSdlcQualificationRunnerOptions) {
    if (
      !isAbsolute(options.entrypointPath) ||
      !/^sha256:[a-f0-9]{64}$/u.test(options.expectedEntrypointDigest) ||
      !/^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$/u.test(
        options.expectedSdlcVersion,
      ) ||
      !Number.isInteger(options.timeoutMs) ||
      options.timeoutMs < 1 ||
      options.timeoutMs > 120_000 ||
      !Number.isInteger(options.maxOutputBytes) ||
      options.maxOutputBytes < 1_024 ||
      options.maxOutputBytes > 16 * 1024 * 1024
    ) {
      throw new AgenticSdlcQualificationError("INVALID_INPUT");
    }
    const entrypointPath = realpathSync(options.entrypointPath);
    if (!statSync(entrypointPath).isFile()) {
      throw new AgenticSdlcQualificationError("INVALID_INPUT");
    }
    if (
      sha256(readFileSync(entrypointPath)) !== options.expectedEntrypointDigest
    ) {
      throw new AgenticSdlcQualificationError("INVALID_INPUT");
    }
    this.#entrypointPath = entrypointPath;
    this.#expectedSdlcVersion = options.expectedSdlcVersion;
    this.#timeoutMs = options.timeoutMs;
    this.#maxOutputBytes = options.maxOutputBytes;
    this.#authenticator = options.authenticator;
    this.#boundary =
      options.boundary ?? new NodeAgenticSdlcQualificationBoundary();
    this.#stateDigester =
      options.stateDigester ?? new FileSystemAgenticSdlcProjectStateDigester();
    this.#environment = Object.freeze(
      sanitizeEnvironment(
        options.environment ?? {},
        new Set(options.blockedEnvironmentKeys ?? []),
      ),
    );
  }

  async run(
    input: AgenticSdlcQualificationCaseInput,
  ): Promise<AgenticSdlcQualificationResult> {
    const parsed = parseCaseInput(input);
    const roots = canonicalWorkspaceRoots(parsed.workspaceRoots);
    const initialStates = await Promise.all(
      Object.values(roots).map((root) => this.#digestState(root)),
    );
    if (new Set(initialStates).size !== 1) {
      throw new AgenticSdlcQualificationError("WORKSPACE_MISMATCH");
    }
    const expectedState = initialStates[0]!;

    let abBaseline: CompletedArm;
    let abCandidate: CompletedArm;
    let baCandidate: CompletedArm;
    let baBaseline: CompletedArm;
    if (parsed.primaryOrder === "AB") {
      abBaseline = await this.#runArm(
        roots.abBaseline,
        parsed.baselineIntent,
        expectedState,
      );
      abCandidate = await this.#runArm(
        roots.abCandidate,
        parsed.candidateIntent,
        expectedState,
      );
      baCandidate = await this.#runArm(
        roots.baCandidate,
        parsed.candidateIntent,
        expectedState,
      );
      baBaseline = await this.#runArm(
        roots.baBaseline,
        parsed.baselineIntent,
        expectedState,
      );
    } else {
      baCandidate = await this.#runArm(
        roots.baCandidate,
        parsed.candidateIntent,
        expectedState,
      );
      baBaseline = await this.#runArm(
        roots.baBaseline,
        parsed.baselineIntent,
        expectedState,
      );
      abBaseline = await this.#runArm(
        roots.abBaseline,
        parsed.baselineIntent,
        expectedState,
      );
      abCandidate = await this.#runArm(
        roots.abCandidate,
        parsed.candidateIntent,
        expectedState,
      );
    }

    const repeatable =
      sameObservation(abBaseline.private, baBaseline.private) &&
      sameObservation(abCandidate.private, baCandidate.private);
    const equivalentChannels = Object.freeze({
      route:
        sameValue(abBaseline.private.route, abCandidate.private.route) &&
        sameValue(baBaseline.private.route, baCandidate.private.route),
      contract:
        sameValue(abBaseline.private.contract, abCandidate.private.contract) &&
        sameValue(baBaseline.private.contract, baCandidate.private.contract),
      outcome:
        sameValue(abBaseline.private.outcome, abCandidate.private.outcome) &&
        sameValue(baBaseline.private.outcome, baCandidate.private.outcome),
    });
    const reasons: AgenticSdlcQualificationReason[] = [];
    if (!repeatable) reasons.push("ORDER_EFFECT");
    if (parsed.expectation.relation === "equivalent") {
      if (!Object.values(equivalentChannels).every(Boolean)) {
        reasons.push("SEMANTIC_DIVERGENCE");
      }
    } else {
      const anyDifference = Object.values(equivalentChannels).includes(false);
      if (!anyDifference) {
        reasons.push("UNSAFE_CONVERGENCE");
      } else if (
        parsed.expectation.mustDifferAnyOf.every(
          (channel) => equivalentChannels[channel],
        )
      ) {
        reasons.push("EXPECTED_DISCRIMINANT_MISSING");
      }
    }

    return deepFreeze({
      schema: AGENTIC_SDLC_QUALIFICATION_RESULT_SCHEMA,
      profile: AGENTIC_SDLC_QUALIFICATION_PROFILE,
      caseRef: parsed.caseRef,
      keyId: this.#authenticator.keyId,
      primaryOrder: parsed.primaryOrder,
      expectedRelation: parsed.expectation.relation,
      status: reasons.length === 0 ? "passed" : "failed",
      reasons,
      repeatable,
      equivalentChannels,
      observations: {
        abBaseline: abBaseline.public,
        abCandidate: abCandidate.public,
        baCandidate: baCandidate.public,
        baBaseline: baBaseline.public,
      },
    });
  }

  async #runArm(
    root: string,
    intent: z.infer<typeof intentSchema>,
    expectedState: Sha256Digest,
  ): Promise<CompletedArm> {
    const argv = [
      this.#entrypointPath,
      "task",
      "start",
      "--root",
      root,
      "--intent-json",
      JSON.stringify(intent),
      "--json",
    ] as const;
    const controller = new AbortController();
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_, rejectPromise) => {
      timer = setTimeout(() => {
        controller.abort();
        rejectPromise(new AgenticSdlcQualificationError("TIMEOUT"));
      }, this.#timeoutMs);
    });
    let result: AgenticSdlcQualificationBoundaryResult;
    try {
      result = await Promise.race([
        this.#boundary.execute({
          executablePath: process.execPath,
          argv,
          cwd: root,
          environment: this.#environment,
          timeoutMs: this.#timeoutMs,
          maxOutputBytes: this.#maxOutputBytes,
          signal: controller.signal,
          shell: false,
        }),
        timeout,
      ]);
    } catch (error) {
      const afterFailure = await this.#digestState(root);
      if (afterFailure !== expectedState) {
        throw new AgenticSdlcQualificationError("PROJECT_MUTATED");
      }
      if (error instanceof AgenticSdlcQualificationError) throw error;
      throw new AgenticSdlcQualificationError("EXECUTION_FAILED");
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
    if (
      typeof result.stdout !== "string" ||
      typeof result.stderr !== "string"
    ) {
      throw new AgenticSdlcQualificationError("MALFORMED_OUTPUT");
    }
    if (
      Buffer.byteLength(result.stdout) + Buffer.byteLength(result.stderr) >
      this.#maxOutputBytes
    ) {
      throw new AgenticSdlcQualificationError("OUTPUT_LIMIT");
    }
    if (result.stderr.length > 0) {
      throw new AgenticSdlcQualificationError("MALFORMED_OUTPUT");
    }
    const after = await this.#digestState(root);
    if (after !== expectedState) {
      throw new AgenticSdlcQualificationError("PROJECT_MUTATED");
    }
    const observation = this.#parseObservation(root, result.stdout, after);
    return {
      private: observation,
      public: this.#authenticateObservation(observation),
    };
  }

  #parseObservation(
    root: string,
    stdout: string,
    stateDigest: Sha256Digest,
  ): PrivateObservation {
    let value: unknown;
    try {
      value = JSON.parse(stdout);
    } catch {
      throw new AgenticSdlcQualificationError("MALFORMED_OUTPUT");
    }
    const parsedResult = taskStartOutputSchema.safeParse(value);
    if (!parsedResult.success) {
      throw new AgenticSdlcQualificationError("MALFORMED_OUTPUT");
    }
    const output = parsedResult.data;
    if (output.sdlc_version !== this.#expectedSdlcVersion) {
      throw new AgenticSdlcQualificationError("MALFORMED_OUTPUT");
    }
    if (
      output.contract !== undefined &&
      output.contract !== null &&
      output.contract.id !== output.contract_id
    ) {
      throw new AgenticSdlcQualificationError("MALFORMED_OUTPUT");
    }
    const checks = [...output.route_decision.deterministic_checks]
      .map(({ check, status }) => ({ check, status }))
      .sort((left, right) => left.check.localeCompare(right.check));
    const contractArtifactDigest =
      output.contract_id === null
        ? null
        : digestSelectedContract(root, output.contract_id);
    return deepFreeze({
      route: {
        profile: AGENTIC_SDLC_QUALIFICATION_PROFILE,
        sdlcVersion: output.sdlc_version,
        route: output.route,
        phase: output.phase,
        decision: {
          route: output.route_decision.route,
          status: output.route_decision.status,
          requiresConfirmation: output.route_decision.requires_confirmation,
          checks,
        },
      },
      contract: {
        storyId: output.story_id,
        contractId: output.contract_id,
        contractAction: output.contract_action,
        artifactDigest: contractArtifactDigest,
        summary:
          output.contract === undefined || output.contract === null
            ? null
            : {
                id: output.contract.id,
                phase: output.contract.phase,
                storyId: output.contract.story_id,
                status: output.contract.status,
                approved: output.contract.approved,
                readinessGaps: [...output.contract.readiness_gaps].sort(),
                freshnessGaps: [...output.contract.freshness_gaps].sort(),
              },
      },
      outcome: {
        status: output.status,
        executionAllowed: output.execution_allowed,
        requiresConfirmation: output.requires_confirmation,
        blockingReasons: [...output.blocking_reasons].sort(),
        routeBlockingReasons: [
          ...output.route_decision.blocking_reasons,
        ].sort(),
      },
      stateDigest,
    });
  }

  #authenticateObservation(
    observation: PrivateObservation,
  ): AgenticSdlcQualificationProjection {
    const routeDigest = this.#authenticator.digest("route", observation.route);
    const contractDigest = this.#authenticator.digest(
      "contract",
      observation.contract,
    );
    const outcomeDigest = this.#authenticator.digest(
      "outcome",
      observation.outcome,
    );
    const projectBindingDigest = this.#authenticator.digest(
      "project",
      observation.stateDigest,
    );
    return deepFreeze({
      schema: AGENTIC_SDLC_QUALIFICATION_OBSERVATION_SCHEMA,
      profile: AGENTIC_SDLC_QUALIFICATION_PROFILE,
      keyId: this.#authenticator.keyId,
      routeDigest,
      contractDigest,
      outcomeDigest,
      projectBindingDigest,
      observationDigest: this.#authenticator.digest("observation", {
        routeDigest,
        contractDigest,
        outcomeDigest,
        projectBindingDigest,
      }),
    });
  }

  async #digestState(root: string): Promise<Sha256Digest> {
    try {
      return await this.#stateDigester.digest(root);
    } catch (error) {
      if (error instanceof AgenticSdlcQualificationError) throw error;
      throw new AgenticSdlcQualificationError("STATE_UNAVAILABLE");
    }
  }
}

function parseCaseInput(input: unknown) {
  try {
    const root = plainDataRecord(input);
    assertExactKeys(root, [
      "baselineIntent",
      "candidateIntent",
      "caseRef",
      "expectation",
      "primaryOrder",
      "workspaceRoots",
    ]);
    const caseRef = root.caseRef;
    const primaryOrder = root.primaryOrder;
    if (
      typeof caseRef !== "string" ||
      !/^hmac-sha256:qualification-case:[a-f0-9]{64}$/u.test(caseRef) ||
      (primaryOrder !== "AB" && primaryOrder !== "BA")
    ) {
      throw invalidInput();
    }

    const expectationRecord = plainDataRecord(root.expectation);
    const relation = expectationRecord.relation;
    let expectation: AgenticSdlcQualificationExpectation;
    if (relation === "equivalent") {
      assertExactKeys(expectationRecord, ["relation"]);
      expectation = Object.freeze({ relation });
    } else if (relation === "different") {
      assertExactKeys(expectationRecord, ["mustDifferAnyOf", "relation"]);
      const channels = denseDataArray(expectationRecord.mustDifferAnyOf);
      if (
        channels.length === 0 ||
        channels.length > 3 ||
        channels.some(
          (channel) =>
            channel !== "route" &&
            channel !== "contract" &&
            channel !== "outcome",
        ) ||
        new Set(channels).size !== channels.length
      ) {
        throw invalidInput();
      }
      expectation = Object.freeze({
        relation,
        mustDifferAnyOf: Object.freeze(channels) as readonly [
          AgenticSdlcQualificationChannel,
          ...AgenticSdlcQualificationChannel[],
        ],
      });
    } else {
      throw invalidInput();
    }

    const workspaceRecord = plainDataRecord(root.workspaceRoots);
    assertExactKeys(workspaceRecord, ["baselineFirst", "candidateFirst"]);
    const baselineFirst = plainDataRecord(workspaceRecord.baselineFirst);
    const candidateFirst = plainDataRecord(workspaceRecord.candidateFirst);
    assertExactKeys(baselineFirst, ["baseline", "candidate"]);
    assertExactKeys(candidateFirst, ["baseline", "candidate"]);
    for (const value of [
      baselineFirst.baseline,
      baselineFirst.candidate,
      candidateFirst.baseline,
      candidateFirst.candidate,
    ]) {
      if (typeof value !== "string" || value.length === 0) {
        throw invalidInput();
      }
    }

    const baseline = intentSchema.safeParse(
      strictJsonSnapshot(root.baselineIntent),
    );
    const candidate = intentSchema.safeParse(
      strictJsonSnapshot(root.candidateIntent),
    );
    if (!baseline.success || !candidate.success) throw invalidInput();

    return deepFreeze({
      caseRef: caseRef as AgenticSdlcQualificationCaseRef,
      primaryOrder: primaryOrder as AgenticSdlcQualificationOrder,
      baselineIntent: baseline.data,
      candidateIntent: candidate.data,
      expectation,
      workspaceRoots: {
        baselineFirst: {
          baseline: baselineFirst.baseline as string,
          candidate: baselineFirst.candidate as string,
        },
        candidateFirst: {
          candidate: candidateFirst.candidate as string,
          baseline: candidateFirst.baseline as string,
        },
      },
    });
  } catch (error) {
    if (error instanceof AgenticSdlcQualificationError) throw error;
    throw invalidInput();
  }
}

function plainDataRecord(value: unknown): Record<string, unknown> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    isProxy(value)
  ) {
    throw invalidInput();
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw invalidInput();
  }
  if (Object.getOwnPropertySymbols(value).length !== 0) {
    throw invalidInput();
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const result: Record<string, unknown> = {};
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (
      descriptor.enumerable !== true ||
      !("value" in descriptor) ||
      descriptor.get !== undefined ||
      descriptor.set !== undefined
    ) {
      throw invalidInput();
    }
    result[key] = descriptor.value;
  }
  return result;
}

function assertExactKeys(
  record: Readonly<Record<string, unknown>>,
  expected: readonly string[],
): void {
  const actual = Object.keys(record).sort();
  const sortedExpected = [...expected].sort();
  if (
    actual.length !== sortedExpected.length ||
    actual.some((key, index) => key !== sortedExpected[index])
  ) {
    throw invalidInput();
  }
}

function denseDataArray(value: unknown): unknown[] {
  if (!Array.isArray(value) || isProxy(value)) throw invalidInput();
  if (
    Object.getPrototypeOf(value) !== Array.prototype ||
    Object.getOwnPropertySymbols(value).length !== 0
  ) {
    throw invalidInput();
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
  const rawLength =
    lengthDescriptor !== undefined && "value" in lengthDescriptor
      ? lengthDescriptor.value
      : undefined;
  if (
    typeof rawLength !== "number" ||
    !Number.isSafeInteger(rawLength) ||
    rawLength < 0 ||
    rawLength > 4_096
  ) {
    throw invalidInput();
  }
  const length = rawLength;
  const expectedKeys = new Set(["length"]);
  const result: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const key = String(index);
    expectedKeys.add(key);
    const descriptor = descriptors[key];
    if (
      descriptor === undefined ||
      descriptor.enumerable !== true ||
      !("value" in descriptor) ||
      descriptor.get !== undefined ||
      descriptor.set !== undefined
    ) {
      throw invalidInput();
    }
    result.push(descriptor.value);
  }
  if (Object.keys(descriptors).some((key) => !expectedKeys.has(key))) {
    throw invalidInput();
  }
  return result;
}

function strictJsonSnapshot(value: unknown): unknown {
  const ancestors = new Set<object>();
  const budget = { nodes: 0 };

  const snapshot = (entry: unknown, depth: number): unknown => {
    budget.nodes += 1;
    if (depth > 32 || budget.nodes > 4_096) throw invalidInput();
    if (
      entry === null ||
      typeof entry === "string" ||
      typeof entry === "boolean"
    ) {
      return entry;
    }
    if (typeof entry === "number" && Number.isFinite(entry)) return entry;
    if (typeof entry !== "object" || isProxy(entry)) throw invalidInput();
    if (ancestors.has(entry)) throw invalidInput();
    ancestors.add(entry);
    try {
      if (Array.isArray(entry)) {
        return denseDataArray(entry).map((child) => snapshot(child, depth + 1));
      }
      const record = plainDataRecord(entry);
      return Object.fromEntries(
        Object.entries(record).map(([key, child]) => [
          key,
          snapshot(child, depth + 1),
        ]),
      );
    } finally {
      ancestors.delete(entry);
    }
  };

  return snapshot(value, 0);
}

function invalidInput(): AgenticSdlcQualificationError {
  return new AgenticSdlcQualificationError("INVALID_INPUT");
}

function canonicalWorkspaceRoots(
  roots: AgenticSdlcQualificationCaseInput["workspaceRoots"],
) {
  let values: string[];
  try {
    values = [
      roots.baselineFirst.baseline,
      roots.baselineFirst.candidate,
      roots.candidateFirst.candidate,
      roots.candidateFirst.baseline,
    ].map((root) => {
      const canonical = realpathSync(root);
      if (!statSync(canonical).isDirectory()) {
        throw new TypeError("not-directory");
      }
      return canonical;
    });
  } catch {
    throw new AgenticSdlcQualificationError("INVALID_INPUT");
  }
  if (new Set(values).size !== values.length) {
    throw new AgenticSdlcQualificationError("INVALID_INPUT");
  }
  return {
    abBaseline: values[0]!,
    abCandidate: values[1]!,
    baCandidate: values[2]!,
    baBaseline: values[3]!,
  };
}

function digestSelectedContract(
  root: string,
  contractId: string,
): Sha256Digest {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(contractId)) {
    throw new AgenticSdlcQualificationError("CONTRACT_UNAVAILABLE");
  }
  try {
    const rootBefore = lstatSync(root, { bigint: true });
    const sdlcRoot = join(root, ".sdlc");
    const contractsRoot = join(root, ".sdlc", "contracts");
    const sdlcBefore = lstatSync(sdlcRoot, { bigint: true });
    const contractsBefore = lstatSync(contractsRoot, { bigint: true });
    if (
      !rootBefore.isDirectory() ||
      rootBefore.isSymbolicLink() ||
      !sdlcBefore.isDirectory() ||
      sdlcBefore.isSymbolicLink() ||
      !contractsBefore.isDirectory() ||
      contractsBefore.isSymbolicLink()
    ) {
      throw new TypeError("unsafe-contract-root");
    }
    const canonicalContractsRoot = realpathSync(contractsRoot);
    if (
      canonicalContractsRoot !== contractsRoot ||
      !pathIsInside(root, canonicalContractsRoot)
    ) {
      throw new TypeError("contract-root-escape");
    }
    const candidate = join(contractsRoot, `${contractId}.json`);
    const before = lstatSync(candidate, { bigint: true });
    if (!before.isFile() || before.isSymbolicLink()) {
      throw new TypeError("unsafe-contract");
    }
    const canonicalBefore = realpathSync(candidate);
    if (
      dirname(canonicalBefore) !== canonicalContractsRoot ||
      !pathIsInside(canonicalContractsRoot, canonicalBefore)
    ) {
      throw new TypeError("contract-escape");
    }
    const content = readFileSync(canonicalBefore);
    const after = lstatSync(candidate, { bigint: true });
    const rootAfter = lstatSync(root, { bigint: true });
    const sdlcAfter = lstatSync(sdlcRoot, { bigint: true });
    const contractsAfter = lstatSync(contractsRoot, { bigint: true });
    if (
      BigInt(content.byteLength) !== before.size ||
      !sameStableFileSnapshot(before, after) ||
      !sameStableFileSnapshot(rootBefore, rootAfter) ||
      !sameStableFileSnapshot(sdlcBefore, sdlcAfter) ||
      !sameStableFileSnapshot(contractsBefore, contractsAfter) ||
      realpathSync(contractsRoot) !== canonicalContractsRoot ||
      realpathSync(candidate) !== canonicalBefore
    ) {
      throw new TypeError("unstable-contract-snapshot");
    }
    return sha256(content);
  } catch {
    throw new AgenticSdlcQualificationError("CONTRACT_UNAVAILABLE");
  }
}

function sameStableFileSnapshot(
  left: BigIntStats,
  right: BigIntStats,
): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.uid === right.uid &&
    left.gid === right.gid &&
    left.rdev === right.rdev &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}

function pathIsInside(parent: string, child: string): boolean {
  const difference = relative(parent, child);
  return (
    difference.length > 0 &&
    difference !== ".." &&
    !difference.startsWith(`..${sep}`) &&
    !isAbsolute(difference)
  );
}

function classifyProcessError(error: Error): AgenticSdlcQualificationError {
  const details = error as Error & {
    readonly code?: string;
    readonly killed?: boolean;
    readonly signal?: string | null;
  };
  if (details.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER") {
    return new AgenticSdlcQualificationError("OUTPUT_LIMIT");
  }
  if (
    details.killed === true ||
    typeof details.signal === "string" ||
    error.name === "AbortError"
  ) {
    return new AgenticSdlcQualificationError("TIMEOUT");
  }
  return new AgenticSdlcQualificationError("EXECUTION_FAILED");
}

function excludedStatePath(path: string): boolean {
  return [".git", "node_modules", ".sdlc/cache", ".sdlc/indexes"].some(
    (prefix) => path === prefix || path.startsWith(`${prefix}/`),
  );
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

function sameObservation(left: PrivateObservation, right: PrivateObservation) {
  return (
    sameValue(left.route, right.route) &&
    sameValue(left.contract, right.contract) &&
    sameValue(left.outcome, right.outcome) &&
    left.stateDigest === right.stateDigest
  );
}

function sameValue(left: unknown, right: unknown): boolean {
  return canonicalJson(left) === canonicalJson(right);
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

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}
