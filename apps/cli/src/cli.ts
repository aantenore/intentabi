import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

import {
  AgenticSdlcCliRoute,
  AgenticSdlcRouteError,
  FixtureAgenticSdlcRoute,
} from "@intentabi/adapter-agentic-sdlc";
import { SemWitnessIntentInspector } from "@intentabi/adapter-semwitness";
import {
  createHmacOpaqueDigester,
  ShadowRuntime,
  type EvidenceSink,
} from "@intentabi/core";
import { MemoryShadowStore } from "@intentabi/store-memory";
import { z } from "zod";

import { parseIntentAbiConfig, strictJsonValueSchema } from "./config.js";

const requestSchema = z
  .object({
    schema: z.literal("io.github.aantenore.intentabi/shadow-request/v1alpha1"),
    source: z.string().min(1).max(16_384),
    locale: z.string().regex(/^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,4}$/u),
    routeInput: strictJsonValueSchema,
  })
  .strict();

export interface CliIo {
  stdout(value: string): void;
  stderr(value: string): void;
}

export async function runCli(
  argv: readonly string[],
  environment: Readonly<Record<string, string | undefined>>,
  io: CliIo,
): Promise<number> {
  try {
    if (argv.length === 1 && argv[0] === "--help") {
      io.stdout(`${usage()}\n`);
      return 0;
    }
    if (argv.length === 1 && argv[0] === "--version") {
      const manifest = await readJson(
        new URL("../package.json", import.meta.url),
        "IntentABI package metadata is unavailable",
      );
      const version = z.object({ version: z.string() }).parse(manifest).version;
      io.stdout(`${version}\n`);
      return 0;
    }

    const options = parseArguments(argv);
    const configPath = resolve(options.configPath);
    const configDirectory = dirname(configPath);
    const config = parseConfig(
      await readJson(configPath, "IntentABI configuration could not be read"),
    );
    const request = parseRequest(
      await readJson(
        resolve(options.requestPath),
        "IntentABI request could not be read",
      ),
    );
    const secret = environment[config.semwitness.hmacSecretEnv];
    if (secret === undefined || Buffer.byteLength(secret) < 32) {
      throw new PublicCliError(
        "The configured IntentABI HMAC secret is missing or too short",
      );
    }

    const digester = createHmacOpaqueDigester(secret, config.evidence.keyId);
    const evidenceSink: EvidenceSink = {
      emit: async (envelope, signal) => {
        if (signal.aborted) throw new DOMException("Aborted", "AbortError");
        io.stderr(
          `${JSON.stringify({ event: "intentabi.shadow.evidence", envelope })}\n`,
        );
      },
    };
    const inspector = new SemWitnessIntentInspector({
      registrySource: await readText(
        resolve(configDirectory, config.semwitness.registryPath),
        "SemWitness registry could not be read",
      ),
      policyDigest: config.semwitness.policyDigest as `sha256:${string}`,
      hmacSecret: secret,
      expectedScope: config.semwitness.expectedScope,
      routeBindings: config.semwitness.routeBindings,
    });
    const route =
      config.agenticSdlc.kind === "fixture"
        ? new FixtureAgenticSdlcRoute(
            await readText(
              resolve(configDirectory, config.agenticSdlc.fixturePath),
              "Agentic SDLC fixture could not be read",
            ),
          )
        : new AgenticSdlcCliRoute({
            entrypointPath: resolve(
              configDirectory,
              config.agenticSdlc.entrypointPath,
            ),
            allowedRoot: resolve(configDirectory, config.agenticSdlc.rootPath),
            deploymentRevisionDigest: config.agenticSdlc
              .deploymentRevisionDigest as `sha256:${string}`,
            timeoutMs: config.agenticSdlc.timeoutMs,
            maxOutputBytes: config.agenticSdlc.maxOutputBytes,
            environment: childEnvironment(
              environment,
              config.semwitness.hmacSecretEnv,
            ),
            blockedEnvironmentKeys: [config.semwitness.hmacSecretEnv],
          });
    const runtime = new ShadowRuntime({
      inspector,
      store: new MemoryShadowStore({ faultMode: config.store.faultMode }),
      route,
      digester,
      evidenceSink,
      timeouts: config.timeouts,
    });

    const result = await runtime.run({
      source: request.source,
      locale: request.locale,
      scope: config.semwitness.expectedScope,
      scopeEpoch: config.semwitness.scopeEpoch,
      routeInput: request.routeInput,
    });
    io.stdout(
      `${JSON.stringify({
        event: "intentabi.shadow.result",
        output: result.output,
        evidenceDigest: result.evidenceDigest,
        evidenceDelivery: result.evidenceDelivery,
      })}\n`,
    );
    return 0;
  } catch (error) {
    io.stderr(
      `${JSON.stringify({
        event: "intentabi.error",
        message: publicErrorMessage(error),
      })}\n`,
    );
    return 1;
  }
}

function parseArguments(argv: readonly string[]): {
  readonly configPath: string;
  readonly requestPath: string;
} {
  if (argv[0] !== "shadow" || argv[1] !== "run" || argv.length !== 6) {
    throw new PublicCliError(usage());
  }
  const options = new Map<string, string>();
  for (let index = 2; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (
      (name !== "--config" && name !== "--request") ||
      value === undefined ||
      value.startsWith("--") ||
      options.has(name)
    ) {
      throw new PublicCliError(usage());
    }
    options.set(name, value);
  }
  const configPath = options.get("--config");
  const requestPath = options.get("--request");
  if (configPath === undefined || requestPath === undefined) {
    throw new PublicCliError(usage());
  }
  return { configPath, requestPath };
}

function parseConfig(value: unknown) {
  try {
    return parseIntentAbiConfig(value);
  } catch {
    throw new PublicCliError("IntentABI configuration is invalid");
  }
}

function parseRequest(value: unknown) {
  try {
    return requestSchema.parse(value);
  } catch {
    throw new PublicCliError("IntentABI request is invalid");
  }
}

async function readJson(path: string | URL, message: string): Promise<unknown> {
  try {
    return JSON.parse(await readFile(path, "utf8"));
  } catch {
    throw new PublicCliError(message);
  }
}

async function readText(path: string, message: string): Promise<string> {
  try {
    return await readFile(path, "utf8");
  } catch {
    throw new PublicCliError(message);
  }
}

function childEnvironment(
  environment: Readonly<Record<string, string | undefined>>,
  secretName: string,
): Readonly<Record<string, string | undefined>> {
  const allowed = ["PATH", "SystemRoot", "WINDIR", "TEMP", "TMP", "TMPDIR"];
  return Object.fromEntries(
    allowed.flatMap((key) =>
      key === secretName || environment[key] === undefined
        ? []
        : [[key, environment[key]]],
    ),
  );
}

function usage(): string {
  return "Usage: intentabi shadow run --config <path> --request <path>";
}

class PublicCliError extends Error {}

function publicErrorMessage(error: unknown): string {
  return error instanceof PublicCliError ||
    error instanceof AgenticSdlcRouteError
    ? error.message
    : "IntentABI command failed";
}
