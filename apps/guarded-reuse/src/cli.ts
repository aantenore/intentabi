import { TextDecoder } from "node:util";
import { resolve } from "node:path";

import { readBoundedRegularFile } from "@intentabi/cli-io";
import { parseSgdGuardedReuseConfig } from "./config.js";
import { executeSgdGuardedReuse } from "./study.js";

const MAX_CONFIG_BYTES = 1024 * 1024;
const MAX_SCHEMA_BYTES = 1024 * 1024;
const MAX_DIALOGUES_BYTES = 8 * 1024 * 1024;
const APP_VERSION = "0.3.0-alpha.1";

export interface GuardedReuseCliIo {
  stdout(value: string): void;
  stderr(value: string): void;
}

export interface GuardedReuseCliDependencies {
  execute: typeof executeSgdGuardedReuse;
}

const defaultDependencies: GuardedReuseCliDependencies = Object.freeze({
  execute: executeSgdGuardedReuse,
});

export async function runGuardedReuseCli(
  argv: readonly string[],
  environment: Readonly<Record<string, string | undefined>>,
  io: GuardedReuseCliIo,
  overrides: Partial<GuardedReuseCliDependencies> = {},
): Promise<number> {
  try {
    if (argv.length === 1 && argv[0] === "--help") {
      io.stdout(`${guardedReuseUsage()}\n`);
      return 0;
    }
    if (argv.length === 1 && argv[0] === "--version") {
      io.stdout(`${APP_VERSION}\n`);
      return 0;
    }

    const options = parseArguments(argv);
    const config = parseSgdGuardedReuseConfig(
      await readJson(resolve(options.configPath), MAX_CONFIG_BYTES),
    );
    const secret = environment[config.study.hmacSecretEnv];
    if (secret === undefined || Buffer.byteLength(secret) < 32) {
      throw new GuardedReuseCliError(
        "The configured guarded-reuse HMAC secret is missing or too short",
      );
    }

    const [schemaBytes, dialoguesBytes] = await Promise.all([
      readBoundedRegularFile(resolve(options.schemaPath), MAX_SCHEMA_BYTES),
      readBoundedRegularFile(
        resolve(options.dialoguesPath),
        MAX_DIALOGUES_BYTES,
      ),
    ]);
    const result = (overrides.execute ?? defaultDependencies.execute)({
      config,
      schemaBytes,
      dialoguesBytes,
      hmacSecret: secret,
    });
    io.stdout(
      `${JSON.stringify({ event: "intentabi.guarded-reuse.report", ...result })}\n`,
    );
    return result.report.summary.gate.passed ? 0 : 2;
  } catch (error) {
    io.stderr(
      `${JSON.stringify({
        event: "intentabi.guarded-reuse.error",
        message:
          error instanceof GuardedReuseCliError
            ? error.message
            : "Guarded reuse evaluation failed",
      })}\n`,
    );
    return 1;
  }
}

function parseArguments(argv: readonly string[]): {
  readonly configPath: string;
  readonly schemaPath: string;
  readonly dialoguesPath: string;
} {
  if (argv.length !== 6) {
    throw new GuardedReuseCliError(guardedReuseUsage());
  }
  const values = new Map<string, string>();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (
      (name !== "--config" && name !== "--schema" && name !== "--dialogues") ||
      value === undefined ||
      value.startsWith("--") ||
      values.has(name)
    ) {
      throw new GuardedReuseCliError(guardedReuseUsage());
    }
    values.set(name, value);
  }
  const configPath = values.get("--config");
  const schemaPath = values.get("--schema");
  const dialoguesPath = values.get("--dialogues");
  if (
    configPath === undefined ||
    schemaPath === undefined ||
    dialoguesPath === undefined
  ) {
    throw new GuardedReuseCliError(guardedReuseUsage());
  }
  return Object.freeze({ configPath, schemaPath, dialoguesPath });
}

async function readJson(path: string, maximumBytes: number): Promise<unknown> {
  const bytes = await readBoundedRegularFile(path, maximumBytes);
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
}

export function guardedReuseUsage(): string {
  return "Usage: intentabi-guarded-reuse --config <config.json> --schema <schema.json> --dialogues <dialogues.json>";
}

class GuardedReuseCliError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GuardedReuseCliError";
  }
}
