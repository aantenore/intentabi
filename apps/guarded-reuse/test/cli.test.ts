import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { runGuardedReuseCli } from "../src/cli.js";
import { syntheticSgdFixture } from "./support.js";

const directories: string[] = [];
const secret = "guarded-reuse-cli-secret-with-at-least-32-bytes";

afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

describe("guarded reuse CLI", () => {
  it("reads caller-supplied files and prints only a redacted JSON report", async () => {
    const fixture = await syntheticSgdFixture();
    const paths = await writeFixture(fixture);
    const stdout: string[] = [];
    const stderr: string[] = [];

    const code = await runGuardedReuseCli(
      [
        "--config",
        paths.config,
        "--schema",
        paths.schema,
        "--dialogues",
        paths.dialogues,
      ],
      { [fixture.config.study.hmacSecretEnv]: secret },
      {
        stdout: (value) => stdout.push(value),
        stderr: (value) => stderr.push(value),
      },
    );

    expect(code).toBe(0);
    expect(stderr).toEqual([]);
    expect(stdout).toHaveLength(1);
    const event = JSON.parse(stdout[0]!) as {
      event: string;
      selectionOrderDigest: string;
      report: { summary: { gate: { passed: boolean } } };
    };
    expect(event).toMatchObject({
      event: "intentabi.guarded-reuse.report",
      report: { summary: { gate: { passed: true } } },
    });
    for (const token of fixture.privateTokens) {
      expect(stdout[0]).not.toContain(token);
    }
  });

  it("rejects a symlinked source and never invokes the study", async () => {
    const fixture = await syntheticSgdFixture();
    const paths = await writeFixture(fixture);
    const linkedSchema = join(paths.directory, "linked-schema.json");
    await symlink(paths.schema, linkedSchema);
    let invoked = false;
    const stderr: string[] = [];

    const code = await runGuardedReuseCli(
      [
        "--config",
        paths.config,
        "--schema",
        linkedSchema,
        "--dialogues",
        paths.dialogues,
      ],
      { [fixture.config.study.hmacSecretEnv]: secret },
      { stdout: () => undefined, stderr: (value) => stderr.push(value) },
      {
        execute: () => {
          invoked = true;
          throw new Error("must not run");
        },
      },
    );

    expect(code).toBe(1);
    expect(invoked).toBe(false);
    expect(stderr.join("")).toContain("Guarded reuse evaluation failed");
  });

  it("requires the configured HMAC environment secret", async () => {
    const fixture = await syntheticSgdFixture();
    const paths = await writeFixture(fixture);
    const stderr: string[] = [];

    const code = await runGuardedReuseCli(
      [
        "--config",
        paths.config,
        "--schema",
        paths.schema,
        "--dialogues",
        paths.dialogues,
      ],
      {},
      { stdout: () => undefined, stderr: (value) => stderr.push(value) },
    );

    expect(code).toBe(1);
    expect(stderr.join("")).toContain("HMAC secret is missing or too short");
  });
});

async function writeFixture(
  fixture: Awaited<ReturnType<typeof syntheticSgdFixture>>,
) {
  const directory = await mkdtemp(join(tmpdir(), "intentabi-guarded-reuse-"));
  directories.push(directory);
  const config = join(directory, "config.json");
  const schema = join(directory, "schema.json");
  const dialogues = join(directory, "dialogues.json");
  await Promise.all([
    writeFile(config, JSON.stringify(fixture.config), { mode: 0o600 }),
    writeFile(schema, fixture.schemaBytes, { mode: 0o600 }),
    writeFile(dialogues, fixture.dialoguesBytes, { mode: 0o600 }),
  ]);
  return Object.freeze({ directory, config, schema, dialogues });
}
