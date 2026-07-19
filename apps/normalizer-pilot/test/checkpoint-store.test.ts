import { createHash } from "node:crypto";
import {
  chmod,
  lstat,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { openPrivateRunStore } from "@intentabi/private-run-store";
import {
  INTENT_EVALUATION_CHECKPOINT_CLAIM_SCHEMA,
  INTENT_EVALUATION_CHECKPOINT_SCHEMA,
  type IntentEvaluationCheckpoint,
  type IntentEvaluationCheckpointClaim,
} from "semwitness/intent";
import { afterEach, describe, expect, it } from "vitest";

import {
  createNormalizerPilotCheckpointStore,
  NORMALIZER_PILOT_CHECKPOINT_PARTITIONS,
  NORMALIZER_PILOT_RUN_BINDING_FILE,
} from "../src/checkpoint-store.js";

const temporaryDirectories = new Set<string>();
const maximumBytes = 16_384;

afterEach(async () => {
  await Promise.all(
    [...temporaryDirectories].map((path) =>
      rm(path, { recursive: true, force: true }),
    ),
  );
  temporaryDirectories.clear();
});

describe("createNormalizerPilotCheckpointStore", () => {
  it("persists append-only claim and completion primitives", async () => {
    const fixture = await checkpointFixture();
    const claim = checkpointClaim("partial-primitives");
    const checkpoint = evaluationCheckpoint(claim);
    const fileName = checkpointFileName(claim);

    await expect(fixture.adapter.inspect(claim)).resolves.toEqual({
      status: "missing",
    });
    const owner = await acquire(fixture.adapter.begin(claim));
    await expect(fixture.adapter.inspect(claim)).resolves.toEqual({
      status: "indeterminate",
    });
    await expect(fixture.adapter.begin(claim)).resolves.toEqual({
      status: "indeterminate",
    });

    await owner.commit(checkpoint);
    await owner.commit(checkpoint);
    await expect(fixture.adapter.inspect(claim)).resolves.toEqual({
      status: "completed",
      checkpoint,
    });
    await expect(fixture.adapter.begin(claim)).resolves.toEqual({
      status: "completed",
      checkpoint,
    });

    const claimBytes = await readFile(join(fixture.claimsPath, fileName));
    const checkpointBytes = await readFile(
      join(fixture.checkpointsPath, fileName),
    );
    expect(claimBytes).toEqual(encodeCanonical(claim));
    expect(checkpointBytes).toEqual(encodeCanonical(checkpoint));
    expect(claimBytes.at(-1)).toBe(0x0a);
    expect(checkpointBytes.at(-1)).toBe(0x0a);
    if (process.platform !== "win32") {
      expect(
        (await lstat(join(fixture.claimsPath, fileName))).mode & 0o777,
      ).toBe(0o600);
      expect(
        (await lstat(join(fixture.checkpointsPath, fileName))).mode & 0o777,
      ).toBe(0o600);
    }
  });

  it("lets exactly one concurrent worker acquire a missing claim", async () => {
    const fixture = await checkpointFixture();
    const claim = checkpointClaim("concurrent-begin");

    const results = await Promise.all([
      fixture.adapter.begin(claim),
      fixture.adapter.begin(claim),
    ]);

    expect(
      results.filter((result) => result.status === "acquired"),
    ).toHaveLength(1);
    expect(
      results.filter((result) => result.status === "indeterminate"),
    ).toHaveLength(1);
    expect(await readdir(fixture.claimsPath)).toEqual([
      checkpointFileName(claim),
    ]);
    expect(await readdir(fixture.checkpointsPath)).toEqual([]);
  });

  it("rejects wrong claims, mismatched slots, and tampered records", async () => {
    const fixture = await checkpointFixture();
    const claim = checkpointClaim("tamper-boundary");
    const invalidClaim = {
      ...claim,
      claimDigest: digest("invalid-claim-digest"),
    } as IntentEvaluationCheckpointClaim;

    await expect(fixture.adapter.inspect(invalidClaim)).rejects.toThrow(
      "Normalizer pilot checkpoint store failed",
    );
    const owner = await acquire(fixture.adapter.begin(claim));

    const mismatchedClaim = checkpointClaim("different-slot", {
      checkpointRef: claim.checkpointRef,
    });
    await expect(
      owner.commit(evaluationCheckpoint(mismatchedClaim)),
    ).rejects.toThrow("Normalizer pilot checkpoint store failed");

    const checkpoint = evaluationCheckpoint(claim);
    await owner.commit(checkpoint);
    const fileName = checkpointFileName(claim);
    const tamperedCheckpoint = {
      ...checkpoint,
      observation: {
        ...checkpoint.observation,
        actual: "bypass",
      },
    };
    await writeFile(
      join(fixture.checkpointsPath, fileName),
      encodeCanonical(tamperedCheckpoint),
    );
    await expect(fixture.adapter.inspect(claim)).rejects.toThrow(
      "Normalizer pilot checkpoint store failed",
    );

    await writeFile(
      join(fixture.checkpointsPath, fileName),
      encodeCanonical(checkpoint),
    );
    await writeFile(
      join(fixture.claimsPath, fileName),
      encodeCanonical({ ...claim, attemptOrdinal: claim.attemptOrdinal + 1 }),
    );
    await expect(fixture.adapter.inspect(claim)).rejects.toThrow(
      "Normalizer pilot checkpoint store failed",
    );
  });

  it("exposes a durable checkpoint after commit acknowledgement is lost", async () => {
    const fixture = await checkpointFixture();
    const claim = checkpointClaim("lost-acknowledgement");
    const checkpoint = evaluationCheckpoint(claim);
    const owner = await acquire(fixture.adapter.begin(claim));

    await expect(
      (async () => {
        await owner.commit(checkpoint);
        throw new Error("simulated lost acknowledgement");
      })(),
    ).rejects.toThrow("simulated lost acknowledgement");

    await expect(fixture.adapter.inspect(claim)).resolves.toEqual({
      status: "completed",
      checkpoint,
    });
    await expect(fixture.adapter.begin(claim)).resolves.toEqual({
      status: "completed",
      checkpoint,
    });
  });

  it.runIf(process.platform !== "win32")(
    "inherits symlink and owner-permission rejection from the private store",
    async () => {
      const symlinkFixture = await checkpointFixture();
      const symlinkClaim = checkpointClaim("symlink-claim");
      const symlinkName = checkpointFileName(symlinkClaim);
      const target = join(symlinkFixture.parent, "claim-target.json");
      await writeFile(target, encodeCanonical(symlinkClaim), { mode: 0o600 });
      await symlink(
        target,
        join(symlinkFixture.claimsPath, symlinkName),
        "file",
      );
      await expect(
        symlinkFixture.adapter.inspect(symlinkClaim),
      ).rejects.toThrow("Normalizer pilot checkpoint store failed");

      const permissionFixture = await checkpointFixture();
      const permissionClaim = checkpointClaim("permissive-claim");
      const permissionName = checkpointFileName(permissionClaim);
      const claimPath = join(permissionFixture.claimsPath, permissionName);
      await writeFile(claimPath, encodeCanonical(permissionClaim), {
        mode: 0o600,
      });
      await chmod(claimPath, 0o644);
      await expect(
        permissionFixture.adapter.inspect(permissionClaim),
      ).rejects.toThrow("Normalizer pilot checkpoint store failed");
    },
  );

  it("never persists content-bearing checkpoint fields or leaks them in errors", async () => {
    const fixture = await checkpointFixture();
    const claim = checkpointClaim("content-free");
    const marker = "RAW_USER_CANARY_DO_NOT_PERSIST";
    const owner = await acquire(fixture.adapter.begin(claim));
    const checkpoint = evaluationCheckpoint(claim);
    const contentBearingPayload = {
      ...withoutRecordDigest(checkpoint),
      observation: {
        ...checkpoint.observation,
        fingerprint: marker,
      },
    };
    const contentBearingCheckpoint = {
      ...contentBearingPayload,
      recordDigest: hashCanonical(contentBearingPayload),
    } as unknown as IntentEvaluationCheckpoint;

    const error = await captureError(owner.commit(contentBearingCheckpoint));
    expect(error.message).toBe("Normalizer pilot checkpoint store failed");
    expect(error.message).not.toContain(marker);
    expect(await readdir(fixture.checkpointsPath)).toEqual([]);

    await owner.commit(checkpoint);
    const persisted = await readTree(fixture.runPath);
    expect(persisted).not.toContain(marker);
    expect(persisted).not.toContain("rawInput");

    const extraFieldClaim = {
      ...checkpointClaim("extra-content-field"),
      rawInput: marker,
    } as unknown as IntentEvaluationCheckpointClaim;
    const claimError = await captureError(
      fixture.adapter.begin(extraFieldClaim),
    );
    expect(claimError.message).not.toContain(marker);
  });

  it("enforces an explicit per-record byte budget and declares the shared layout", async () => {
    const parent = await temporaryDirectory("intentabi-checkpoint-budget-");
    const store = await openPrivateRunStore({
      path: join(parent, "run"),
      partitions: NORMALIZER_PILOT_CHECKPOINT_PARTITIONS,
    });
    expect(NORMALIZER_PILOT_RUN_BINDING_FILE).toBe(
      "normalizer-pilot-run-binding.json",
    );
    expect(() =>
      createNormalizerPilotCheckpointStore({ store, maximumBytes: 0 }),
    ).toThrow("Normalizer pilot checkpoint store failed");

    const bounded = createNormalizerPilotCheckpointStore({
      store,
      maximumBytes: 32,
    });
    await expect(
      bounded.begin(checkpointClaim("record-over-budget")),
    ).rejects.toThrow("Normalizer pilot checkpoint store failed");
  });
});

async function checkpointFixture() {
  const parent = await temporaryDirectory("intentabi-checkpoint-store-");
  const runPath = join(parent, "run");
  const store = await openPrivateRunStore({
    path: runPath,
    partitions: NORMALIZER_PILOT_CHECKPOINT_PARTITIONS,
  });
  return {
    parent,
    runPath,
    claimsPath: store.partition("claims").path,
    checkpointsPath: store.partition("checkpoints").path,
    adapter: createNormalizerPilotCheckpointStore({ store, maximumBytes }),
  };
}

function checkpointClaim(
  seed: string,
  overrides: Partial<
    Pick<
      IntentEvaluationCheckpointClaim,
      "checkpointRef" | "evaluationBindingDigest" | "caseRef" | "attemptOrdinal"
    >
  > = {},
): IntentEvaluationCheckpointClaim {
  const payload = {
    schema: INTENT_EVALUATION_CHECKPOINT_CLAIM_SCHEMA,
    checkpointRef: overrides.checkpointRef ?? digest(`checkpoint:${seed}`),
    evaluationBindingDigest:
      overrides.evaluationBindingDigest ?? digest(`evaluation:${seed}`),
    caseRef: overrides.caseRef ?? digest(`case:${seed}`),
    attemptOrdinal: overrides.attemptOrdinal ?? 0,
  } as const;
  return Object.freeze({ ...payload, claimDigest: hashCanonical(payload) });
}

function evaluationCheckpoint(
  claim: IntentEvaluationCheckpointClaim,
): IntentEvaluationCheckpoint {
  const payload = {
    schema: INTENT_EVALUATION_CHECKPOINT_SCHEMA,
    mode: "shadow" as const,
    activeCacheQualified: false as const,
    checkpointRef: claim.checkpointRef,
    evaluationBindingDigest: claim.evaluationBindingDigest,
    caseRef: claim.caseRef,
    attemptOrdinal: claim.attemptOrdinal,
    observation: Object.freeze({
      actual: "intent" as const,
      fingerprint: digest("fingerprint"),
      intentDigest: digest("intent"),
      reasons: Object.freeze(["INTENT_NORMALIZATION_ELIGIBLE"] as const),
      executionFailure: false,
      contractDigest: digest("contract"),
      normalizerBindingDigest: digest("normalizer"),
      ontologyBindingDigest: digest("ontology"),
    }),
  } as const;
  return Object.freeze({ ...payload, recordDigest: hashCanonical(payload) });
}

async function acquire(
  resultInput: ReturnType<
    ReturnType<typeof createNormalizerPilotCheckpointStore>["begin"]
  >,
) {
  const result = await resultInput;
  if (result.status !== "acquired") {
    throw new Error("test expected checkpoint acquisition");
  }
  return result;
}

function checkpointFileName(claim: IntentEvaluationCheckpointClaim): string {
  return `${claim.checkpointRef.slice(7)}.json`;
}

function withoutRecordDigest(checkpoint: IntentEvaluationCheckpoint) {
  const { recordDigest: _recordDigest, ...payload } = checkpoint;
  return payload;
}

function digest(value: string): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}

function hashCanonical(value: unknown): `sha256:${string}` {
  return digest(canonicalJson(value));
}

function encodeCanonical(value: unknown): Buffer {
  return Buffer.from(`${canonicalJson(value)}\n`, "utf8");
}

function canonicalJson(value: unknown): string {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string" ||
    typeof value === "number"
  ) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  if (value === null || typeof value !== "object") {
    throw new Error("test value is not JSON");
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(",")}}`;
}

async function temporaryDirectory(prefix: string): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), prefix));
  temporaryDirectories.add(path);
  return path;
}

async function captureError(promise: Promise<unknown>): Promise<Error> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof Error) return error;
  }
  throw new Error("test expected an error");
}

async function readTree(path: string): Promise<string> {
  const entries = await readdir(path, { withFileTypes: true });
  const chunks: string[] = [];
  for (const entry of entries) {
    const child = join(path, entry.name);
    if (entry.isDirectory()) chunks.push(await readTree(child));
    else if (entry.isFile()) chunks.push(await readFile(child, "utf8"));
  }
  return chunks.join("\n");
}
