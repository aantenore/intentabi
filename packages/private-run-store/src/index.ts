import type { BigIntStats } from "node:fs";
import { lstat, mkdir, readdir, realpath, unlink } from "node:fs/promises";
import { basename, join, resolve } from "node:path";

import {
  CliIoError,
  MAX_CLI_IO_BYTES,
  readBoundedRegularFile,
  reservePrivateArtifact,
  snapshotBoundedBytes,
} from "@intentabi/cli-io";

const COMPONENT_PATTERN = /^[a-z0-9][a-z0-9._-]{0,254}$/u;
const WINDOWS_RESERVED_COMPONENT =
  /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/u;
const PRIVATE_TEMPORARY_FILE = /^\.intentabi-private-[a-f0-9]{32}\.tmp$/u;

export type PrivateRunStoreCreateResult = "created" | "exists";

export interface OpenPrivateRunStoreInput {
  readonly path: string;
  readonly partitions?: readonly string[];
}

export interface PrivateRunStorePartition {
  readonly path: string;
  readOptional(name: string, maximumBytes: number): Promise<Uint8Array | null>;
  create(
    name: string,
    bytes: Uint8Array,
    maximumBytes: number,
  ): Promise<PrivateRunStoreCreateResult>;
  publishOrVerify(
    name: string,
    bytes: Uint8Array,
    maximumBytes: number,
  ): Promise<void>;
}

export interface PrivateRunStore {
  readonly root: PrivateRunStorePartition;
  partition(name: string): PrivateRunStorePartition;
  guard<T>(operation: () => Promise<T>): Promise<T>;
  assertStable(): Promise<void>;
}

/** A deliberately content-free filesystem boundary error. */
export class PrivateRunStoreError extends Error {
  constructor() {
    super("Private run store failed");
    this.name = "PrivateRunStoreError";
  }
}

/**
 * Opens a run directory and its declared child partitions. POSIX modes and UID
 * are owner-private; Windows deployments must provide an equivalently private
 * ACL. Every operation verifies captured directory identities before and after
 * filesystem work so callers can safely resume append-only runs.
 */
export async function openPrivateRunStore(
  input: OpenPrivateRunStoreInput,
): Promise<PrivateRunStore> {
  try {
    assertRunPath(input.path);
    const names = normalizePartitionNames(input.partitions ?? []);
    const rootIdentity = await ensurePrivateDirectory(input.path);
    const partitionIdentities = new Map<string, PrivateDirectoryIdentity>();
    for (const name of names) {
      const identity = await ensurePrivateDirectory(
        join(rootIdentity.path, name),
        rootIdentity,
      );
      if (
        [...partitionIdentities.values()].some((existing) =>
          sameDirectory(existing, identity),
        )
      ) {
        throw new PrivateRunStoreError();
      }
      partitionIdentities.set(name, identity);
    }

    const layout = Object.freeze({
      root: rootIdentity,
      partitions: Object.freeze([...partitionIdentities.values()]),
    });
    await assertStableLayout(layout);

    const guard = async <T>(operation: () => Promise<T>): Promise<T> => {
      if (typeof operation !== "function") throw new PrivateRunStoreError();
      await assertStableLayout(layout);
      try {
        const value = await operation();
        await assertStableLayout(layout);
        return value;
      } catch (error) {
        await assertStableLayout(layout);
        throw error;
      }
    };
    const root = createPartition(rootIdentity, layout, guard);
    const partitions = new Map<string, PrivateRunStorePartition>();
    for (const [name, identity] of partitionIdentities) {
      partitions.set(name, createPartition(identity, layout, guard));
    }

    return Object.freeze({
      root,
      partition: (name: string): PrivateRunStorePartition => {
        assertComponent(name);
        const partition = partitions.get(name);
        if (partition === undefined) throw new PrivateRunStoreError();
        return partition;
      },
      guard,
      assertStable: async (): Promise<void> => assertStableLayout(layout),
    });
  } catch (error) {
    if (error instanceof PrivateRunStoreError) throw error;
    throw new PrivateRunStoreError();
  }
}

function createPartition(
  identity: PrivateDirectoryIdentity,
  layout: PrivateRunLayout,
  guard: <T>(operation: () => Promise<T>) => Promise<T>,
): PrivateRunStorePartition {
  const destination = (name: string): string => {
    assertComponent(name);
    const path = join(identity.path, name);
    if (basename(path) !== name) throw new PrivateRunStoreError();
    return path;
  };

  const readOptional = async (
    name: string,
    maximumBytes: number,
  ): Promise<Uint8Array | null> => {
    const path = destination(name);
    assertMaximumBytes(maximumBytes);
    return translateErrors(() =>
      guard(async () => {
        const before = await lstat(path, { bigint: true }).catch(
          (error: unknown) => {
            if (hasCode(error, "ENOENT")) return null;
            throw new PrivateRunStoreError();
          },
        );
        if (before === null) return null;
        const readableBefore = await recoverPublishedArtifact(
          identity.path,
          path,
          before,
        );
        const bytes = await readBoundedRegularFile(path, maximumBytes);
        const after = await lstat(path, { bigint: true }).catch(() => {
          throw new PrivateRunStoreError();
        });
        assertPrivateArtifact(after);
        if (!sameDirectory(readableBefore, after)) {
          throw new PrivateRunStoreError();
        }
        return bytes;
      }),
    );
  };

  const create = async (
    name: string,
    bytes: Uint8Array,
    maximumBytes: number,
  ): Promise<PrivateRunStoreCreateResult> => {
    const path = destination(name);
    assertMaximumBytes(maximumBytes);
    const snapshot = snapshotBytes(bytes, maximumBytes);
    return translateErrors(() =>
      guard(async () => {
        let reservation;
        try {
          reservation = await reservePrivateArtifact(path, maximumBytes);
        } catch (error) {
          if (error instanceof CliIoError && error.code === "OUTPUT_EXISTS") {
            return "exists" as const;
          }
          throw error;
        }
        try {
          await assertStableLayout(layout);
          await reservation.commit(snapshot);
          await assertStableLayout(layout);
          return "created" as const;
        } catch (error) {
          await reservation.abort();
          if (error instanceof CliIoError && error.code === "OUTPUT_EXISTS") {
            return "exists" as const;
          }
          throw error;
        }
      }),
    );
  };

  return Object.freeze({
    path: identity.path,
    readOptional,
    create,
    publishOrVerify: async (
      name: string,
      bytes: Uint8Array,
      maximumBytes: number,
    ): Promise<void> => {
      destination(name);
      assertMaximumBytes(maximumBytes);
      const snapshot = snapshotBytes(bytes, maximumBytes);
      const existing = await readOptional(name, maximumBytes);
      if (existing !== null) {
        if (!equalBytes(existing, snapshot)) throw new PrivateRunStoreError();
        return;
      }
      if ((await create(name, snapshot, maximumBytes)) === "created") return;
      const concurrent = await readOptional(name, maximumBytes);
      if (concurrent === null || !equalBytes(concurrent, snapshot)) {
        throw new PrivateRunStoreError();
      }
    },
  });
}

interface PrivateDirectoryIdentity {
  readonly path: string;
  readonly dev: bigint;
  readonly ino: bigint;
}

interface PrivateRunLayout {
  readonly root: PrivateDirectoryIdentity;
  readonly partitions: readonly PrivateDirectoryIdentity[];
}

async function ensurePrivateDirectory(
  path: string,
  expectedParent?: PrivateDirectoryIdentity,
): Promise<PrivateDirectoryIdentity> {
  const absolute = resolve(path);
  if (expectedParent !== undefined) {
    await assertSamePrivateDirectory(expectedParent);
  }

  const initial = await lstatOptional(absolute);
  if (initial === null) {
    await mkdir(absolute, { recursive: true, mode: 0o700 }).catch(() => {
      throw new PrivateRunStoreError();
    });
  } else {
    assertPrivateDirectory(initial);
  }

  if (expectedParent !== undefined) {
    await assertSamePrivateDirectory(expectedParent);
  }
  const beforeRealpath = await lstatPrivateDirectory(absolute);
  if (initial !== null && !sameDirectory(initial, beforeRealpath)) {
    throw new PrivateRunStoreError();
  }

  const canonical = await realpath(absolute).catch(() => {
    throw new PrivateRunStoreError();
  });
  const [canonicalState, pathAfterRealpath] = await Promise.all([
    lstatPrivateDirectory(canonical),
    lstatPrivateDirectory(absolute),
  ]);
  if (
    !sameDirectory(beforeRealpath, canonicalState) ||
    !sameDirectory(beforeRealpath, pathAfterRealpath)
  ) {
    throw new PrivateRunStoreError();
  }
  if (expectedParent !== undefined) {
    await assertSamePrivateDirectory(expectedParent);
  }
  return Object.freeze({
    path: canonical,
    dev: canonicalState.dev,
    ino: canonicalState.ino,
  });
}

async function assertStableLayout(layout: PrivateRunLayout): Promise<void> {
  await assertSamePrivateDirectory(layout.root);
  for (const partition of layout.partitions) {
    await assertSamePrivateDirectory(partition);
  }
  await assertSamePrivateDirectory(layout.root);
}

async function assertSamePrivateDirectory(
  expected: PrivateDirectoryIdentity,
): Promise<void> {
  const current = await lstatPrivateDirectory(expected.path);
  if (!sameDirectory(expected, current)) throw new PrivateRunStoreError();
}

async function lstatOptional(path: string): Promise<BigIntStats | null> {
  try {
    return await lstat(path, { bigint: true });
  } catch (error) {
    if (hasCode(error, "ENOENT")) return null;
    throw new PrivateRunStoreError();
  }
}

async function lstatPrivateDirectory(path: string): Promise<BigIntStats> {
  const state = await lstat(path, { bigint: true }).catch(() => {
    throw new PrivateRunStoreError();
  });
  assertPrivateDirectory(state);
  return state;
}

function assertPrivateDirectory(state: BigIntStats): void {
  if (
    !state.isDirectory() ||
    state.isSymbolicLink() ||
    (process.platform !== "win32" && Number(state.mode & 0o077n) !== 0) ||
    (typeof process.getuid === "function" &&
      state.uid !== BigInt(process.getuid()))
  ) {
    throw new PrivateRunStoreError();
  }
}

function assertPrivateArtifact(state: BigIntStats): void {
  assertPrivateArtifactWithLinks(state, 1n);
}

function assertPrivateArtifactWithLinks(
  state: BigIntStats,
  expectedLinks: bigint,
): void {
  if (
    !state.isFile() ||
    state.isSymbolicLink() ||
    state.nlink !== expectedLinks ||
    (process.platform !== "win32" && Number(state.mode & 0o777n) !== 0o600) ||
    (typeof process.getuid === "function" &&
      state.uid !== BigInt(process.getuid()))
  ) {
    throw new PrivateRunStoreError();
  }
}

async function recoverPublishedArtifact(
  directory: string,
  path: string,
  state: BigIntStats,
): Promise<BigIntStats> {
  if (state.nlink === 1n) {
    assertPrivateArtifact(state);
    return state;
  }
  assertPrivateArtifactWithLinks(state, 2n);

  const matchingTemporaryPaths: string[] = [];
  for (const name of await readdir(directory).catch(() => {
    throw new PrivateRunStoreError();
  })) {
    if (!PRIVATE_TEMPORARY_FILE.test(name)) continue;
    const temporaryPath = join(directory, name);
    const temporaryState = await lstat(temporaryPath, { bigint: true }).catch(
      () => null,
    );
    if (
      temporaryState !== null &&
      sameDirectory(state, temporaryState) &&
      temporaryState.nlink === 2n
    ) {
      assertPrivateArtifactWithLinks(temporaryState, 2n);
      matchingTemporaryPaths.push(temporaryPath);
    }
  }
  if (matchingTemporaryPaths.length !== 1) {
    const recovered = await revalidateRecoveredArtifact(path, state);
    if (recovered !== null) return recovered;
    throw new PrivateRunStoreError();
  }

  const temporaryPath = matchingTemporaryPaths[0]!;
  const [finalBefore, temporaryBefore] = await Promise.all([
    lstat(path, { bigint: true }).catch(() => null),
    lstat(temporaryPath, { bigint: true }).catch(() => null),
  ]);
  if (
    finalBefore === null ||
    temporaryBefore === null ||
    !sameDirectory(state, finalBefore) ||
    !sameDirectory(state, temporaryBefore)
  ) {
    const recovered = await revalidateRecoveredArtifact(path, state);
    if (recovered !== null) return recovered;
    throw new PrivateRunStoreError();
  }
  assertPrivateArtifactWithLinks(finalBefore, 2n);
  assertPrivateArtifactWithLinks(temporaryBefore, 2n);

  await unlink(temporaryPath).catch((error: unknown) => {
    if (!hasCode(error, "ENOENT")) throw new PrivateRunStoreError();
  });
  const recovered = await revalidateRecoveredArtifact(
    path,
    state,
    temporaryPath,
  );
  if (recovered === null) throw new PrivateRunStoreError();
  return recovered;
}

async function revalidateRecoveredArtifact(
  path: string,
  identity: BigIntStats,
  temporaryPath?: string,
): Promise<BigIntStats | null> {
  const [finalState, temporaryState] = await Promise.all([
    lstat(path, { bigint: true }).catch(() => null),
    temporaryPath === undefined
      ? Promise.resolve(null)
      : lstat(temporaryPath, { bigint: true }).catch((error: unknown) => {
          if (hasCode(error, "ENOENT")) return null;
          throw new PrivateRunStoreError();
        }),
  ]);
  if (
    finalState === null ||
    temporaryState !== null ||
    !sameDirectory(identity, finalState)
  ) {
    return null;
  }
  try {
    assertPrivateArtifact(finalState);
    return finalState;
  } catch {
    return null;
  }
}

function normalizePartitionNames(names: readonly string[]): readonly string[] {
  if (!Array.isArray(names)) throw new PrivateRunStoreError();
  const seen = new Set<string>();
  for (const name of names) {
    assertComponent(name);
    if (seen.has(name)) throw new PrivateRunStoreError();
    seen.add(name);
  }
  return Object.freeze([...seen]);
}

function assertRunPath(path: string): void {
  if (
    typeof path !== "string" ||
    path.length === 0 ||
    path.length > 4_096 ||
    path.includes("\0")
  ) {
    throw new PrivateRunStoreError();
  }
}

function assertComponent(value: string): void {
  if (
    typeof value !== "string" ||
    !COMPONENT_PATTERN.test(value) ||
    value.endsWith(".") ||
    WINDOWS_RESERVED_COMPONENT.test(value)
  ) {
    throw new PrivateRunStoreError();
  }
}

function assertMaximumBytes(maximumBytes: number): void {
  if (
    !Number.isSafeInteger(maximumBytes) ||
    maximumBytes < 1 ||
    maximumBytes > MAX_CLI_IO_BYTES
  ) {
    throw new PrivateRunStoreError();
  }
}

function sameDirectory(
  left: Readonly<{ dev: bigint; ino: bigint }>,
  right: Readonly<{ dev: bigint; ino: bigint }>,
): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  try {
    return Buffer.from(left).equals(Buffer.from(right));
  } catch {
    throw new PrivateRunStoreError();
  }
}

function snapshotBytes(bytes: Uint8Array, maximumBytes: number): Uint8Array {
  try {
    return snapshotBoundedBytes(bytes, maximumBytes);
  } catch {
    throw new PrivateRunStoreError();
  }
}

async function translateErrors<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof PrivateRunStoreError) throw error;
    throw new PrivateRunStoreError();
  }
}

function hasCode(error: unknown, code: string): boolean {
  return (
    error !== null &&
    typeof error === "object" &&
    Object.getOwnPropertyDescriptor(error, "code")?.value === code
  );
}
