import { randomBytes } from "node:crypto";
import { constants } from "node:fs";
import {
  link,
  lstat,
  open,
  realpath,
  rm,
  type FileHandle,
} from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { isProxy, isUint8Array } from "node:util/types";

export const MAX_CLI_IO_BYTES = 128 * 1024 * 1024;
const MAX_TEMPORARY_FILE_ATTEMPTS = 16;
const TEMPORARY_SUFFIX_PATTERN = /^[a-f0-9]{32}$/u;
const PRIVATE_FILE_MODE = 0o600;
const TYPED_ARRAY_PROTOTYPE = Object.getPrototypeOf(
  Uint8Array.prototype,
) as object;
const TYPED_ARRAY_BUFFER_GETTER = Object.getOwnPropertyDescriptor(
  TYPED_ARRAY_PROTOTYPE,
  "buffer",
)?.get;
const TYPED_ARRAY_BYTE_LENGTH_GETTER = Object.getOwnPropertyDescriptor(
  TYPED_ARRAY_PROTOTYPE,
  "byteLength",
)?.get;
const TYPED_ARRAY_BYTE_OFFSET_GETTER = Object.getOwnPropertyDescriptor(
  TYPED_ARRAY_PROTOTYPE,
  "byteOffset",
)?.get;

export type CliIoErrorCode =
  | "INVALID_POLICY"
  | "INPUT_CHANGED"
  | "INPUT_TOO_LARGE"
  | "INPUT_UNAVAILABLE"
  | "INPUT_UNSAFE"
  | "OUTPUT_EXISTS"
  | "OUTPUT_FAILED"
  | "OUTPUT_TOO_LARGE"
  | "OUTPUT_UNSAFE"
  | "RESERVATION_CLOSED";

const ERROR_MESSAGES: Readonly<Record<CliIoErrorCode, string>> = Object.freeze({
  INVALID_POLICY: "CLI I/O policy is invalid",
  INPUT_CHANGED: "CLI input changed while being read",
  INPUT_TOO_LARGE: "CLI input exceeds its byte budget",
  INPUT_UNAVAILABLE: "CLI input is unavailable",
  INPUT_UNSAFE: "CLI input path is unsafe",
  OUTPUT_EXISTS: "CLI output already exists",
  OUTPUT_FAILED: "CLI output could not be published",
  OUTPUT_TOO_LARGE: "CLI output exceeds its byte budget",
  OUTPUT_UNSAFE: "CLI output path is unsafe",
  RESERVATION_CLOSED: "CLI output reservation is closed",
});

/** A deliberately content-free filesystem error safe for a CLI boundary. */
export class CliIoError extends Error {
  readonly code: CliIoErrorCode;

  constructor(code: CliIoErrorCode) {
    super(ERROR_MESSAGES[code]);
    this.name = "CliIoError";
    this.code = code;
  }
}

/**
 * Read one stable regular file without following a final-component symlink.
 * The returned bytes are detached from the internal over-read buffer.
 */
export async function readBoundedRegularFile(
  path: string,
  maximumBytes: number,
): Promise<Uint8Array> {
  assertPath(path, "input");
  assertMaximumBytes(maximumBytes);

  let pathBefore;
  try {
    pathBefore = await lstat(path, { bigint: true });
  } catch {
    throw new CliIoError("INPUT_UNAVAILABLE");
  }
  if (!pathBefore.isFile() || pathBefore.isSymbolicLink()) {
    throw new CliIoError("INPUT_UNSAFE");
  }
  if (pathBefore.size > BigInt(maximumBytes)) {
    throw new CliIoError("INPUT_TOO_LARGE");
  }

  const noFollow = process.platform === "win32" ? 0 : constants.O_NOFOLLOW;
  let handle: FileHandle | undefined;
  try {
    try {
      handle = await open(path, constants.O_RDONLY | noFollow);
    } catch {
      throw new CliIoError("INPUT_CHANGED");
    }
    const openedBefore = await handle.stat({ bigint: true });
    if (!openedBefore.isFile()) throw new CliIoError("INPUT_UNSAFE");
    if (!sameIdentity(pathBefore, openedBefore)) {
      throw new CliIoError("INPUT_CHANGED");
    }
    if (openedBefore.size > BigInt(maximumBytes)) {
      throw new CliIoError("INPUT_TOO_LARGE");
    }

    const expectedBytes = Number(openedBefore.size);
    const buffer = Buffer.alloc(expectedBytes + 1);
    let total = 0;
    while (total < buffer.byteLength) {
      const { bytesRead } = await handle.read(
        buffer,
        total,
        buffer.byteLength - total,
        total,
      );
      if (bytesRead === 0) break;
      total += bytesRead;
    }
    if (total > maximumBytes) throw new CliIoError("INPUT_TOO_LARGE");

    const [openedAfter, pathAfter] = await Promise.all([
      handle.stat({ bigint: true }),
      lstat(path, { bigint: true }).catch(() => undefined),
    ]);
    if (
      total !== expectedBytes ||
      !sameSnapshot(openedBefore, openedAfter) ||
      pathAfter === undefined ||
      !pathAfter.isFile() ||
      pathAfter.isSymbolicLink() ||
      !sameIdentity(openedAfter, pathAfter)
    ) {
      throw new CliIoError("INPUT_CHANGED");
    }
    return Uint8Array.from(buffer.subarray(0, total));
  } catch (error) {
    if (error instanceof CliIoError) throw error;
    throw new CliIoError("INPUT_UNAVAILABLE");
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

export interface PrivateArtifactReservation {
  /** Publish complete bytes atomically at the reserved destination. */
  commit(bytes: Uint8Array): Promise<void>;
  /**
   * Close an open reservation and remove its unpublished private sibling.
   * Once commit owns the reservation, abort is an idempotent no-op.
   */
  abort(): Promise<void>;
}

/**
 * Copy a real Uint8Array without consulting overridable properties or its
 * iterator. The copy is made synchronously and is bounded before allocation.
 */
export function snapshotBoundedBytes(
  bytes: Uint8Array,
  maximumBytes: number,
): Uint8Array {
  assertMaximumBytes(maximumBytes);
  const byteLength = intrinsicUint8ArrayByteLength(bytes);
  if (byteLength === null) throw new CliIoError("INVALID_POLICY");
  if (byteLength > maximumBytes) throw new CliIoError("OUTPUT_TOO_LARGE");
  const snapshot = copyUint8Array(bytes, byteLength);
  if (snapshot === null) throw new CliIoError("INVALID_POLICY");
  return snapshot;
}

/**
 * Reserve a private sibling before expensive work, then publish a complete,
 * synced 0600 artifact through a no-clobber hard link. The final path is never
 * visible with partial content.
 */
export async function reservePrivateArtifact(
  path: string,
  maximumBytes: number,
): Promise<PrivateArtifactReservation> {
  assertPath(path, "output");
  assertMaximumBytes(maximumBytes);

  const absolutePath = resolve(path);
  let canonicalParent: string;
  try {
    canonicalParent = await realpath(dirname(absolutePath));
  } catch {
    throw new CliIoError("OUTPUT_UNSAFE");
  }
  const parent = await lstat(canonicalParent, { bigint: true }).catch(
    () => undefined,
  );
  if (parent === undefined || !isTrustedPrivateDirectory(parent)) {
    throw new CliIoError("OUTPUT_UNSAFE");
  }

  const destination = join(canonicalParent, basename(absolutePath));
  const destinationState = await lstat(destination).catch((error: unknown) => {
    if (hasCode(error, "ENOENT")) return undefined;
    throw new CliIoError("OUTPUT_UNSAFE");
  });
  if (destinationState !== undefined) throw new CliIoError("OUTPUT_EXISTS");

  const temporary = await openPrivateTemporaryFile(canonicalParent);
  const identity = await temporary.handle.stat({ bigint: true });
  if (
    !identity.isFile() ||
    !(await isSameTrustedDirectory(canonicalParent, parent))
  ) {
    await temporary.handle.close().catch(() => undefined);
    await rm(temporary.path, { force: true }).catch(() => undefined);
    throw new CliIoError("OUTPUT_FAILED");
  }

  let handle: FileHandle | undefined = temporary.handle;
  let state: "open" | "committing" | "settled" = "open";

  return Object.freeze({
    commit: async (bytes: Uint8Array): Promise<void> => {
      if (state !== "open") throw new CliIoError("RESERVATION_CLOSED");
      state = "committing";

      const byteLength = intrinsicUint8ArrayByteLength(bytes);
      if (byteLength === null) {
        state = "settled";
        await closeAndRemove(handle, temporary.path, identity);
        handle = undefined;
        throw new CliIoError("INVALID_POLICY");
      }
      if (byteLength > maximumBytes) {
        state = "settled";
        await closeAndRemove(handle, temporary.path, identity);
        handle = undefined;
        throw new CliIoError("OUTPUT_TOO_LARGE");
      }
      // Snapshot synchronously before the first await. The caller can mutate,
      // detach, or reuse its view as soon as commit() returns its Promise.
      const snapshot = copyUint8Array(bytes, byteLength);
      if (snapshot === null) {
        state = "settled";
        await closeAndRemove(handle, temporary.path, identity);
        handle = undefined;
        throw new CliIoError("INVALID_POLICY");
      }

      let destinationLinked = false;
      try {
        if (
          handle === undefined ||
          !(await isSameFile(temporary.path, identity)) ||
          !(await isSameTrustedDirectory(canonicalParent, parent)) ||
          !(await isExclusiveFileHandle(handle, identity))
        ) {
          throw new CliIoError("OUTPUT_FAILED");
        }
        const destinationBefore = await lstat(destination).catch(
          (error: unknown) => {
            if (hasCode(error, "ENOENT")) return undefined;
            throw new CliIoError("OUTPUT_FAILED");
          },
        );
        if (destinationBefore !== undefined) {
          throw new CliIoError("OUTPUT_EXISTS");
        }
        await handle.writeFile(snapshot);
        await handle.chmod(PRIVATE_FILE_MODE);
        await handle.sync();
        if (
          !(await isSameFile(temporary.path, identity)) ||
          !(await isSameTrustedDirectory(canonicalParent, parent)) ||
          !(await isExclusiveFileHandle(handle, identity))
        ) {
          throw new CliIoError("OUTPUT_FAILED");
        }
        await handle.close();
        handle = undefined;

        try {
          await link(temporary.path, destination);
          destinationLinked = true;
        } catch (error) {
          if (hasCode(error, "EEXIST")) {
            throw new CliIoError("OUTPUT_EXISTS");
          }
          throw new CliIoError("OUTPUT_FAILED");
        }
        if (
          !(await isSameTrustedDirectory(canonicalParent, parent)) ||
          !(await isSamePrivateFile(destination, identity, 2n))
        ) {
          throw new CliIoError("OUTPUT_FAILED");
        }
        await removeSameFile(temporary.path, identity);
        if (await isSameFile(temporary.path, identity)) {
          throw new CliIoError("OUTPUT_FAILED");
        }
        if (
          !(await isSameTrustedDirectory(canonicalParent, parent)) ||
          !(await isSamePrivateFile(destination, identity, 1n))
        ) {
          throw new CliIoError("OUTPUT_FAILED");
        }
        state = "settled";
      } catch (error) {
        state = "settled";
        await handle?.close().catch(() => undefined);
        handle = undefined;
        if (destinationLinked || (await isSameFile(destination, identity))) {
          await removeSameFile(destination, identity);
        }
        await removeSameFile(temporary.path, identity);
        if (error instanceof CliIoError) throw error;
        throw new CliIoError("OUTPUT_FAILED");
      }
    },
    abort: async (): Promise<void> => {
      if (state !== "open") return;
      state = "settled";
      await closeAndRemove(handle, temporary.path, identity);
      handle = undefined;
    },
  });
}

async function openPrivateTemporaryFile(parent: string): Promise<{
  readonly path: string;
  readonly handle: FileHandle;
}> {
  const noFollow = process.platform === "win32" ? 0 : constants.O_NOFOLLOW;
  for (let attempt = 0; attempt < MAX_TEMPORARY_FILE_ATTEMPTS; attempt += 1) {
    const suffix = randomBytes(16).toString("hex");
    if (!TEMPORARY_SUFFIX_PATTERN.test(suffix)) break;
    const path = join(parent, `.intentabi-private-${suffix}.tmp`);
    try {
      return {
        path,
        handle: await open(
          path,
          constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | noFollow,
          PRIVATE_FILE_MODE,
        ),
      };
    } catch (error) {
      if (!hasCode(error, "EEXIST")) {
        throw new CliIoError("OUTPUT_FAILED");
      }
    }
  }
  throw new CliIoError("OUTPUT_FAILED");
}

function assertPath(path: string, kind: "input" | "output"): void {
  if (
    typeof path !== "string" ||
    path.length === 0 ||
    path.length > 4_096 ||
    path.includes("\0")
  ) {
    throw new CliIoError(kind === "input" ? "INPUT_UNSAFE" : "OUTPUT_UNSAFE");
  }
}

function assertMaximumBytes(maximumBytes: number): void {
  if (
    !Number.isSafeInteger(maximumBytes) ||
    maximumBytes < 1 ||
    maximumBytes > MAX_CLI_IO_BYTES
  ) {
    throw new CliIoError("INVALID_POLICY");
  }
}

function sameIdentity(
  left: Readonly<{ dev: bigint; ino: bigint }>,
  right: Readonly<{ dev: bigint; ino: bigint }>,
): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function sameSnapshot(
  left: Readonly<{
    dev: bigint;
    ino: bigint;
    size: bigint;
    mtimeNs: bigint;
    ctimeNs: bigint;
  }>,
  right: Readonly<{
    dev: bigint;
    ino: bigint;
    size: bigint;
    mtimeNs: bigint;
    ctimeNs: bigint;
  }>,
): boolean {
  return (
    sameIdentity(left, right) &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}

async function isSameFile(
  path: string,
  identity: Readonly<{ dev: bigint; ino: bigint }>,
): Promise<boolean> {
  const current = await lstat(path, { bigint: true }).catch(() => undefined);
  return (
    current !== undefined &&
    current.isFile() &&
    !current.isSymbolicLink() &&
    sameIdentity(current, identity)
  );
}

async function isSamePrivateFile(
  path: string,
  identity: Readonly<{ dev: bigint; ino: bigint }>,
  expectedLinks?: bigint,
): Promise<boolean> {
  const current = await lstat(path, { bigint: true }).catch(() => undefined);
  return (
    current !== undefined &&
    current.isFile() &&
    !current.isSymbolicLink() &&
    sameIdentity(current, identity) &&
    (expectedLinks === undefined || current.nlink === expectedLinks) &&
    (process.platform === "win32" ||
      Number(current.mode & 0o777n) === PRIVATE_FILE_MODE)
  );
}

async function isExclusiveFileHandle(
  handle: FileHandle,
  identity: Readonly<{ dev: bigint; ino: bigint }>,
): Promise<boolean> {
  const current = await handle.stat({ bigint: true }).catch(() => undefined);
  return (
    current !== undefined &&
    current.isFile() &&
    sameIdentity(current, identity) &&
    current.nlink === 1n
  );
}

function isTrustedPrivateDirectory(
  value: Readonly<{
    isDirectory(): boolean;
    isSymbolicLink(): boolean;
    mode: bigint;
    uid: bigint;
  }>,
): boolean {
  return (
    value.isDirectory() &&
    !value.isSymbolicLink() &&
    (process.platform === "win32" || Number(value.mode & 0o022n) === 0) &&
    (typeof process.getuid !== "function" ||
      value.uid === BigInt(process.getuid()))
  );
}

async function isSameTrustedDirectory(
  path: string,
  identity: Readonly<{ dev: bigint; ino: bigint }>,
): Promise<boolean> {
  const current = await lstat(path, { bigint: true }).catch(() => undefined);
  return (
    current !== undefined &&
    sameIdentity(current, identity) &&
    isTrustedPrivateDirectory(current)
  );
}

async function closeAndRemove(
  handle: FileHandle | undefined,
  path: string,
  identity: Readonly<{ dev: bigint; ino: bigint }>,
): Promise<void> {
  await handle?.close().catch(() => undefined);
  await removeSameFile(path, identity);
}

async function removeSameFile(
  path: string,
  identity: Readonly<{ dev: bigint; ino: bigint }>,
): Promise<void> {
  if (await isSameFile(path, identity)) {
    await rm(path, { force: true }).catch(() => undefined);
  }
}

function hasCode(error: unknown, code: string): boolean {
  if (error === null || typeof error !== "object" || isProxy(error)) {
    return false;
  }
  const descriptor = Object.getOwnPropertyDescriptor(error, "code");
  return (
    descriptor !== undefined &&
    "value" in descriptor &&
    descriptor.value === code
  );
}

function intrinsicUint8ArrayByteLength(value: unknown): number | null {
  if (
    value === null ||
    typeof value !== "object" ||
    isProxy(value) ||
    !isUint8Array(value) ||
    TYPED_ARRAY_BYTE_LENGTH_GETTER === undefined
  ) {
    return null;
  }
  try {
    const result = Reflect.apply(TYPED_ARRAY_BYTE_LENGTH_GETTER, value, []);
    return typeof result === "number" && Number.isSafeInteger(result)
      ? result
      : null;
  } catch {
    return null;
  }
}

function copyUint8Array(
  value: Uint8Array,
  expectedByteLength: number,
): Uint8Array | null {
  if (
    isProxy(value) ||
    TYPED_ARRAY_BUFFER_GETTER === undefined ||
    TYPED_ARRAY_BYTE_OFFSET_GETTER === undefined
  ) {
    return null;
  }
  try {
    const buffer = Reflect.apply(
      TYPED_ARRAY_BUFFER_GETTER,
      value,
      [],
    ) as ArrayBufferLike;
    const byteOffset = Reflect.apply(TYPED_ARRAY_BYTE_OFFSET_GETTER, value, []);
    if (typeof byteOffset !== "number" || !Number.isSafeInteger(byteOffset)) {
      return null;
    }
    const view = new Uint8Array(buffer, byteOffset, expectedByteLength);
    return new Uint8Array(view);
  } catch {
    return null;
  }
}
