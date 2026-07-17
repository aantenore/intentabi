import {
  access,
  chmod,
  link,
  lstat,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  truncate,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  CliIoError,
  readBoundedRegularFile,
  reservePrivateArtifact,
} from "../src/index.js";

const temporaryDirectories = new Set<string>();

afterEach(async () => {
  await Promise.all(
    [...temporaryDirectories].map((path) =>
      rm(path, { recursive: true, force: true }),
    ),
  );
  temporaryDirectories.clear();
});

describe("readBoundedRegularFile", () => {
  it("returns detached bytes from a regular file at the exact budget", async () => {
    const directory = await privateDirectory("intentabi-read ");
    const path = join(directory, "input with spaces.json");
    const expected = Buffer.from('{"safe":true}\n', "utf8");
    await writeFile(path, expected);

    const actual = await readBoundedRegularFile(path, expected.byteLength);

    expect(Buffer.from(actual)).toEqual(expected);
    actual[0] = 0;
    expect(await readFile(path)).toEqual(expected);
  });

  it("accepts an empty regular file without reading beyond its handle", async () => {
    const directory = await privateDirectory("intentabi-empty-");
    const path = join(directory, "empty");
    await writeFile(path, "");

    await expect(readBoundedRegularFile(path, 1)).resolves.toHaveLength(0);
  });

  it("rejects a final-component symlink and a non-regular path", async () => {
    const directory = await privateDirectory("intentabi-unsafe-read-");
    await expectCliIoError(
      readBoundedRegularFile(directory, 64),
      "INPUT_UNSAFE",
    );
    if (process.platform === "win32") return;

    const target = join(directory, "target");
    const alias = join(directory, "alias");
    await writeFile(target, "private");
    await symlink(target, alias);

    await expectCliIoError(readBoundedRegularFile(alias, 64), "INPUT_UNSAFE");
  });

  it("rejects an oversized sparse file before allocating its declared size", async () => {
    const directory = await privateDirectory("intentabi-large-read-");
    const path = join(directory, "large");
    await writeFile(path, "x");
    await truncate(path, 65_537);

    await expectCliIoError(
      readBoundedRegularFile(path, 65_536),
      "INPUT_TOO_LARGE",
    );
  });

  it("uses content-free errors for unavailable inputs and invalid budgets", async () => {
    const directory = await privateDirectory("intentabi-errors-");
    const privateMarker = "PRIVATE_INPUT_MARKER";
    const path = join(directory, privateMarker);

    const unavailable = await captureError(readBoundedRegularFile(path, 32));
    expect(unavailable).toMatchObject({ code: "INPUT_UNAVAILABLE" });
    expect(JSON.stringify(unavailable)).not.toContain(privateMarker);
    expect(unavailable.message).not.toContain(path);

    await expectCliIoError(readBoundedRegularFile(path, 0), "INVALID_POLICY");
    await expectCliIoError(
      readBoundedRegularFile(path, 128 * 1024 * 1024 + 1),
      "INVALID_POLICY",
    );
  });
});

describe("reservePrivateArtifact", () => {
  it("keeps the destination absent until complete bytes are atomically published", async () => {
    const directory = await privateDirectory("intentabi-publish ");
    const destination = join(directory, "receipt with spaces.json");
    const reservation = await reservePrivateArtifact(destination, 4_096);
    const temporary = await privateTemporaryFiles(directory);

    expect(temporary).toHaveLength(1);
    await expect(access(destination)).rejects.toThrow();
    if (process.platform !== "win32") {
      expect((await lstat(temporary[0]!)).mode & 0o777).toBe(0o600);
    }

    const bytes = Buffer.from('{"complete":true}\n', "utf8");
    await reservation.commit(bytes);

    expect(await readFile(destination)).toEqual(bytes);
    expect(await privateTemporaryFiles(directory)).toEqual([]);
    if (process.platform !== "win32") {
      expect((await lstat(destination)).mode & 0o777).toBe(0o600);
    }
  });

  it("never overwrites an existing file or follows a destination symlink", async () => {
    const directory = await privateDirectory("intentabi-no-clobber-");
    const destination = join(directory, "receipt.json");
    const marker = Buffer.from("owned-by-user", "utf8");
    await writeFile(destination, marker, { mode: 0o600 });

    await expectCliIoError(
      reservePrivateArtifact(destination, 4_096),
      "OUTPUT_EXISTS",
    );
    expect(await readFile(destination)).toEqual(marker);

    if (process.platform === "win32") return;
    const target = join(directory, "target.json");
    const alias = join(directory, "alias.json");
    await writeFile(target, marker, { mode: 0o600 });
    await symlink(target, alias);
    await expectCliIoError(
      reservePrivateArtifact(alias, 4_096),
      "OUTPUT_EXISTS",
    );
    expect(await readFile(target)).toEqual(marker);
  });

  it("preserves a file that wins the destination race after reservation", async () => {
    const directory = await privateDirectory("intentabi-external-race-");
    const destination = join(directory, "receipt.json");
    const reservation = await reservePrivateArtifact(destination, 1_024);
    const winner = Buffer.from("external-winner", "utf8");
    await writeFile(destination, winner, { mode: 0o600 });

    await expectCliIoError(
      reservation.commit(Buffer.from("candidate", "utf8")),
      "OUTPUT_EXISTS",
    );

    expect(await readFile(destination)).toEqual(winner);
    expect(await privateTemporaryFiles(directory)).toEqual([]);
  });

  it("makes concurrent publishers race through no-clobber atomic links", async () => {
    const directory = await privateDirectory("intentabi-race-");
    const destination = join(directory, "receipt.json");
    const first = await reservePrivateArtifact(destination, 1_024);
    const second = await reservePrivateArtifact(destination, 1_024);
    const firstBytes = Buffer.from("first-complete-artifact", "utf8");
    const secondBytes = Buffer.from("second-complete-artifact", "utf8");

    const results = await Promise.allSettled([
      first.commit(firstBytes),
      second.commit(secondBytes),
    ]);

    expect(results.filter((item) => item.status === "fulfilled")).toHaveLength(
      1,
    );
    const failure = results.find((item) => item.status === "rejected");
    expect(failure).toMatchObject({
      status: "rejected",
      reason: { code: "OUTPUT_EXISTS" },
    });
    const published = await readFile(destination);
    expect([firstBytes, secondBytes]).toContainEqual(published);
    expect(await privateTemporaryFiles(directory)).toEqual([]);
  });

  it("snapshots caller bytes before the first asynchronous filesystem step", async () => {
    const directory = await privateDirectory("intentabi-snapshot-");
    const destination = join(directory, "receipt.json");
    const reservation = await reservePrivateArtifact(destination, 1_024);
    const bytes = Buffer.from("immutable-snapshot", "utf8");
    const expected = Buffer.from(bytes);

    const committing = reservation.commit(bytes);
    bytes.fill(0x78);
    await committing;

    expect(await readFile(destination)).toEqual(expected);
  });

  it("copies typed-array internals without invoking hostile overrides", async () => {
    const directory = await privateDirectory("intentabi-hostile-bytes-");
    const destination = join(directory, "receipt.json");
    const reservation = await reservePrivateArtifact(destination, 1_024);
    const bytes = new Uint8Array(Buffer.from("safe-bytes", "utf8"));
    let hostileCalls = 0;
    for (const key of ["buffer", "byteLength", "byteOffset"] as const) {
      Object.defineProperty(bytes, key, {
        configurable: true,
        get: () => {
          hostileCalls += 1;
          throw new Error("hostile getter");
        },
      });
    }
    Object.defineProperty(bytes, Symbol.iterator, {
      value: () => {
        hostileCalls += 1;
        throw new Error("hostile iterator");
      },
    });

    await reservation.commit(bytes);

    expect(await readFile(destination)).toEqual(
      Buffer.from("safe-bytes", "utf8"),
    );
    expect(hostileCalls).toBe(0);
  });

  it("rejects proxied byte views without invoking traps or leaving artifacts", async () => {
    const directory = await privateDirectory("intentabi-proxy-bytes-");
    const destination = join(directory, "receipt.json");
    const reservation = await reservePrivateArtifact(destination, 1_024);
    let trapCalls = 0;
    const bytes = new Proxy(new Uint8Array([1, 2, 3]), {
      get: () => {
        trapCalls += 1;
        return undefined;
      },
      getOwnPropertyDescriptor: () => {
        trapCalls += 1;
        return undefined;
      },
    });

    await expectCliIoError(
      reservation.commit(bytes as unknown as Uint8Array),
      "INVALID_POLICY",
    );

    expect(trapCalls).toBe(0);
    await expect(access(destination)).rejects.toThrow();
    expect(await privateTemporaryFiles(directory)).toEqual([]);
  });

  it("serializes commit ownership on one reservation", async () => {
    const directory = await privateDirectory("intentabi-one-reservation-");
    const destination = join(directory, "receipt.json");
    const reservation = await reservePrivateArtifact(destination, 1_024);

    const first = reservation.commit(Buffer.from("first", "utf8"));
    const second = reservation.commit(Buffer.from("second", "utf8"));
    const secondError = captureError(second);
    await reservation.abort();

    await first;
    expect(await secondError).toMatchObject({ code: "RESERVATION_CLOSED" });
    expect(await readFile(destination)).toEqual(Buffer.from("first", "utf8"));
    expect(await privateTemporaryFiles(directory)).toEqual([]);
  });

  it("contains a destination hard-link hijack of its private reservation", async () => {
    const directory = await privateDirectory("intentabi-hardlink-hijack-");
    const destination = join(directory, "receipt.json");
    const reservation = await reservePrivateArtifact(destination, 1_024);
    const [temporary] = await privateTemporaryFiles(directory);
    expect(temporary).toBeDefined();
    await link(temporary!, destination);

    await expectCliIoError(
      reservation.commit(Buffer.from("PRIVATE CANDIDATE", "utf8")),
      "OUTPUT_FAILED",
    );

    await expect(access(destination)).rejects.toThrow();
    expect(await privateTemporaryFiles(directory)).toEqual([]);
  });

  it("aborts without publishing and treats a settled reservation as closed", async () => {
    const directory = await privateDirectory("intentabi-abort-");
    const destination = join(directory, "receipt.json");
    const reservation = await reservePrivateArtifact(destination, 1_024);

    await reservation.abort();
    await reservation.abort();

    await expect(access(destination)).rejects.toThrow();
    expect(await privateTemporaryFiles(directory)).toEqual([]);
    await expectCliIoError(
      reservation.commit(Buffer.from("late", "utf8")),
      "RESERVATION_CLOSED",
    );
  });

  it("removes its reservation and publishes nothing when output exceeds budget", async () => {
    const directory = await privateDirectory("intentabi-output-budget-");
    const destination = join(directory, "receipt.json");
    const reservation = await reservePrivateArtifact(destination, 4);

    await expectCliIoError(
      reservation.commit(Buffer.from("12345", "utf8")),
      "OUTPUT_TOO_LARGE",
    );

    await expect(access(destination)).rejects.toThrow();
    expect(await privateTemporaryFiles(directory)).toEqual([]);
  });

  it("refuses an untrusted parent and reports no output path or payload", async () => {
    const directory = await privateDirectory("intentabi-parent-");
    const destination = join(directory, "PRIVATE_OUTPUT_NAME");
    if (process.platform !== "win32") await chmod(directory, 0o777);

    if (process.platform !== "win32") {
      const error = await captureError(
        reservePrivateArtifact(destination, 1_024),
      );
      expect(error).toMatchObject({ code: "OUTPUT_UNSAFE" });
      expect(JSON.stringify(error)).not.toContain("PRIVATE_OUTPUT_NAME");
      expect(error.message).not.toContain(destination);
    }
  });

  it("rejects invalid output policies without creating a temporary file", async () => {
    const directory = await privateDirectory("intentabi-policy-");

    await expectCliIoError(
      reservePrivateArtifact(join(directory, "receipt"), 0),
      "INVALID_POLICY",
    );
    await expectCliIoError(
      reservePrivateArtifact("bad\0path", 1_024),
      "OUTPUT_UNSAFE",
    );
    expect(await privateTemporaryFiles(directory)).toEqual([]);
  });
});

async function privateDirectory(prefix: string): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), prefix));
  temporaryDirectories.add(directory);
  if (process.platform !== "win32") await chmod(directory, 0o700);
  return directory;
}

async function privateTemporaryFiles(directory: string): Promise<string[]> {
  return (await readdir(directory))
    .filter((name) => /^\.intentabi-private-[a-f0-9]{32}\.tmp$/u.test(name))
    .map((name) => join(directory, name));
}

async function expectCliIoError(
  promise: Promise<unknown>,
  code: CliIoError["code"],
): Promise<void> {
  const error = await captureError(promise);
  expect(error).toBeInstanceOf(CliIoError);
  expect(error.code).toBe(code);
}

async function captureError(promise: Promise<unknown>): Promise<CliIoError> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof CliIoError) return error;
    throw error;
  }
  throw new Error("Expected promise to reject");
}
