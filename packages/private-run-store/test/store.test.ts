import {
  access,
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { openPrivateRunStore, PrivateRunStoreError } from "../src/index.js";

const temporaryDirectories = new Set<string>();

afterEach(async () => {
  await Promise.all(
    [...temporaryDirectories].map((path) =>
      rm(path, { recursive: true, force: true }),
    ),
  );
  temporaryDirectories.clear();
});

describe("openPrivateRunStore", () => {
  it("creates an owner-private root and declared partitions", async () => {
    const parent = await temporaryDirectory("intentabi-run-layout-");
    const run = join(parent, "nested", "run");

    const store = await openPrivateRunStore({
      path: run,
      partitions: ["records", "receipts"],
    });

    expect(store.root.path).toBe(await canonicalPath(run));
    expect(store.partition("records").path).toBe(
      await canonicalPath(join(run, "records")),
    );
    await expect(store.assertStable()).resolves.toBeUndefined();
    if (process.platform !== "win32") {
      expect((await lstat(run)).mode & 0o777).toBe(0o700);
      expect((await lstat(join(run, "records"))).mode & 0o777).toBe(0o700);
      expect((await lstat(join(run, "receipts"))).mode & 0o777).toBe(0o700);
    }
  });

  it("rejects duplicate, undeclared, and path-like partition names", async () => {
    const parent = await temporaryDirectory("intentabi-run-partitions-");
    const run = join(parent, "run");

    await expectStoreError(
      openPrivateRunStore({ path: run, partitions: ["records", "records"] }),
    );
    await expectStoreError(
      openPrivateRunStore({ path: run, partitions: ["../records"] }),
    );
    await expectStoreError(
      openPrivateRunStore({ path: run, partitions: ["records", "RECORDS"] }),
    );
    await expectStoreError(
      openPrivateRunStore({ path: run, partitions: ["con"] }),
    );

    const store = await openPrivateRunStore({
      path: run,
      partitions: ["records"],
    });
    expect(() => store.partition("missing")).toThrow(PrivateRunStoreError);
    expect(() => store.partition("../records")).toThrow(PrivateRunStoreError);
  });

  it("uses content-free errors for invalid run paths", async () => {
    const marker = "PRIVATE_RUN_MARKER";
    const error = await captureStoreError(
      openPrivateRunStore({ path: `${marker}\0` }),
    );

    expect(error.message).not.toContain(marker);
    expect(JSON.stringify(error)).not.toContain(marker);
  });

  it.runIf(process.platform !== "win32")(
    "rejects permissive roots and final-component directory symlinks",
    async () => {
      const parent = await temporaryDirectory("intentabi-run-private-");
      const permissive = join(parent, "permissive");
      await mkdir(permissive, { mode: 0o700 });
      await chmod(permissive, 0o755);
      await expectStoreError(openPrivateRunStore({ path: permissive }));

      const target = join(parent, "target");
      const alias = join(parent, "alias");
      await mkdir(target, { mode: 0o700 });
      await symlink(target, alias, "dir");
      await expectStoreError(openPrivateRunStore({ path: alias }));
    },
  );

  it.runIf(process.platform !== "win32")(
    "rejects permissive and symlinked declared partitions",
    async () => {
      const parent = await temporaryDirectory("intentabi-partition-private-");
      const run = join(parent, "run");
      const records = join(run, "records");
      await mkdir(records, { recursive: true, mode: 0o700 });
      await chmod(records, 0o750);
      await expectStoreError(
        openPrivateRunStore({ path: run, partitions: ["records"] }),
      );

      await rm(records, { recursive: true });
      const target = join(parent, "target-records");
      await mkdir(target, { mode: 0o700 });
      await symlink(target, records, "dir");
      await expectStoreError(
        openPrivateRunStore({ path: run, partitions: ["records"] }),
      );
    },
  );
});

describe("private run partition artifacts", () => {
  it("reads detached bounded bytes and reports a missing artifact", async () => {
    const { store } = await fixture();
    const records = store.partition("records");
    const bytes = Buffer.from('{"complete":true}\n', "utf8");

    await expect(records.readOptional("missing.json", 32)).resolves.toBeNull();
    await writeFile(join(records.path, "record.json"), bytes, { mode: 0o600 });
    const actual = await records.readOptional("record.json", bytes.byteLength);

    expect(Buffer.from(actual!)).toEqual(bytes);
    actual![0] = 0;
    expect(await readFile(join(records.path, "record.json"))).toEqual(bytes);
  });

  it("creates 0600 artifacts once and never clobbers existing bytes", async () => {
    const { store } = await fixture();
    const records = store.partition("records");
    const first = Buffer.from("first-complete", "utf8");
    const second = Buffer.from("second-complete", "utf8");

    await expect(records.create("record.json", first, 128)).resolves.toBe(
      "created",
    );
    await expect(records.create("record.json", second, 128)).resolves.toBe(
      "exists",
    );

    expect(await readFile(join(records.path, "record.json"))).toEqual(first);
    if (process.platform !== "win32") {
      expect(
        (await lstat(join(records.path, "record.json"))).mode & 0o777,
      ).toBe(0o600);
    }
  });

  it("snapshots mutable bytes before create performs asynchronous work", async () => {
    const { store } = await fixture();
    const records = store.partition("records");
    const mutable = Uint8Array.from([1, 2, 3]);

    const creation = records.create("snapshot.json", mutable, 128);
    mutable.fill(9);

    await expect(creation).resolves.toBe("created");
    expect(await readFile(join(records.path, "snapshot.json"))).toEqual(
      Buffer.from([1, 2, 3]),
    );
  });

  it("copies bytes without invoking hostile getters or iterators", async () => {
    const { store } = await fixture();
    const records = store.partition("records");
    const bytes = new Uint8Array([1, 2, 3]);
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

    await expect(records.create("intrinsic.json", bytes, 128)).resolves.toBe(
      "created",
    );
    expect(await readFile(join(records.path, "intrinsic.json"))).toEqual(
      Buffer.from([1, 2, 3]),
    );
    expect(hostileCalls).toBe(0);
  });

  it("rejects proxied byte views without invoking traps", async () => {
    const { store } = await fixture();
    const records = store.partition("records");
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

    await expectStoreError(
      records.create("proxy.json", bytes as unknown as Uint8Array, 128),
    );
    expect(trapCalls).toBe(0);
    await expect(access(join(records.path, "proxy.json"))).rejects.toThrow();
  });

  it("serializes concurrent creators through a no-clobber result", async () => {
    const { store } = await fixture();
    const records = store.partition("records");
    const first = Buffer.from("first", "utf8");
    const second = Buffer.from("second", "utf8");

    const outcomes = await Promise.all([
      records.create("race.json", first, 128),
      records.create("race.json", second, 128),
    ]);

    expect(outcomes.sort()).toEqual(["created", "exists"]);
    expect([first, second]).toContainEqual(
      await readFile(join(records.path, "race.json")),
    );
    expect(await privateTemporaryFiles(records.path)).toEqual([]);
  });

  it("publishes once, accepts identical bytes, and rejects drift", async () => {
    const { store } = await fixture();
    const artifact = Buffer.from("stable-artifact", "utf8");

    await store.root.publishOrVerify("manifest.json", artifact, 128);
    await expect(
      store.root.publishOrVerify("manifest.json", Buffer.from(artifact), 128),
    ).resolves.toBeUndefined();
    await expectStoreError(
      store.root.publishOrVerify(
        "manifest.json",
        Buffer.from("changed-artifact", "utf8"),
        128,
      ),
    );
    expect(await readFile(join(store.root.path, "manifest.json"))).toEqual(
      artifact,
    );
  });

  it("accepts concurrent publication only when the bytes agree", async () => {
    const { store } = await fixture();
    const artifact = Buffer.from("same-content", "utf8");

    await expect(
      Promise.all([
        store.root.publishOrVerify("same.json", artifact, 128),
        store.root.publishOrVerify("same.json", Buffer.from(artifact), 128),
      ]),
    ).resolves.toEqual([undefined, undefined]);
    expect(await readFile(join(store.root.path, "same.json"))).toEqual(
      artifact,
    );
  });

  it("snapshots mutable bytes before publish-or-verify awaits storage", async () => {
    const { store } = await fixture();
    const mutable = Uint8Array.from([4, 5, 6]);

    const publication = store.root.publishOrVerify(
      "snapshot-manifest.json",
      mutable,
      128,
    );
    mutable.fill(8);

    await expect(publication).resolves.toBeUndefined();
    expect(
      await readFile(join(store.root.path, "snapshot-manifest.json")),
    ).toEqual(Buffer.from([4, 5, 6]));
  });

  it("rejects unsafe names, invalid budgets, oversized bytes, and symlinks", async () => {
    const { store, parent } = await fixture();
    const records = store.partition("records");
    await expectStoreError(records.readOptional("../escape", 128));
    await expectStoreError(records.readOptional("Uppercase.json", 128));
    await expectStoreError(records.readOptional("nul.json", 128));
    await expectStoreError(records.readOptional("trailing.", 128));
    await expectStoreError(records.readOptional("missing.json", 0));
    await expectStoreError(
      records.create("large.json", Buffer.from("12345"), 4),
    );
    await expect(access(join(records.path, "large.json"))).rejects.toThrow();
    expect(await privateTemporaryFiles(records.path)).toEqual([]);

    if (process.platform !== "win32") {
      const target = join(parent, "outside.json");
      const alias = join(records.path, "alias.json");
      await writeFile(target, "outside", { mode: 0o600 });
      await symlink(target, alias);
      await expectStoreError(records.readOptional("alias.json", 128));
      await expect(
        records.create("alias.json", Buffer.from("new"), 128),
      ).resolves.toBe("exists");
      expect(await readFile(target, "utf8")).toBe("outside");
    }
  });

  it.runIf(process.platform !== "win32")(
    "rejects artifacts that are not exclusive owner-private files",
    async () => {
      const { store, parent } = await fixture();
      const records = store.partition("records");
      const permissive = join(records.path, "permissive.json");
      await writeFile(permissive, "private", { mode: 0o600 });
      await chmod(permissive, 0o640);
      await expectStoreError(records.readOptional("permissive.json", 128));

      const linked = join(records.path, "linked.json");
      await writeFile(linked, "private", { mode: 0o600 });
      await link(linked, join(parent, "second-link.json"));
      await expectStoreError(records.readOptional("linked.json", 128));
    },
  );

  it("recovers a complete publication interrupted after its atomic link", async () => {
    const { store } = await fixture();
    const records = store.partition("records");
    const destination = join(records.path, "recoverable.json");
    const temporary = join(
      records.path,
      ".intentabi-private-0123456789abcdef0123456789abcdef.tmp",
    );
    const expected = Buffer.from("durable-complete-record", "utf8");
    await writeFile(destination, expected, { mode: 0o600 });
    await link(destination, temporary);
    expect((await lstat(destination)).nlink).toBe(2);

    const recovered = await records.readOptional("recoverable.json", 128);
    expect(Buffer.from(recovered!)).toEqual(expected);
    expect((await lstat(destination)).nlink).toBe(1);
    await expect(access(temporary)).rejects.toThrow();
  });

  it("lets concurrent resumers converge on one recovered publication", async () => {
    const { store, run } = await fixture();
    const peer = await openPrivateRunStore({
      path: run,
      partitions: ["records"],
    });
    const records = store.partition("records");
    const peerRecords = peer.partition("records");
    const destination = join(records.path, "concurrent-recovery.json");
    const temporary = join(
      records.path,
      ".intentabi-private-fedcba9876543210fedcba9876543210.tmp",
    );
    const expected = Buffer.from("complete-concurrent-record", "utf8");
    await writeFile(destination, expected, { mode: 0o600 });
    await link(destination, temporary);

    const recovered = await Promise.all([
      records.readOptional("concurrent-recovery.json", 128),
      peerRecords.readOptional("concurrent-recovery.json", 128),
    ]);

    expect(recovered.map((bytes) => Buffer.from(bytes!))).toEqual([
      expected,
      expected,
    ]);
    expect((await lstat(destination)).nlink).toBe(1);
    await expect(access(temporary)).rejects.toThrow();
  });

  it("rejects a multiply linked artifact without the exact publisher sibling", async () => {
    const { store, parent } = await fixture();
    const records = store.partition("records");
    const destination = join(records.path, "untrusted-link.json");
    await writeFile(destination, "private", { mode: 0o600 });
    await link(destination, join(parent, "outside-link.json"));

    await expectStoreError(records.readOptional("untrusted-link.json", 128));
  });

  it("does not expose a private filename or payload through errors", async () => {
    const { store } = await fixture();
    const marker = "PRIVATE_ARTIFACT_MARKER";
    const error = await captureStoreError(
      store.root.create(`${marker}.json`, Buffer.from(marker), 1),
    );

    expect(error.message).not.toContain(marker);
    expect(JSON.stringify(error)).not.toContain(marker);
  });
});

describe("private run identity guards", () => {
  it("preserves operation errors while the layout remains stable", async () => {
    const { store } = await fixture();
    const expected = new Error("operation failed");

    await expect(
      store.guard(async () => {
        throw expected;
      }),
    ).rejects.toBe(expected);
  });

  it.runIf(process.platform !== "win32")(
    "rejects a root identity change during guarded work",
    async () => {
      const { store, run, parent } = await fixture();
      const displaced = join(parent, "displaced-run");

      await expectStoreError(
        store.guard(async () => {
          await rename(run, displaced);
          await mkdir(join(run, "records"), { recursive: true, mode: 0o700 });
        }),
      );
    },
  );

  it.runIf(process.platform !== "win32")(
    "rejects a partition identity change during guarded work",
    async () => {
      const { store, run, parent } = await fixture();
      const records = join(run, "records");
      const displaced = join(parent, "displaced-records");

      await expectStoreError(
        store.guard(async () => {
          await rename(records, displaced);
          await mkdir(records, { mode: 0o700 });
        }),
      );
      await expectStoreError(store.assertStable());
    },
  );
});

async function fixture(): Promise<{
  readonly store: Awaited<ReturnType<typeof openPrivateRunStore>>;
  readonly parent: string;
  readonly run: string;
}> {
  const parent = await temporaryDirectory("intentabi-run-store-");
  const run = join(parent, "run");
  return {
    parent,
    run,
    store: await openPrivateRunStore({ path: run, partitions: ["records"] }),
  };
}

async function temporaryDirectory(prefix: string): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), prefix));
  temporaryDirectories.add(directory);
  if (process.platform !== "win32") await chmod(directory, 0o700);
  return directory;
}

async function canonicalPath(path: string): Promise<string> {
  const { realpath } = await import("node:fs/promises");
  return realpath(path);
}

async function privateTemporaryFiles(directory: string): Promise<string[]> {
  return (await readdir(directory))
    .filter((name) => /^\.intentabi-private-[a-f0-9]{32}\.tmp$/u.test(name))
    .map((name) => join(directory, name));
}

async function expectStoreError(promise: Promise<unknown>): Promise<void> {
  expect(await captureStoreError(promise)).toBeInstanceOf(PrivateRunStoreError);
}

async function captureStoreError(
  promise: Promise<unknown>,
): Promise<PrivateRunStoreError> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof PrivateRunStoreError) return error;
    throw error;
  }
  throw new Error("Expected promise to reject");
}
