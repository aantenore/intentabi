import { describe, expect, it } from "vitest";

import { createHmacOpaqueDigester } from "../src/index.js";

describe("createHmacOpaqueDigester", () => {
  it("copies mutable key bytes at construction", () => {
    const secret = new Uint8Array(32).fill(7);
    const digester = createHmacOpaqueDigester(secret, "test-v1");
    const before = digester.digestJson({ value: 1 });

    secret.fill(9);

    expect(digester.digestJson({ value: 1 })).toBe(before);
  });

  it("rejects non-JSON objects instead of creating ambiguous digests", () => {
    const digester = createHmacOpaqueDigester("x".repeat(32));

    expect(() => digester.digestJson(new Date(0))).toThrow("plain JSON");
    expect(() => digester.digestJson(new Map([["value", 1]]))).toThrow(
      "plain JSON",
    );
    expect(() => digester.digestJson({ value: undefined })).toThrow(
      "strict JSON",
    );
  });

  it("requires a bounded public key identifier", () => {
    expect(() =>
      createHmacOpaqueDigester("x".repeat(32), "invalid key id"),
    ).toThrow("key id");
  });
});
