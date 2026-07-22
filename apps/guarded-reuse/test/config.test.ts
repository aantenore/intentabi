import { describe, expect, it } from "vitest";

import {
  parseSgdGuardedReuseConfig,
  selectorManifestDigest,
  sourceManifestDigest,
} from "../src/config.js";
import { officialConfigValue } from "./support.js";

describe("SGD guarded-reuse configuration", () => {
  it("pins the golden selector manifest and public source formula", async () => {
    const config = parseSgdGuardedReuseConfig(await officialConfigValue());

    expect(selectorManifestDigest(config.source.selector)).toBe(
      "sha256:bbca78806558e2c396c3faf304db445cfc12bc102272be56b663cc9a2816611f",
    );
    expect(
      sourceManifestDigest(
        config,
        "sha256:85e1e3f5541ec2219bab8fc5fcedc6a92fb3e2205b83623d246c62b78f9e0e06",
      ),
    ).toBe(
      "sha256:38a05ee4be88b685da28be7dd92cdd72ef75247fee9044d4bf4d667a99d2775e",
    );
  });

  it("rejects unknown fields and any selector drift", async () => {
    const value = (await officialConfigValue()) as Record<string, unknown>;
    expect(() =>
      parseSgdGuardedReuseConfig({ ...value, unexpected: true }),
    ).toThrow();

    const changed = structuredClone(value) as {
      source: { selector: { families: Array<{ take: number }> } };
    };
    changed.source.selector.families[0]!.take -= 1;
    expect(() => parseSgdGuardedReuseConfig(changed)).toThrow();
  });
});
