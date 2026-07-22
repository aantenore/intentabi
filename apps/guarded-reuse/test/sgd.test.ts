import { describe, expect, it } from "vitest";

import { parseSgdGuardedReuseConfig } from "../src/config.js";
import { prepareSgdSource, SgdSourceError, sha256Bytes } from "../src/sgd.js";
import { officialConfigValue, syntheticSgdFixture } from "./support.js";

describe("pinned SGD source preparation", () => {
  it("selects exactly 56 examples deterministically", async () => {
    const fixture = await syntheticSgdFixture();
    const first = prepareSgdSource(
      fixture.config,
      fixture.schemaBytes,
      fixture.dialoguesBytes,
    );
    const second = prepareSgdSource(
      fixture.config,
      fixture.schemaBytes,
      fixture.dialoguesBytes,
    );

    expect(first.selected).toHaveLength(56);
    expect(
      Object.fromEntries(
        fixture.config.source.selector.families.map((family) => [
          family.id,
          first.selected.filter((item) => item.family.id === family.id).length,
        ]),
      ),
    ).toEqual(
      Object.fromEntries(
        fixture.config.source.selector.families.map((family) => [
          family.id,
          family.take,
        ]),
      ),
    );
    expect(second.selectionOrderDigest).toBe(first.selectionOrderDigest);
    expect(second.selected).toEqual(first.selected);
  });

  it("verifies byte digests before parsing source JSON", async () => {
    const config = parseSgdGuardedReuseConfig(await officialConfigValue());
    expect(() =>
      prepareSgdSource(
        config,
        Uint8Array.from(Buffer.from("not-json")),
        Uint8Array.from(Buffer.from("also-not-json")),
      ),
    ).toThrowError(
      expect.objectContaining<SgdSourceError>({
        code: "SOURCE_DIGEST_MISMATCH",
      }),
    );
  });

  it("rejects unknown fields even when the source digest matches", async () => {
    const fixture = await syntheticSgdFixture();
    const dialogues = JSON.parse(
      Buffer.from(fixture.dialoguesBytes).toString("utf8"),
    ) as Array<Record<string, unknown>>;
    dialogues[0]!.unexpected = true;
    const changedBytes = Uint8Array.from(
      Buffer.from(JSON.stringify(dialogues)),
    );
    const config = parseSgdGuardedReuseConfig({
      ...fixture.config,
      source: {
        ...fixture.config.source,
        dialogues: {
          ...fixture.config.source.dialogues,
          sha256: sha256Bytes(changedBytes),
        },
      },
    });

    expect(() =>
      prepareSgdSource(config, fixture.schemaBytes, changedBytes),
    ).toThrowError(
      expect.objectContaining<SgdSourceError>({ code: "SOURCE_INVALID" }),
    );
  });
});
