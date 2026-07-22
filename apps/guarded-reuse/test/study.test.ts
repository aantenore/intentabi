import { describe, expect, it } from "vitest";

import { executeSgdGuardedReuse } from "../src/study.js";
import { syntheticSgdFixture } from "./support.js";

const secret = "guarded-reuse-test-secret-with-at-least-32-bytes";

describe("external-label guarded reuse composition", () => {
  it("passes all 56 conformance cases without exposing source content", async () => {
    const fixture = await syntheticSgdFixture();
    const result = executeSgdGuardedReuse({
      config: fixture.config,
      schemaBytes: fixture.schemaBytes,
      dialoguesBytes: fixture.dialoguesBytes,
      hmacSecret: secret,
    });

    expect(result.report.summary).toMatchObject({
      requests: 56,
      exact: { unsafeHits: 0 },
      guarded: {
        safeHits: 31,
        unsafeHits: 0,
        admissionBypasses: 3,
        misses: 14,
        ineligible: 8,
      },
      safeHitLiftVsExact: 31,
      gate: { passed: true, reasons: [] },
    });
    expect(
      result.report.cases.every((item) => item.guardedMatchedExpectation),
    ).toBe(true);
    expect(result.report.summary.scenarios).toMatchObject({
      "tenant-drift": 1,
      "ttl-stale": 1,
      "revision-drift": 1,
      "transactional-effect": 8,
      "hostile-store-substitution": 1,
    });
    expect(result.report).toMatchObject({
      mode: "shadow",
      servingAuthority: "none",
      activationAuthorized: false,
      applied: false,
      statisticalQualification: false,
      economicQualification: false,
    });

    const serialized = JSON.stringify(result);
    for (const token of fixture.privateTokens) {
      expect(serialized).not.toContain(token);
    }
    expect(result.selectionOrderDigest).toMatch(/^sha256:[a-f0-9]{64}$/u);
    expect(result.report.reportMac).toMatch(
      /^hmac-sha256:evidence:[a-f0-9]{64}$/u,
    );
    expect(result.report.datasetDigest).toMatch(
      /^hmac-sha256:evidence:[a-f0-9]{64}$/u,
    );
  });

  it("is deterministic for the same bytes, profile, and HMAC key", async () => {
    const fixture = await syntheticSgdFixture();
    const run = () =>
      executeSgdGuardedReuse({
        config: fixture.config,
        schemaBytes: fixture.schemaBytes,
        dialoguesBytes: fixture.dialoguesBytes,
        hmacSecret: secret,
      });

    expect(run()).toEqual(run());
  });
});
