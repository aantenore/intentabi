import { createHash } from "node:crypto";

import {
  GUARDED_REUSE_SCENARIOS,
  type GuardedReuseScenario,
} from "@intentabi/guarded-reuse";
import { z } from "zod";

export const SGD_GUARDED_REUSE_CONFIG_SCHEMA =
  "io.github.aantenore.intentabi/sgd-guarded-reuse-config/v1alpha1" as const;
export const SGD_SOURCE_MANIFEST_SCHEMA =
  "io.github.aantenore.intentabi/sgd-source-manifest/v1" as const;
export const SGD_SELECTOR_MANIFEST_SCHEMA =
  "io.github.aantenore.intentabi/sgd-selector-manifest/v1" as const;
export const SGD_SELECTED_ORDER_SCHEMA =
  "io.github.aantenore.intentabi/sgd-selected-order/v1" as const;
export const SGD_REPOSITORY =
  "google-research-datasets/dstc8-schema-guided-dialogue" as const;
export const SGD_SELECTION_SEED = "sgd-guarded-reuse-v1" as const;

const sha256 = z.custom<`sha256:${string}`>(
  (value) => typeof value === "string" && /^sha256:[a-f0-9]{64}$/u.test(value),
  "Invalid SHA-256 digest",
);
const identifier = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u);
const environmentName = z.string().regex(/^[A-Z][A-Z0-9_]{0,126}[A-Z0-9]$/u);
const safeDatasetName = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_]{0,127}$/u);
const slotValue = z.string().min(1).max(4_096);

const familySchema = z
  .object({
    id: identifier,
    service: safeDatasetName,
    intent: safeDatasetName,
    slots: z.record(safeDatasetName, z.array(slotValue).min(1).max(16)),
    requestedSlots: z.array(safeDatasetName).max(16),
    effect: z.enum(["read", "write"]),
    available: z.number().int().min(1).max(10_000),
    take: z.number().int().min(1).max(10_000),
  })
  .strict();

export type SgdSelectionFamily = z.infer<typeof familySchema>;

/**
 * The exact externally-labelled strata used by the reproducible v1 study.
 * Object key order is canonicalized before digesting or comparison.
 */
export const SGD_SELECTION_FAMILIES: readonly SgdSelectionFamily[] = deepFreeze(
  [
    {
      id: "hotels-search-empty",
      service: "Hotels_4",
      intent: "SearchHotel",
      slots: {},
      requestedSlots: [],
      effect: "read",
      available: 42,
      take: 29,
    },
    {
      id: "hotels-search-london",
      service: "Hotels_4",
      intent: "SearchHotel",
      slots: { location: ["London"] },
      requestedSlots: [],
      effect: "read",
      available: 2,
      take: 2,
    },
    {
      id: "hotels-search-room-star",
      service: "Hotels_4",
      intent: "SearchHotel",
      slots: { number_of_rooms: ["1"], star_rating: ["3"] },
      requestedSlots: [],
      effect: "read",
      available: 2,
      take: 2,
    },
    {
      id: "hotels-search-smoking",
      service: "Hotels_4",
      intent: "SearchHotel",
      slots: { smoking_allowed: ["True"] },
      requestedSlots: [],
      effect: "read",
      available: 3,
      take: 3,
    },
    {
      id: "hotels-search-star",
      service: "Hotels_4",
      intent: "SearchHotel",
      slots: { star_rating: ["3"] },
      requestedSlots: [],
      effect: "read",
      available: 4,
      take: 4,
    },
    {
      id: "music-lookup-empty",
      service: "Music_3",
      intent: "LookupMusic",
      slots: {},
      requestedSlots: [],
      effect: "read",
      available: 8,
      take: 8,
    },
    {
      id: "restaurants-reserve-empty",
      service: "Restaurants_2",
      intent: "ReserveRestaurant",
      slots: {},
      requestedSlots: [],
      effect: "write",
      available: 9,
      take: 8,
    },
  ] satisfies readonly SgdSelectionFamily[],
);

const sourceSchema = z
  .object({
    kind: z.literal("google-schema-guided-dialogue"),
    repository: z.literal(SGD_REPOSITORY),
    revision: z.string().regex(/^[a-f0-9]{40}$/u),
    schema: z
      .object({
        path: z.literal("test/schema.json"),
        sha256,
      })
      .strict(),
    dialogues: z
      .object({
        path: z.literal("test/dialogues_001.json"),
        sha256,
      })
      .strict(),
    selector: z
      .object({
        seed: z.literal(SGD_SELECTION_SEED),
        manifestSha256: sha256,
        families: z.array(familySchema).length(SGD_SELECTION_FAMILIES.length),
      })
      .strict(),
  })
  .strict();

const studySchema = z
  .object({
    keyId: identifier,
    hmacSecretEnv: environmentName,
    locale: z.literal("en-US"),
    normalizationPolicyDigest: sha256,
    cachePolicyDigest: sha256,
    ttl: z
      .object({
        createdAtEpochMs: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
        ttlMs: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
        freshOffsetMs: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
        staleOffsetMs: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
      })
      .strict()
      .superRefine((value, context) => {
        if (value.freshOffsetMs >= value.ttlMs) {
          context.addIssue({
            code: "custom",
            path: ["freshOffsetMs"],
            message: "Fresh offset must be inside the TTL window",
          });
        }
        if (value.staleOffsetMs < value.ttlMs) {
          context.addIssue({
            code: "custom",
            path: ["staleOffsetMs"],
            message: "Stale offset must be at or beyond the TTL boundary",
          });
        }
      }),
    revisionNamespace: identifier,
    requiredScenarios: z
      .array(z.enum(GUARDED_REUSE_SCENARIOS))
      .length(GUARDED_REUSE_SCENARIOS.length),
  })
  .strict();

export const sgdGuardedReuseConfigSchema = z
  .object({
    schema: z.literal(SGD_GUARDED_REUSE_CONFIG_SCHEMA),
    mode: z.literal("shadow"),
    source: sourceSchema,
    study: studySchema,
  })
  .strict()
  .superRefine((value, context) => {
    if (
      canonicalJson(value.source.selector.families) !==
      canonicalJson(SGD_SELECTION_FAMILIES)
    ) {
      context.addIssue({
        code: "custom",
        path: ["source", "selector", "families"],
        message: "Selection families do not match the pinned v1 profile",
      });
    }
    const selectorDigest = selectorManifestDigest(value.source.selector);
    if (selectorDigest !== value.source.selector.manifestSha256) {
      context.addIssue({
        code: "custom",
        path: ["source", "selector", "manifestSha256"],
        message: "Selector manifest digest does not match its contents",
      });
    }
    if (
      new Set(value.study.requiredScenarios).size !==
        GUARDED_REUSE_SCENARIOS.length ||
      GUARDED_REUSE_SCENARIOS.some(
        (scenario) => !value.study.requiredScenarios.includes(scenario),
      )
    ) {
      context.addIssue({
        code: "custom",
        path: ["study", "requiredScenarios"],
        message: "Every guarded reuse scenario must be required exactly once",
      });
    }
  });

export type SgdGuardedReuseConfig = z.infer<typeof sgdGuardedReuseConfigSchema>;

export function parseSgdGuardedReuseConfig(
  value: unknown,
): SgdGuardedReuseConfig {
  return deepFreeze(sgdGuardedReuseConfigSchema.parse(value));
}

export function selectorManifestDigest(selector: {
  readonly seed: string;
  readonly families: readonly SgdSelectionFamily[];
}): `sha256:${string}` {
  return sha256Canonical({
    schema: SGD_SELECTOR_MANIFEST_SCHEMA,
    seed: selector.seed,
    families: selector.families,
  });
}

/**
 * Public reproducibility commitment. It covers both source-file digests and
 * every selector/study setting, but never contains an HMAC secret.
 */
export function sourceManifestDigest(
  config: SgdGuardedReuseConfig,
  selectionOrderDigest: `sha256:${string}`,
): `sha256:${string}` {
  return sha256Canonical({
    schema: SGD_SOURCE_MANIFEST_SCHEMA,
    config,
    selectionOrderDigest,
  });
}

export function sha256Canonical(value: unknown): `sha256:${string}` {
  return `sha256:${createHash("sha256")
    .update(canonicalJson(value), "utf8")
    .digest("hex")}`;
}

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean")
    return JSON.stringify(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number" && Number.isSafeInteger(value)) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  if (isRecord(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  throw new TypeError("Value is not canonical JSON");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const nested of Object.values(value)) deepFreeze(nested);
  }
  return value;
}

export type RequiredSgdScenario = GuardedReuseScenario;
