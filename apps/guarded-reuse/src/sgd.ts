import { createHash } from "node:crypto";
import { TextDecoder } from "node:util";

import { z } from "zod";

import {
  canonicalJson,
  SGD_SELECTED_ORDER_SCHEMA,
  sha256Canonical,
  type SgdGuardedReuseConfig,
  type SgdSelectionFamily,
} from "./config.js";

const text = z.string().min(1).max(16_384);
const name = z.string().min(1).max(256);
const stringList = z.array(z.string().max(16_384)).max(256);
const stringRecord = z.record(name, z.string().max(16_384));

const sgdSlotSchema = z
  .object({
    name,
    description: z.string().max(16_384),
    is_categorical: z.boolean(),
    possible_values: stringList,
  })
  .strict();

const sgdIntentSchema = z
  .object({
    name,
    description: z.string().max(16_384),
    is_transactional: z.boolean(),
    required_slots: z.array(name).max(256),
    optional_slots: stringRecord,
    result_slots: z.array(name).max(256),
  })
  .strict();

const sgdServiceSchema = z
  .object({
    service_name: name,
    description: z.string().max(16_384),
    slots: z.array(sgdSlotSchema).max(1_024),
    intents: z.array(sgdIntentSchema).max(1_024),
  })
  .strict();

const sgdSchemaFileSchema = z.array(sgdServiceSchema).min(1).max(1_024);

const sgdActionSchema = z
  .object({
    act: name,
    slot: z.string().max(256),
    values: stringList,
    canonical_values: stringList,
  })
  .strict();

const sgdSpanSchema = z
  .object({
    slot: name,
    start: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
    exclusive_end: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
  })
  .strict();

const sgdStateSchema = z
  .object({
    active_intent: name,
    requested_slots: z.array(name).max(256),
    slot_values: z.record(name, z.array(text).min(1).max(256)),
  })
  .strict();

const sgdServiceCallSchema = z
  .object({
    method: name,
    parameters: stringRecord,
  })
  .strict();

const sgdFrameSchema = z
  .object({
    service: name,
    actions: z.array(sgdActionSchema).max(1_024),
    slots: z.array(sgdSpanSchema).max(1_024),
    state: sgdStateSchema.optional(),
    service_call: sgdServiceCallSchema.optional(),
    service_results: z.array(stringRecord).max(10_000).optional(),
  })
  .strict();

const sgdTurnSchema = z
  .object({
    speaker: z.enum(["USER", "SYSTEM"]),
    utterance: text,
    frames: z.array(sgdFrameSchema).min(1).max(256),
  })
  .strict();

const sgdDialogueSchema = z
  .object({
    dialogue_id: name,
    services: z.array(name).min(1).max(256),
    turns: z.array(sgdTurnSchema).min(1).max(1_024),
  })
  .strict();

const sgdDialoguesFileSchema = z.array(sgdDialogueSchema).min(1).max(100_000);

type SgdService = z.infer<typeof sgdServiceSchema>;
type SgdDialogue = z.infer<typeof sgdDialogueSchema>;

export interface SelectedSgdExample {
  readonly family: SgdSelectionFamily;
  readonly ordinalInFamily: number;
  readonly dialogueId: string;
  readonly utterance: string;
}

export interface PreparedSgdSource {
  readonly selected: readonly SelectedSgdExample[];
  readonly schemaDigest: `sha256:${string}`;
  readonly dialoguesDigest: `sha256:${string}`;
  /** Public hash commitment; selected dialogue identifiers never leave it. */
  readonly selectionOrderDigest: `sha256:${string}`;
}

export class SgdSourceError extends Error {
  readonly code:
    "SOURCE_DIGEST_MISMATCH" | "SOURCE_INVALID" | "SOURCE_PROFILE_MISMATCH";

  constructor(code: SgdSourceError["code"]) {
    super(
      code === "SOURCE_DIGEST_MISMATCH"
        ? "SGD source digest does not match the pinned configuration"
        : code === "SOURCE_PROFILE_MISMATCH"
          ? "SGD source does not match the pinned selection profile"
          : "SGD source is invalid",
    );
    this.name = "SgdSourceError";
    this.code = code;
  }
}

/** Verify both byte commitments before decoding or parsing either artifact. */
export function prepareSgdSource(
  config: SgdGuardedReuseConfig,
  schemaBytes: Uint8Array,
  dialoguesBytes: Uint8Array,
): PreparedSgdSource {
  const schemaDigest = sha256Bytes(schemaBytes);
  const dialoguesDigest = sha256Bytes(dialoguesBytes);
  if (
    schemaDigest !== config.source.schema.sha256 ||
    dialoguesDigest !== config.source.dialogues.sha256
  ) {
    throw new SgdSourceError("SOURCE_DIGEST_MISMATCH");
  }

  let services: readonly SgdService[];
  let dialogues: readonly SgdDialogue[];
  try {
    services = sgdSchemaFileSchema.parse(parseJsonBytes(schemaBytes));
    dialogues = sgdDialoguesFileSchema.parse(parseJsonBytes(dialoguesBytes));
  } catch {
    throw new SgdSourceError("SOURCE_INVALID");
  }

  try {
    const serviceMap = uniqueServices(services);
    validateProfileAgainstSchema(config.source.selector.families, serviceMap);
    const selected = selectExamples(
      dialogues,
      config.source.selector.seed,
      config.source.selector.families,
    );
    const selectionOrderDigest = sha256Canonical({
      schema: SGD_SELECTED_ORDER_SCHEMA,
      seed: config.source.selector.seed,
      entries: selected.map((item) => ({
        familyId: item.family.id,
        ordinalInFamily: item.ordinalInFamily,
        dialogueId: item.dialogueId,
        utteranceDigest: sha256Canonical({ utterance: item.utterance }),
      })),
    });
    return Object.freeze({
      selected,
      schemaDigest,
      dialoguesDigest,
      selectionOrderDigest,
    });
  } catch (error) {
    if (error instanceof SgdSourceError) throw error;
    throw new SgdSourceError("SOURCE_PROFILE_MISMATCH");
  }
}

export function sha256Bytes(bytes: Uint8Array): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function parseJsonBytes(bytes: Uint8Array): unknown {
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
}

function uniqueServices(
  services: readonly SgdService[],
): ReadonlyMap<string, SgdService> {
  const result = new Map<string, SgdService>();
  for (const service of services) {
    if (result.has(service.service_name)) {
      throw new SgdSourceError("SOURCE_PROFILE_MISMATCH");
    }
    if (
      new Set(service.slots.map((slot) => slot.name)).size !==
        service.slots.length ||
      new Set(service.intents.map((intent) => intent.name)).size !==
        service.intents.length
    ) {
      throw new SgdSourceError("SOURCE_PROFILE_MISMATCH");
    }
    result.set(service.service_name, deepFreeze(service));
  }
  return result;
}

function validateProfileAgainstSchema(
  families: readonly SgdSelectionFamily[],
  services: ReadonlyMap<string, SgdService>,
): void {
  for (const family of families) {
    const service = services.get(family.service);
    const intent = service?.intents.find((item) => item.name === family.intent);
    if (
      service === undefined ||
      intent === undefined ||
      intent.is_transactional !== (family.effect === "write")
    ) {
      throw new SgdSourceError("SOURCE_PROFILE_MISMATCH");
    }
    const knownSlots = new Set(service.slots.map((slot) => slot.name));
    if (
      Object.keys(family.slots).some((slot) => !knownSlots.has(slot)) ||
      family.requestedSlots.some((slot) => !knownSlots.has(slot))
    ) {
      throw new SgdSourceError("SOURCE_PROFILE_MISMATCH");
    }
  }
}

function selectExamples(
  dialogues: readonly SgdDialogue[],
  seed: string,
  families: readonly SgdSelectionFamily[],
): readonly SelectedSgdExample[] {
  if (
    new Set(dialogues.map((dialogue) => dialogue.dialogue_id)).size !==
    dialogues.length
  ) {
    throw new SgdSourceError("SOURCE_PROFILE_MISMATCH");
  }

  const selected: SelectedSgdExample[] = [];
  for (const family of families) {
    const candidates = dialogues
      .flatMap((dialogue) => {
        const firstUserTurn = dialogue.turns.find(
          (turn) => turn.speaker === "USER",
        );
        const frame = firstUserTurn?.frames[0];
        if (
          firstUserTurn === undefined ||
          frame?.state === undefined ||
          frame.service !== family.service ||
          frame.state.active_intent !== family.intent ||
          canonicalJson(frame.state.slot_values) !==
            canonicalJson(family.slots) ||
          canonicalJson(frame.state.requested_slots) !==
            canonicalJson(family.requestedSlots)
        ) {
          return [];
        }
        return [
          {
            dialogueId: dialogue.dialogue_id,
            utterance: firstUserTurn.utterance,
            rank: selectionRank(
              seed,
              family.id,
              dialogue.dialogue_id,
              firstUserTurn.utterance,
            ),
          },
        ];
      })
      .sort(
        (left, right) =>
          left.rank.localeCompare(right.rank) ||
          left.dialogueId.localeCompare(right.dialogueId) ||
          left.utterance.localeCompare(right.utterance),
      );

    if (
      candidates.length !== family.available ||
      family.take > candidates.length
    ) {
      throw new SgdSourceError("SOURCE_PROFILE_MISMATCH");
    }
    for (const [ordinalInFamily, candidate] of candidates
      .slice(0, family.take)
      .entries()) {
      selected.push(
        Object.freeze({
          family,
          ordinalInFamily,
          dialogueId: candidate.dialogueId,
          utterance: candidate.utterance,
        }),
      );
    }
  }
  if (selected.length !== 56) {
    throw new SgdSourceError("SOURCE_PROFILE_MISMATCH");
  }
  return Object.freeze(selected);
}

function selectionRank(
  seed: string,
  familyId: string,
  dialogueId: string,
  utterance: string,
): `sha256:${string}` {
  return sha256Canonical({
    schema: "io.github.aantenore.intentabi/sgd-selector-rank/v1",
    seed,
    familyId,
    dialogueId,
    utterance,
  });
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const nested of Object.values(value)) deepFreeze(nested);
  }
  return value;
}
