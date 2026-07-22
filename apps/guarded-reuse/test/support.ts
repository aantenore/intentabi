import { readFile } from "node:fs/promises";

import {
  parseSgdGuardedReuseConfig,
  SGD_SELECTION_FAMILIES,
  type SgdGuardedReuseConfig,
} from "../src/config.js";
import { sha256Bytes } from "../src/sgd.js";

export interface SyntheticSgdFixture {
  readonly config: SgdGuardedReuseConfig;
  readonly schemaBytes: Uint8Array;
  readonly dialoguesBytes: Uint8Array;
  readonly privateTokens: readonly string[];
}

export async function officialConfigValue(): Promise<unknown> {
  return JSON.parse(
    await readFile(
      new URL("../../../config/sgd-guarded-reuse.json", import.meta.url),
      "utf8",
    ),
  );
}

export async function syntheticSgdFixture(): Promise<SyntheticSgdFixture> {
  const schema = [
    service("Hotels_4", false, "SearchHotel", [
      "location",
      "number_of_rooms",
      "smoking_allowed",
      "star_rating",
    ]),
    service("Music_3", false, "LookupMusic", []),
    service("Restaurants_2", true, "ReserveRestaurant", []),
  ];
  let identifier = 0;
  const dialogues = SGD_SELECTION_FAMILIES.flatMap((family) =>
    Array.from({ length: family.available }, (_, ordinal) => {
      identifier += 1;
      return {
        dialogue_id: `synthetic_${identifier}`,
        services: [family.service],
        turns: [
          {
            speaker: "USER",
            utterance: `Private synthetic utterance ${family.id} ${ordinal}`,
            frames: [
              {
                service: family.service,
                actions: [],
                slots: [],
                state: {
                  active_intent: family.intent,
                  requested_slots: [...family.requestedSlots],
                  slot_values: structuredClone(family.slots),
                },
              },
            ],
          },
        ],
      };
    }),
  );
  const schemaBytes = Uint8Array.from(Buffer.from(JSON.stringify(schema)));
  const dialoguesBytes = Uint8Array.from(
    Buffer.from(JSON.stringify(dialogues)),
  );
  const base = parseSgdGuardedReuseConfig(await officialConfigValue());
  const config = parseSgdGuardedReuseConfig({
    ...base,
    source: {
      ...base.source,
      schema: { ...base.source.schema, sha256: sha256Bytes(schemaBytes) },
      dialogues: {
        ...base.source.dialogues,
        sha256: sha256Bytes(dialoguesBytes),
      },
    },
  });
  return Object.freeze({
    config,
    schemaBytes,
    dialoguesBytes,
    privateTokens: Object.freeze([
      "synthetic_1",
      "Private synthetic utterance hotels-search-empty 0",
      "Hotels_4",
      "SearchHotel",
    ]),
  });
}

function service(
  serviceName: string,
  transactional: boolean,
  intentName: string,
  slots: readonly string[],
) {
  return {
    service_name: serviceName,
    description: "Synthetic fixture",
    slots: slots.map((name) => ({
      name,
      description: "Synthetic fixture slot",
      is_categorical: false,
      possible_values: [],
    })),
    intents: [
      {
        name: intentName,
        description: "Synthetic fixture intent",
        is_transactional: transactional,
        required_slots: [],
        optional_slots: {},
        result_slots: [],
      },
    ],
  };
}
