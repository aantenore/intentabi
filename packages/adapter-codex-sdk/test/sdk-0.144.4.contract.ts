import {
  Codex,
  Thread,
  type Input,
  type RunResult,
  type RunStreamedResult,
  type ThreadEvent,
  type ThreadOptions,
  type TurnOptions,
  type Usage,
} from "@openai/codex-sdk";

import type { CodexSdkClientLike, CodexSdkThreadLike } from "../src/index.js";

declare const codex: Codex;
declare const input: Input;
declare const threadOptions: ThreadOptions;
declare const turnOptions: TurnOptions;
declare const usage: Usage;

const clientContract: CodexSdkClientLike = codex;
const thread: Thread = clientContract.startThread(threadOptions) as Thread;
const threadContract: CodexSdkThreadLike = thread;
const run: Promise<RunResult> = threadContract.run(input, turnOptions);
const streamed: Promise<RunStreamedResult> = thread.runStreamed(
  input,
  turnOptions,
);
const events: AsyncGenerator<ThreadEvent> = (await streamed).events;
const counters: readonly number[] = [
  usage.input_tokens,
  usage.cached_input_tokens,
  usage.output_tokens,
  usage.reasoning_output_tokens,
];

void run;
void events;
void counters;
