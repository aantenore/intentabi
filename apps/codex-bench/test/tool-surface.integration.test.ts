import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Codex } from "@openai/codex-sdk";
import { expect, it } from "vitest";

import {
  attestCodexBoundary,
  createLockedCodexArmProcessConfig,
  createIsolatedBenchmarkRuntime,
} from "../src/index.js";

const cliPath = process.env.INTENTABI_CODEX_SECURITY_CLI;
const securityIt = cliPath === undefined ? it.skip : it;

securityIt(
  "captures the exact 0.144.4 tool surface and rejects an unsolicited view_image canary",
  async () => {
    const binary = cliPath!;
    await attestCodexBoundary({
      executablePath: binary,
      threadOptions: {
        model: "gpt-codex-boundary-attestation",
        sandboxMode: "read-only",
        skipGitRepoCheck: false,
        modelReasoningEffort: "medium",
        networkAccessEnabled: false,
        webSearchMode: "disabled",
        webSearchEnabled: false,
        approvalPolicy: "never",
      },
      timeoutMs: 10_000,
      maxOutputTokensPerCall: 64,
      maxRequestBytes: 2 * 1024 * 1024,
      maxResponseBytes: 65_536,
      createRuntime: createIsolatedBenchmarkRuntime,
      platformEnvironment: {},
    });

    const requests: Array<Record<string, unknown>> = [];
    const canaryDirectory = await mkdtemp(
      join(tmpdir(), "intentabi-view-image-canary-"),
    );
    const canaryPath = join(canaryDirectory, "readable-canary.png");
    await writeFile(canaryPath, Buffer.from(PNG_CANARY_BASE64, "base64"), {
      mode: 0o600,
    });
    const server = createServer(async (request, response) => {
      try {
        const body = JSON.parse(await readRequestBody(request)) as Record<
          string,
          unknown
        >;
        requests.push(body);
        response.writeHead(200, {
          "content-type": "text/event-stream",
          connection: "close",
        });
        response.end(
          requests.length === 1
            ? unsolicitedViewImageCall(canaryPath)
            : completedTurn(),
        );
      } catch (error) {
        response.writeHead(500, { "content-type": "text/plain" });
        response.end(error instanceof Error ? error.message : "capture failed");
      }
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (address === null || typeof address === "string") {
      throw new Error("Fake provider did not expose a TCP address");
    }

    const model = "gpt-codex-security-capture";
    const runtime = await createIsolatedBenchmarkRuntime({}, model);
    try {
      const client = new Codex({
        apiKey: "codex-security-canary-key",
        baseUrl: `http://127.0.0.1:${address.port}/v1`,
        codexPathOverride: binary,
        env: runtime.sdkEnvironment,
        config: createLockedCodexArmProcessConfig(
          `http://127.0.0.1:${address.port}/v1`,
        ),
      });
      await client
        .startThread({
          model,
          workingDirectory: runtime.workspaceDirectory,
          sandboxMode: "read-only",
          skipGitRepoCheck: false,
          modelReasoningEffort: "medium",
          networkAccessEnabled: false,
          webSearchMode: "disabled",
          webSearchEnabled: false,
          approvalPolicy: "never",
        })
        .run("Security conformance canary. Respond only with OK.");
    } finally {
      await runtime.release();
      await new Promise<void>((resolve, reject) => {
        server.close((error) =>
          error === undefined ? resolve() : reject(error),
        );
      });
      await rm(canaryDirectory, { recursive: true, force: true });
    }

    expect(requests).toHaveLength(2);
    expect(requests.map((request) => toolNames(request))).toEqual([
      ["update_plan"],
      ["update_plan"],
    ]);
    expect(JSON.stringify(requests[0])).not.toContain(
      runtime.workspaceDirectory,
    );
    expect(JSON.stringify(requests[0])).not.toContain(canaryPath);
    const serialized = JSON.stringify(requests);
    expect(serialized).not.toContain("data:image");
    expect(serialized).not.toContain("image_data");
    expect(serialized).not.toContain(PNG_CANARY_BASE64);
    expect(serialized).toContain("view_image");
    expect(serialized).toMatch(/unsupported (?:call|tool)|not supported/u);
  },
  30_000,
);

async function readRequestBody(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    length += buffer.length;
    if (length > 4 * 1024 * 1024) throw new Error("Request body is too large");
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function toolNames(request: Record<string, unknown> | undefined): string[] {
  if (!Array.isArray(request?.tools)) return [];
  return request.tools
    .map((tool) => {
      if (tool === null || typeof tool !== "object") return "";
      const candidate = tool as Record<string, unknown>;
      return typeof candidate.name === "string"
        ? candidate.name
        : typeof candidate.type === "string"
          ? candidate.type
          : "";
    })
    .filter((name) => name.length > 0)
    .sort();
}

function unsolicitedViewImageCall(canaryPath: string): string {
  return sse([
    { type: "response.created", response: { id: "resp-canary" } },
    {
      type: "response.output_item.done",
      item: {
        type: "function_call",
        call_id: "call-view-image-canary",
        name: "view_image",
        arguments: JSON.stringify({ path: canaryPath }),
      },
    },
    completedEvent("resp-canary", 1, 0),
  ]);
}

// Valid 1x1 PNG. If `view_image` were registered, this file is readable and
// encodable, so the fake provider would receive an image-data tool result.
const PNG_CANARY_BASE64 =
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=";

function completedTurn(): string {
  return sse([
    { type: "response.created", response: { id: "resp-complete" } },
    {
      type: "response.output_item.done",
      item: {
        type: "message",
        role: "assistant",
        id: "msg-complete",
        content: [{ type: "output_text", text: "OK" }],
      },
    },
    completedEvent("resp-complete", 1, 1),
  ]);
}

function completedEvent(id: string, inputTokens: number, outputTokens: number) {
  return {
    type: "response.completed",
    response: {
      id,
      usage: {
        input_tokens: inputTokens,
        input_tokens_details: null,
        output_tokens: outputTokens,
        output_tokens_details: null,
        total_tokens: inputTokens + outputTokens,
      },
    },
  };
}

function sse(events: readonly Record<string, unknown>[]): string {
  return events
    .map(
      (event) =>
        `event: ${String(event.type)}\ndata: ${JSON.stringify(event)}\n\n`,
    )
    .join("");
}
