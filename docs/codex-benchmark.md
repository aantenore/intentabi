# Codex paired benchmark

`@intentabi/codex-bench` is a research/conformance composition, not an active
prompt-rewriting runtime. It compares a baseline input with an explicitly
provided candidate on fresh Codex threads and records host-observed SDK usage.
It never changes `CodexShadowHost`, never emits SemWitness promotion evidence,
and never creates a promotion manifest.

## Safe defaults

- `validate` and `plan` make zero provider calls. `plan` needs the configured
  HMAC secret so prompt-derived case references stay keyed and content-free.
- `run` is rejected unless both `--execute` and
  `--allow-candidate-submission` are present.
- Before any private benchmark input is submitted, the staged pinned binary
  must complete a public-canary turn through the same locked composition. The
  canary uses an in-process fake upstream, makes no billable provider call, and
  proves that the effective Codex request reaches the loopback policy boundary.
- The strict config fixes sandboxing to `read-only`, network and web search to
  disabled, Git checking to enabled, approvals to `never`, login shells to
  disabled, and the shell/unified-exec features to disabled.
- Every real run uses a newly created, minimal Git workspace and isolated
  `CODEX_HOME`, home, temp, XDG, and empty `PATH` directories. They are removed
  before a receipt is written. A caller-supplied repository path is not part of
  the config contract.
- The isolated `CODEX_HOME` disables local and remote execution environments
  with `environments.toml`, so environment-backed shell, `apply_patch`, and
  `view_image` tools are not constructed. Its one-model authoritative catalog
  additionally permits text input only and disables model tool capabilities.
  Auth storage is configured as ephemeral; history persistence and update
  checks are off. See [Containment limits](#containment-limits) for the abrupt
  termination caveat.
- The SDK receives an explicit allow-listed environment. The HMAC secret,
  GitHub/cloud tokens, and the full host process environment are never
  inherited by the Codex child. Only Windows system-root variables may cross
  the platform bootstrap allow-list. The real provider API key remains in the
  parent process; each arm gives its Codex child a random, short-lived proxy key
  accepted only by that arm's loopback gateway. Tool subprocess inheritance is
  fixed to `none` with an empty `set` map and profile loading disabled.
- Every arm creates a new SDK client and thread. Runs are sequential, have one
  attempt, and use deterministic counterbalanced AB/BA order.
- Every arm also creates a new loopback Responses gateway. It accepts exactly
  one authenticated request, requires the pinned model and exact
  `update_plan`-only advertised tool surface, rejects image/continuation/
  background requests, requires the exact bound instructions and arm input,
  strips Codex session/client/cache metadata, projects a pinned tool schema,
  injects `tool_choice: "none"`, and forwards only to the pinned official
  upstream with the parent-held API key.
- Codex uses a dedicated custom provider with WebSockets and transport retries
  disabled. Its persisted fallback URL is an unusable loopback port; only the
  per-arm command-line policy replaces it with the live gateway URL. A missing
  or ignored override therefore cannot silently fall through to the public
  provider with the child proxy credential.
- Configurable budgets cap cases, provider calls, per-input UTF-8 bytes, total
  dataset bytes, output tokens per call, total reserved output tokens, total
  paired-arm execution duration, and streamed gateway response bytes.
  Case/input/dataset/call budgets are checked before provider access; each arm
  reserves its output allowance before its one permitted request.
- The receipt path is exclusively reserved with mode `0600` before executable
  preflight or provider access. A pre-existing file or symlink therefore fails
  before billable work begins.
- Receipts contain HMAC case references, configuration/executable digests,
  bounded counters, latency, reason codes, an explicit execution mode, and the
  public evidence `keyId`. A domain-separated HMAC authenticates the complete
  canonical receipt body. The `keyId` is also bound into the HMAC-protected
  case/dataset payloads and carried by both plan and receipt. Receipts contain no
  input, candidate, model response, item trace, path, provider error, or session
  ID.
- `RunResult.usage === null`, invalid counter relationships, or a failed turn
  makes accounting incomplete. Such a run exits `2`; it is not silently counted
  as a saving.

## Resource budgets

All limits are explicit in `benchmark` configuration:

- `maxCases`: dataset case count;
- `maxProviderCalls`: at most one forwarded request per arm, with two arms per
  case;
- `maxInputBytes`: UTF-8 bytes in each original or candidate input;
- `maxDatasetBytes`: combined UTF-8 bytes across all originals and candidates;
- `maxOutputTokensPerCall`: upper bound for one arm; the gateway injects the
  lower of this value and the equal share of the effective total output budget;
- `maxTotalOutputTokens`: output allowance reserved across all arms;
- `maxRunDurationMs`: host deadline for the paired provider-arm execution,
  excluding offline validation, executable preflight, and the public canary;
- `maxGatewayResponseBytes`: streamed upstream response bytes allowed per arm.

The request-envelope byte ceiling is derived from `maxInputBytes` plus a fixed
2 MiB protocol allowance. It is enforced by the loopback gateway before JSON
parsing or upstream forwarding.

Exhausting an arm-level call, output, duration, request, or response allowance
fails closed. These limits bound the application path but do not replace the
provider-side spend limit described under
[Containment limits](#containment-limits).

## Binary opt-in

The workspace deliberately ignores the SDK's platform-native optional packages.
pnpm applies that rule at workspace level, so this app uses the SDK-supported
`codexPathOverride` instead of silently changing every package install.

`codex.codexPathOverride`, `codex.expectedExecutableDigest`, and the exact CLI
version are mandatory. The source path is resolved relative to the config and
must identify an executable regular file no larger than 512 MiB. A real run
copies it into a private `0700` directory, marks the staged copy non-writable,
and performs version and streaming SHA-256 checks on that copy. Only the staged
path is given to the SDK. Integrity is rechecked before and after every arm,
and any mismatch aborts the whole run rather than producing a partial receipt.
The private copy is deleted before receipt output.

The digest in the example is an intentionally unusable all-zero placeholder.
Replace it with `sha256:` plus the lowercase SHA-256 of the trusted exact
`0.144.4` executable. A CLI such as `0.144.5`, a digest mismatch, or a path swap
is deliberately rejected; upgrading requires moving the SDK contract tests,
CLI version, and reviewed digest together.

The example path is a placeholder and is never accessed by `validate` or
`plan`. Before `run`, point it at a trusted exact-version executable and set the
API-key environment named by `codex.authentication.apiKeyEnv`. Local Codex
login state, user plugins, MCP servers, skills, configuration, and sessions are
not reused: the run gets a fresh `CODEX_HOME`. The CLI reads the real API key
into the parent process, while the SDK child receives only a per-arm loopback
proxy credential.

## Tool and host boundary

The locked policy follows the official `0.144.4` config surface: it sets
`allow_login_shell = false`, `shell_environment_policy.inherit = "none"`,
`experimental_use_profile = false`, `ignore_default_excludes = false`, and
`set = {}`. It also disables `shell_tool`, `unified_exec`, code mode, plugins,
apps, connectors, collaboration, browser, image generation, and web/search
features. `CODEX_HOME/environments.toml` fixes `default = "none"` and
`include_local = false`; because the child environment excludes every remote
executor variable, no environment is available. The generated one-entry model
catalog binds the selected model to text-only input, a disabled shell, no
`apply_patch` capability, and no experimental model tools. Equivalent SDK
overrides provide defense in depth.

The only core tool still advertised by this pinned composition is the
non-execution `update_plan` utility; Codex `0.144.4` constructs it
unconditionally. The real-run loopback gateway fails closed unless the
effective outbound request advertises exactly that one tool. It additionally
forces `tool_choice: "none"`, `parallel_tool_calls: false`, `store: false`, and a
configured `max_output_tokens` before forwarding. A second request in the same
arm is rejected.

The locked custom provider sets `supports_websockets: false`,
`request_max_retries: 0`, and `stream_max_retries: 0`. This avoids an
unattested WebSocket path and makes the gateway's single-request budget the
only provider transport path. The static provider URL is fail-closed loopback;
the official OpenAI HTTPS URL exists only in the parent gateway's upstream
policy.

Before private data reaches an upstream provider, a separate isolated runtime
runs a fixed public canary through the staged binary and the loopback gateway.
Its upstream is an in-process fake Responses endpoint. Failure to observe the
expected model, request shape, or exact `update_plan` surface aborts the run.
This attestation is repeated by policy enforcement on every real arm request.

Linux CI downloads the exact platform archive only from its versioned npm URL,
verifies a repository-pinned SHA-512 for the archive and SHA-256 for the native
binary before execution, then runs a fake-provider conformance turn. It asserts
that no shell, execution, filesystem, image, web, skill, plugin, or MCP tool is
exposed. The fake provider then requests `view_image` against a valid PNG
outside the workspace and verifies that Codex returns an unsupported-call result
with no encoded image data. This test makes no external model-provider call.

This boundary is pinned to the official
[SDK environment contract](https://github.com/openai/codex/blob/rust-v0.144.4/sdk/typescript/README.md#controlling-the-codex-cli-environment),
[v0.144.4 config schema](https://github.com/openai/codex/blob/rust-v0.144.4/codex-rs/core/config.schema.json),
[environment-file precedence](https://github.com/openai/codex/blob/rust-v0.144.4/codex-rs/exec-server/src/environment.rs#L96-L119),
[environment TOML semantics](https://github.com/openai/codex/blob/rust-v0.144.4/codex-rs/exec-server/src/environment_toml.rs),
[static catalog selection](https://github.com/openai/codex/blob/rust-v0.144.4/codex-rs/model-provider/src/provider.rs#L315-L335),
and [tool-selection logic](https://github.com/openai/codex/blob/rust-v0.144.4/codex-rs/core/src/tools/spec_plan.rs).
Those sources must be reviewed again before changing either pin.

Codex `0.144.4` does not expose one public config switch that removes every
core tool. This composition therefore removes the execution environment itself:
in `0.144.4`, `view_image` is added only when an environment exists, and
`apply_patch` needs both an environment and model capability. The text-only
model catalog is a second guard: even if a future composition accidentally
restores an environment, this pinned handler rejects `view_image` before
parsing arguments, resolving a path, or reading bytes.

## Containment limits

This remains application-level containment, not an OS-level filesystem or
process isolation boundary. A fresh `CODEX_HOME`, command-line overrides, the
public canary, and per-request gateway checks do not prove that every
system/MDM-managed Codex layer has been removed. In particular, a higher-trust
managed configuration or legacy `notify` command can execute outside the
Responses request surface and therefore cannot be neutralized absolutely by
this process.

Run the research composition only on a dedicated, clean, least-privilege host,
container, or VM with no managed Codex configuration, legacy notifications,
plugins, hooks, MCP servers, or unrelated credentials. Re-audit the exact CLI
source whenever the SDK/CLI pin changes.

SDK/CLI `0.144.4` is not launched with `--ephemeral`. Normal completion removes
the private runtime and staged executable, but a crash, `SIGKILL`, power loss,
or host termination can leave raw Codex session material inside its private
temporary directory. Before creating a later runtime, a conservative scavenger
removes only private, same-user IntentABI runtime and staged-binary artifact
directories whose lease PID is no longer alive; live leases are preserved, and
missing/invalid leases get a 24-hour grace period. This cannot clean anything at
the instant of abrupt termination, so residue remains until the next invocation;
inspect and remove abandoned benchmark temp directories manually before
decommissioning or reassigning the host.

The application budgets are fail-closed local controls, not an authoritative
billing ceiling. Configure a dedicated least-privilege API project/key with a
provider-side spend limit as the final cost boundary. A host timeout or abort
does not by itself prove that upstream billing stopped immediately.

## Commands

```bash
pnpm codex:bench validate \
  --config config/codex-bench.example.json \
  --dataset fixtures/codex-bench-conformance.json

INTENTABI_BENCH_HMAC_SECRET='<at-least-32-random-bytes>' \
pnpm codex:bench plan \
  --config config/codex-bench.example.json \
  --dataset fixtures/codex-bench-conformance.json

INTENTABI_BENCH_HMAC_SECRET='<at-least-32-random-bytes>' \
INTENTABI_CODEX_API_KEY='<dedicated-least-privilege-api-key>' \
pnpm codex:bench run \
  --config config/codex-bench.example.json \
  --dataset fixtures/codex-bench-conformance.json \
  --out codex-bench-receipt.json \
  --execute \
  --allow-candidate-submission
```

The output file is exclusively created with mode `0600` before executable
preflight or provider access. Its canonical parent must be owned by the current
user and not group/world writable; existing files and symlinks at the final path
are not overwritten. Commit and cleanup re-check the reserved inode, so a path
swap cannot overwrite or remove a replacement file.

To repeat the fake-provider boundary check with a trusted native `0.144.4`
binary:

```bash
INTENTABI_CODEX_SECURITY_CLI=/absolute/path/to/native/codex \
pnpm --filter @intentabi/codex-bench exec vitest run \
  test/tool-surface.integration.test.ts
```

## What the receipt proves

For completed pairs it reports exact integer counters exposed by the SDK:
input, cached input, output, and reasoning output tokens. It also reports a
monotonic host-side latency and the observed input-token delta. Provenance is
`host-observed-codex-sdk-run-result`: this is not a signed provider receipt.
`receiptMac` is local tamper evidence over the canonical receipt body under the
configured evidence HMAC key; verification requires that secret and does not
turn host observations into provider attestations. The public `keyId` in the
plan and receipt identifies the HMAC key lineage without exposing key material;
changing it changes the HMAC-bound case and dataset references.

The protocol digest binds the benchmark-core, Codex composition, and gateway
implementation identifiers together with the exact SDK/CLI, executable digest,
model/tool/process policies, output-allocation rule, public-canary digest, and
receipt-MAC domain. Any semantic change to those controls requires an explicit
implementation/schema bump.

Production CLI receipts are labeled `pinned-provider-boundary`. Dependency-
injected unit/integration runs are labeled `injected-test-boundary`, even when
they use the same plan and version pins, so fake-provider evidence cannot be
mistaken for a real bounded run.

The `cold`/`warm` value is dataset protocol metadata. SDK `0.144.4` has no cache
flush or warm-state control, so the app does not claim that label establishes
provider cache state; the observed cached-input counter remains visible.

The receipt does **not** measure task quality, semantic equivalence, safety,
price, normalized cost, cache-write tokens, or statistical confidence. It also
cannot prove a reproducible model backend behind an alias. A positive input
delta is therefore diagnostic, not token-saving product evidence or net value.

No benchmark result triggers automatic promotion. SemWitness remains the
promotion authority. Its current active host contract is limited to promoted
`tool`-role typed JSON through `json-jcs@1`, while the Codex SDK surface accepts
user input. This conformance receipt intentionally cannot be fed to or
substituted for the SemWitness promotion workbench. A future Codex-specific
candidate contract needs its own held-out task oracle, exact provider
accounting, model/prompt/tool bindings, unsafe-accept bound, and
SemWitness-owned promotion artifact before any transformed production request.

## Test boundary

Regular tests use injected clients/runners. Gateway and public-canary tests use
in-process fake upstreams; the tool-boundary test runs the pinned native CLI
only against a local fake provider. Automated tests submit no prompt and no API
key to an external provider. A real model execution remains a manual, billable,
double-opt-in smoke and should additionally use a provider-side spend cap.
