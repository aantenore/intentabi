# IntentABI

IntentABI is a provider-agnostic **shadow qualification host** for measuring
whether different user phrasings can safely converge on the same typed intent
beside a real application route. It never serves candidate content, skips the
ordinary route, or treats similarity as cache authorization.

The first contract slices integrate Agentic SDLC and a Codex SDK shadow host.
SemWitness remains the sole owner of Intent IR, verified preparation,
normalization witnesses, evaluation, and promotion. The trusted Codex host sees
request content in process; IntentABI core, telemetry, and sinks receive only
keyed, scope/route-bound evidence through anti-corruption adapters.

An additional research-only Codex benchmark composition can validate and plan a
paired baseline/candidate experiment entirely offline. Provider execution needs
two explicit CLI consent flags and produces only a content-free conformance
receipt; it cannot create promotion evidence or an activation manifest. Real
runs additionally pin and privately stage the exact CLI, run a public boundary
canary, and use a fresh minimal Git workspace. Every arm gets a one-request
loopback gateway: the real provider key remains in the parent process, while
the Codex child receives only a per-arm proxy key. Configurable call, input,
output, duration, and response-byte budgets fail closed; automated tests use
only fake upstreams and make no real provider calls.

## Why This Exists

Semantic caching is valuable only after equivalence, scope, authorization,
freshness, side effects, dependencies, and regressions have been measured.
IntentABI creates evidence before an active cache exists, so a future reuse
decision stays reversible and benchmark-driven rather than threshold-driven.

For hosts that already captured complete, sealed SemWitness case records,
`evaluateHostAttestedPromotionRun` provides one narrow application boundary:
host attestation and unknown records enter; SemWitness assembles the binding,
IntentABI emits deterministic JSONL, and SemWitness reparses and evaluates the
exact artifact. The returned workbench may validly be `qualified: false`.
IntentABI never fills missing witnesses, derives promotion counters, or carries
candidate or infrastructure payloads through this API.

This alpha proves a narrow contract:

- exact configured aliases can converge through SemWitness;
- a trusted operation-to-route binding prevents measuring intent A against
  executed input B;
- an untrusted nomination store can report only `found`/`not found`, and a hit
  is labeled `unverified-candidate-observed`;
- the ordinary route remains the only source of application output;
- the Codex shadow host can observe a SemWitness-prepared candidate while
  submitting the original input byte-for-byte to `Thread.run`;
- evidence is emitted in an authenticated, content-free envelope.

It does **not** prove broad paraphrase recall, token savings, cache safety,
lower model latency, or safe prompt rewriting. The Codex path is deliberately
passthrough-only until held-out task and provider-usage evidence passes the
existing SemWitness gates.

## Run the Source Alpha

Requirements: Node.js 24+ and pnpm 11. The packages are intentionally private
and source-checkout-only while SemWitness is pinned to an unreleased Git commit.

```bash
pnpm install --frozen-lockfile
pnpm check
```

macOS/Linux:

```bash
INTENTABI_HMAC_SECRET="$(openssl rand -hex 32)" \
  pnpm shadow \
  --config config/intentabi.example.json \
  --request fixtures/shadow-request.json
```

PowerShell:

```powershell
$env:INTENTABI_HMAC_SECRET = -join ((1..64) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
pnpm shadow --config config/intentabi.example.json --request fixtures/shadow-request.json
```

The channels are intentionally separate:

- stdout: `intentabi.shadow.result`, containing the ordinary route output;
- stderr: `intentabi.shadow.evidence`, containing an HMAC-authenticated
  envelope with keyed bindings and reason codes.

The example uses a deterministic fixture. A real Agentic SDLC route uses
`agenticSdlc.kind: "cli"`, an absolute or config-relative entrypoint/root, and a
host-owned `deploymentRevisionDigest`. The adapter combines that digest with the
entrypoint file hash, invokes only `route decide`, passes no raw prompt, and
strictly validates the current object-shaped canonical intent contract.

Every SemWitness operation that may be measured also needs an exact trusted
`semwitness.routeBindings` entry. A mismatch bypasses shadow measurement while
the ordinary route still executes.

For a reproducible read-only contract smoke against an installed Agentic SDLC
checkout, set `AGENTIC_SDLC_ENTRYPOINT`, `AGENTIC_SDLC_ROOT`, and a host-derived
`AGENTIC_SDLC_DEPLOYMENT_REVISION_DIGEST`, then run
`pnpm smoke:agentic-sdlc`.

## Safety Invariants

- configuration accepts only `mode: "shadow"`;
- the request file contains no tenant or authorization claims; the CLI takes
  measurement scope from trusted host configuration;
- library hosts must derive scope from authenticated context, not user text;
- intent, witness, scope, route input, route revision, and execution output are
  represented by domain-separated keyed digests in telemetry;
- raw semantic SHA-256 digests never cross the SemWitness adapter;
- the nomination-store port has no content-read or cache-admission method;
- a positive store probe is unverified and never applied;
- the evidence sink receives `{eventId, keyId, evidence, mac}` atomically;
- malformed inspector/store results become shadow faults, never route failures;
- timeout-aware ports receive `AbortSignal` and event IDs for cooperative
  cancellation/idempotency; a timed-out sink is reported `unacknowledged`;
- stdout application output is never mixed into the stderr evidence event.
- Codex candidates, prompts, outputs, working directories, and run options
  never appear raw in shadow evidence; proof content is reduced to presence;
- Codex transport receives only the captured original input; candidate,
  preparer timeout, malformed evidence, and sink failure cannot replace it;
- structured text/image SDK inputs bypass preparation and retain their exact
  object identity in the passthrough transport.

## Workspace

```text
packages/core                 provider-agnostic runtime and ports
packages/adapter-semwitness   route binding and SemWitness promotion orchestration
packages/adapter-agentic-sdlc typed fixture and trusted CLI routes
packages/codex-host             SemWitness-preparer/Codex transport host
packages/adapter-codex-sdk      pinned Thread factory and passthrough adapter
packages/benchmark-core         provider-neutral paired conformance runner
packages/store-memory         metadata-only development nomination store
apps/cli                      first Agentic SDLC host composition
apps/codex-bench              opt-in Codex SDK research composition
```

See [Codex benchmark](docs/codex-benchmark.md) for offline validation, explicit
execution, binary pinning, gateway/resource limits, workspace/process
isolation, and the limits of the resulting measurements. Real runs belong on a
dedicated clean host/container/VM because system/MDM configuration and legacy
Codex notifications cannot be neutralized absolutely from inside the process.

Read [architecture](docs/architecture.md),
[delivery contract](docs/delivery-contract.md),
[threat model](docs/threat-model.md),
[landscape](docs/landscape.md), and
[Codex integration boundary](docs/codex-integration.md) before extending the
alpha.

## Non-goals for `v0.1`

No embeddings, vector database, active cache, response reuse, transformed
Codex submission, transparent composer interception, production multi-tenant
store, or npm release. The runtime and shadow path remain provider-free; the
separate, double-opt-in Codex benchmark can call a network model provider only
as a research-conformance diagnostic. The exact-alias fixture proves contracts;
it is not a claim of universal natural-language equivalence.

Apache-2.0.
