# IntentABI

## What this changes in the real world

People can ask for the same thing in many ways, so an exact-text cache misses useful reuse. A naive
"similar meaning" cache is worse: it can return an answer from the wrong route, user scope, data
version, or authorization context. **IntentABI measures whether explicitly known alternate
phrasings can converge on the same typed intent while the real application continues to answer
normally. It collects evidence before anyone turns a semantic cache on.**

### A concrete example

An application is configured to treat "show unpaid invoices" and "list invoices not yet paid" as
the same read operation. IntentABI observes the candidate key in shadow mode, binds it to the exact
route and deployment revision, and still sends the original request through the ordinary route. Its
offline lab then reports whether the normalized key would have created a safe additional hit and
whether measured token usage improved. It never returns the candidate cached value to the user.

IntentABI is for AI platform teams evaluating intent normalization and semantic caching without
betting production correctness on a similarity threshold.

| Feature                                | Practical benefit                                                                                           |
| -------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| Shadow-only passthrough                | Teams can study candidate reuse without changing application answers or bypassing the normal route.         |
| Typed intent and route bindings        | Equivalent wording is not enough; evidence stays tied to the intended operation, scope, and deployment.     |
| Content-free authenticated evidence    | Experiments can be audited without placing prompts, outputs, or cached values in telemetry.                 |
| Resumable provider capture             | Interrupted local or remote model measurements continue from atomic per-case records instead of restarting. |
| Raw-versus-normalized cache-impact lab | Teams can see workload-specific safe-hit and token differences instead of relying on a sales claim.         |
| Counterbalanced qualification runs     | Baseline and candidate paths can be compared in both orders to reduce simple ordering bias.                 |
| Explicit activation boundary           | A positive experiment remains evidence, not permission to serve cached content.                             |

> **Maturity:** IntentABI is alpha, source-checkout-only, and shadow-only. It currently evaluates
> configured equivalences and bounded experiments; it does not prove broad paraphrase recall,
> production cache safety, lower latency, or general token savings. It never activates a cache or
> authorizes a cached response.

## Technical scope

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

The Qualification Lab is the evidence boundary after capture: it creates a
counterbalanced HMAC-only plan, accepts host-sealed SemWitness records, and
publishes an authenticated receipt plus a private exact authority artifact. It
does not call a model, generate evidence, serve a cache hit, or authorize active
reuse. A read-only Agentic SDLC adapter separately checks route, contract, and
outcome stability in both AB and BA order without exposing task content.

The cache-impact lab is the smaller feedback loop before qualification. It
replays an ordered private workload through the existing SemWitness adapter,
compares exact-request keys with normalized intent keys, checks every candidate
hit against a host-supplied value digest, and reports safe-hit lift plus net
input/output token deltas. It remains offline, content-free, and shadow-only.
The report binds the exact registry bytes and inspector configuration, while
labeling workload, usage, and freshness provenance as unattested diagnostics.

The separate Diagnostic Provider Capture fills the input gap without adding a
router or cache: it calls a configured OpenAI-compatible endpoint, compares
JSON output with a host oracle, persists one private immutable observation per
case, resumes missing work, and assembles the existing cache-impact workload.
Its records explicitly deny statistical qualification and activation. Resume
is bound to host-declared deployment and credential identities, raw token usage
fails closed before SDK normalization can hide missing fields, and artifact
budgets are preflighted before the first provider call.

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

It does **not** prove broad paraphrase recall, production cache safety, general
token savings, lower model latency, or safe prompt rewriting. The cache-impact
lab can measure workload-specific hit and token deltas, but its report declares
statistical readiness false. The Codex path is deliberately passthrough-only
until held-out task and provider-usage evidence passes the existing SemWitness
gates.

## Run the Source Alpha

Requirements: Node.js 24+ and pnpm 11. The packages are intentionally private
and source-checkout-only while SemWitness is pinned to the immutable commit for
the `v0.6.0-alpha.1` prerelease.

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

## Run the Cache Impact Lab

The bundled workload demonstrates the concrete hypothesis: exact cache keys
miss differently worded requests, while SemWitness-normalized keys converge
configured equivalent phrasings. Token counters are workload observations,
not estimates produced by this tool.

```bash
INTENTABI_HMAC_SECRET="$(openssl rand -hex 32)" \
  pnpm cache:impact \
  --config config/cache-impact.example.json \
  --workload fixtures/cache-impact-workload.json
```

PowerShell:

```powershell
$env:INTENTABI_HMAC_SECRET = -join ((1..64) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
pnpm cache:impact --config config/cache-impact.example.json --workload fixtures/cache-impact-workload.json
```

The example reports one safe raw hit versus three safe normalized hits and a
63-token positive delta after normalization overhead. Exit `0` means the exact
diagnostic workload had safe hit lift and positive net tokens; exit `2` means a
complete report failed a safety or value gate; exit `1` means the boundary or
execution failed. None of the three authorizes cache activation. See
[Cache Impact Lab](docs/cache-impact-lab.md) for contracts and metric formulas.

## Capture Provider Measurements

The capture app turns real OpenAI-compatible usage observations into the
existing cache-impact workload without storing model output or separate
reasoning in clear. Validate first with zero provider calls:

```bash
pnpm capture:pilot validate \
  --config config/diagnostic-capture.ollama.example.json \
  --dataset fixtures/diagnostic-capture-smoke.json
```

Then use an empty private run directory and explicit execution consent:

```bash
pnpm capture:pilot run \
  --config config/diagnostic-capture.ollama.example.json \
  --dataset fixtures/diagnostic-capture-smoke.json \
  --run-dir /absolute/private/path/intentabi-pilot \
  --execute
```

Repeat the command to resume. A workload is published only after every case
matches the host JSON oracle. Change the configured deployment revision or
credential identity whenever that backend changes, and start a new run
directory. The bundled fixture is a four-case transport smoke, not statistical
evidence. See
[Diagnostic Provider Capture](docs/diagnostic-capture.md).

## Run the Qualification Lab

`validate` performs schema and budget checks without reading a secret or calling
SemWitness. `plan` emits only HMAC-bound references. `run` consumes private,
already-sealed evidence and requires explicit execution consent:

```bash
pnpm qualify validate \
  --config config/qualification.example.json \
  --dataset /private/held-out-metadata.json

INTENTABI_QUALIFICATION_HMAC_SECRET="<at-least-32-bytes>" \
  pnpm qualify plan \
  --config config/qualification.example.json \
  --dataset /private/held-out-metadata.json

INTENTABI_QUALIFICATION_HMAC_SECRET="<same-secret>" \
  pnpm qualify run \
  --config config/qualification.example.json \
  --dataset /private/held-out-metadata.json \
  --evidence /private/semwitness-input.json \
  --out /private/qualification-artifact.json \
  --execute
```

Exit `0` means SemWitness qualified the exact evidence but still does not
authorize activation; exit `2` is a valid unqualified result; exit `1` is a
boundary/execution failure. The output file is atomically published as `0600`
on POSIX and contains the private exact JSONL/workbench, while stdout is
content-free. See [Qualification Lab](docs/qualification-lab.md).

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
- cache-impact raw keys bind source, locale, scope, epoch, route, revision, and
  route input; normalized keys keep the SemWitness policy/ontology binding;
- expected value digests stay private, unsafe hits never save tokens, and every
  report explicitly forbids activation.

## Workspace

```text
packages/core                    provider-agnostic runtime and ports
packages/adapter-semwitness      route binding and SemWitness promotion orchestration
packages/adapter-agentic-sdlc    typed fixture and trusted CLI routes
packages/codex-host              SemWitness-preparer/Codex transport host
packages/adapter-codex-sdk       pinned Thread factory and passthrough adapter
packages/benchmark-core          paired runs and raw-vs-normalized impact metrics
packages/qualification-core      provider-neutral plan/authority/receipt core
packages/cli-io                  bounded reads and atomic private publication
packages/store-memory            metadata-only development nomination store
apps/cli                         first Agentic SDLC host composition
apps/codex-bench                 opt-in Codex SDK research composition
apps/diagnostic-capture          resumable OpenAI-compatible usage capture
apps/qualification               offline SemWitness qualification handoff
```

See [Codex benchmark](docs/codex-benchmark.md) for offline validation, explicit
execution, binary pinning, gateway/resource limits, workspace/process
isolation, and the limits of the resulting measurements. Real runs belong on a
dedicated clean host/container/VM because system/MDM configuration and legacy
Codex notifications cannot be neutralized absolutely from inside the process.

Read [architecture](docs/architecture.md),
[delivery contract](docs/delivery-contract.md),
[threat model](docs/threat-model.md),
[landscape](docs/landscape.md),
[cache-impact lab](docs/cache-impact-lab.md),
[diagnostic provider capture](docs/diagnostic-capture.md), and
[Codex integration boundary](docs/codex-integration.md) before extending the
alpha.

## Non-goals for this alpha

No embeddings, vector database, active cache, response reuse, transformed
Codex submission, transparent composer interception, production multi-tenant
store, or npm release. The runtime and cache-impact core remain provider-free;
the separate, explicit-execution capture and Codex benchmark apps may call a
configured model only for diagnostics. The exact-alias fixture proves
contracts and arithmetic; it is not a claim of universal natural-language
equivalence.

Apache-2.0.
