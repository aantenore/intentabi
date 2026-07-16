# IntentABI

IntentABI is a provider-agnostic **shadow qualification host** for measuring
whether different user phrasings can safely converge on the same typed intent
beside a real application route. It never serves candidate content, skips the
ordinary route, or treats similarity as cache authorization.

The first vertical slice integrates Agentic SDLC. SemWitness remains the sole
owner of Intent IR, normalization witnesses, and qualification. IntentABI sees
only keyed, scope/route-bound correlation metadata through an anti-corruption
adapter.

## Why This Exists

Semantic caching is valuable only after equivalence, scope, authorization,
freshness, side effects, dependencies, and regressions have been measured.
IntentABI creates evidence before an active cache exists, so a future reuse
decision stays reversible and benchmark-driven rather than threshold-driven.

This alpha proves a narrow contract:

- exact configured aliases can converge through SemWitness;
- a trusted operation-to-route binding prevents measuring intent A against
  executed input B;
- an untrusted nomination store can report only `found`/`not found`, and a hit
  is labeled `unverified-candidate-observed`;
- the ordinary route remains the only source of application output;
- evidence is emitted in an authenticated, content-free envelope.

It does **not** prove broad paraphrase recall, token savings, cache safety, or
lower model latency.

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

## Workspace

```text
packages/core                 provider-agnostic runtime and ports
packages/adapter-semwitness   semantic authority and route-binding adapter
packages/adapter-agentic-sdlc typed fixture and trusted CLI routes
packages/store-memory         metadata-only development nomination store
apps/cli                      first Agentic SDLC host composition
```

Read [architecture](docs/architecture.md),
[delivery contract](docs/delivery-contract.md),
[threat model](docs/threat-model.md),
[landscape](docs/landscape.md), and
[Codex integration boundary](docs/codex-integration.md) before extending the
alpha.

## Non-goals for `v0.1`

No embeddings, vector database, network model provider, active cache, response
reuse, prompt rewriting, transparent Codex-composer interception, production
multi-tenant store, or npm release. The exact-alias fixture proves contracts;
it is not a claim of universal natural-language equivalence.

Apache-2.0.
