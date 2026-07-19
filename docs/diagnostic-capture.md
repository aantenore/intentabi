# Diagnostic provider capture

## What this changes in the real world

A useful cache experiment needs the token counters and output observed from a
real model, not numbers typed into a fixture. A 64-case local run can also take
long enough that restarting from zero after an interruption wastes time.

The Diagnostic Provider Capture calls one replaceable OpenAI-compatible model
per case, checks its JSON output against a host-owned oracle, and saves each
completed observation as a private no-clobber record. Running the same command
again skips verified records and continues with the first missing case. Only a
complete, oracle-matching run becomes the existing Cache Impact Lab workload.

Every record and manifest fixes:

- `classification: "diagnostic-held-out-pilot"`;
- `statisticalQualification: false`;
- `activationAuthorized: false`;
- `promotionManifest: "not-produced"`.

This is a measurement input, not a router, cache, promotion authority, or
serving credential. SemWitness remains the verifier and sole promotion
authority.

## Data flow

```mermaid
flowchart LR
  D["Private case dataset"] --> P["OpenAI-compatible provider"]
  P --> O["Host JSON oracle"]
  O --> R["Atomic private case record"]
  R --> A["Deterministic resume and assembly"]
  A --> W["Cache-impact workload v1"]
  W --> C["Existing Cache Impact Lab"]
  C -. "never authorizes" .-> X["Active cache"]
```

IntentABI owns provider measurement and workload assembly. The existing
`@intentabi/benchmark-core` stays provider-neutral. The capture app reuses
Vercel AI SDK and `@ai-sdk/openai-compatible`; it does not implement another
provider client or semantic router.

## Provider contract

Configuration selects the provider name, base URL, model, optional bearer-key
environment variable, system instructions, token and byte budgets, timeout,
and optional OpenAI-compatible `reasoningEffort`. It also requires a host-owned
`deploymentRevisionDigest` and non-secret `credentialKeyId`. These bind resume
to one frozen deployment and account/key identity even when the provider model
name is a mutable alias. Rotate either value and use a new run directory when
the deployment or credential identity changes. Plain HTTP is accepted only for
a loopback host; other providers require HTTPS. Redirects are denied and
request and response bytes are bounded.

Thinking models require special care. Some providers enable reasoning by
default and can spend the entire output allowance before producing JSON. The
bundled local example sets `reasoningEffort: "none"`. A length finish is
reported as `OUTPUT_BUDGET_EXHAUSTED_WITH_REASONING` when separate reasoning is
present, rather than being mislabeled as a semantic failure.

On success the host records exact integer input, output, total, and available
reasoning-token counters exposed by the provider response. The raw wire usage
object must contain coherent prompt, completion, and total counters before SDK
normalization; missing, partial, negative, unsafe, or inconsistent counters fail
closed as `USAGE_UNAVAILABLE`. A reasoning counter is preserved exactly when
the wire response supplies it; an omitted, null, or empty details object remains
`null` rather than being converted into a synthetic zero. These are
`host-observed-openai-compatible-response` observations, not signed provider
receipts. The model response and separate reasoning are not stored in clear:
the record carries their SHA-256 digests and a reasoning-presence bit.

Before the first provider call, capture constructs conservative maximum-size
record, workload, and manifest shapes for the exact dataset. Separate
`maxRecordBytes`, `maxWorkloadBytes`, and `maxManifestBytes` limits must contain
those shapes. This prevents an otherwise valid run from spending provider calls
and only then discovering that a mandatory artifact cannot be published.

## Oracle and assembly

Each private dataset case supplies:

- a stable case ID, source text, and locale;
- the exact route input used by the Cache Impact Lab;
- a host-owned JSON `oracleValue` describing the expected route result.

The capture compares canonical JSON digests, so harmless object-key ordering
does not change the result. A mismatch remains visible in its immutable case
record and final manifest, but no cache-impact workload is produced. This
prevents token counters from being combined with a provider output that failed
the host's task oracle.

The completed workload uses the existing
`io.github.aantenore.intentabi/cache-impact-workload/v1alpha1` schema. Source,
locale, route input, oracle digest, provider counters, and configured
normalization overhead are assembled in original dataset order. Reassembly of
the same validated records produces identical bytes.

## Run and resume

Validate configuration and dataset without a provider call:

```bash
pnpm capture:pilot validate \
  --config config/diagnostic-capture.ollama.example.json \
  --dataset fixtures/diagnostic-capture-smoke.json
```

Run the credential-free loopback example after starting a compatible local
server at the configured address:

```bash
umask 077
pnpm capture:pilot run \
  --config config/diagnostic-capture.ollama.example.json \
  --dataset fixtures/diagnostic-capture-smoke.json \
  --run-dir /absolute/private/path/intentabi-pilot \
  --execute
```

The command creates the private run directory when needed. Repeat the exact
command to resume. `--limit 1` captures at most one missing case, which is
useful for a first live smoke before a larger campaign.

After a complete oracle-matching capture, evaluate the generated workload:

```bash
INTENTABI_HMAC_SECRET="<at-least-32-random-bytes>" \
pnpm cache:impact \
  --config config/diagnostic-cache-impact.example.json \
  --workload /absolute/private/path/intentabi-pilot/cache-impact-workload.json
```

The bundled four-case dataset and matching registry prove transport, resume,
oracle, and assembly behavior only. They are configured-alias smoke fixtures,
not an independently sampled held-out population. A real pilot should use a
frozen external dataset and a new empty run directory.

## Private run layout

```text
intentabi-pilot/
  records/
    00000-case-id.json
    00001-case-id.json
  cache-impact-workload.json
  diagnostic-capture-manifest.json
```

Files are atomically published with no overwrite and mode `0600` on POSIX;
directories must remain private and final-component directory symlinks are
rejected before they are followed. Captured run/records directory identities
are rechecked around each path operation and provider boundary, so a persistent
replacement discards the operation and fails closed. Portable Node filesystem
APIs remain path-based: a process running as the same OS user could still swap
and restore a directory entirely between two system calls. Protect the host and
run directory from same-user interference when stronger native handle-relative
guarantees are required. Resume validates dataset, config, provider deployment
and credential identity, case, and oracle bindings before accepting a record. A
changed config, deployment, credential identity, or dataset needs a new run
directory instead of rewriting history.

The record files omit raw source, output, and reasoning, but stable digests can
still reveal equality or permit dictionary recovery for low-entropy values.
The assembled workload intentionally contains source text and route input.
Keep the whole run directory private and never commit it.

## What this does not prove

- The `held-out` label is host-declared, not statistically attested.
- Provider usage is observed by the host, not cryptographically signed.
- A loopback endpoint alone does not prove that its server cannot use cloud
  compute; configure and audit the selected runtime separately.
- Exact JSON oracle equality is a bounded task check, not general semantic
  equivalence, freshness, authorization, or safety.
- A complete capture does not qualify normalization, authorize cache
  activation, or permit serving a cached response.
