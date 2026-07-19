# Delivery Contract

## Product Claim

IntentABI demonstrates that a source-installed host can measure
typed intent convergence beside an application route while cryptographically
binding the normalized operation to the exact executed input, without creating
an active cache or duplicating SemWitness.

It does **not** demonstrate broad paraphrase equivalence, production cache
safety, token savings, lower model latency, transparent Codex prompt rewriting,
or an installable npm release. The external CLINC150 pilot adds reproducible
English conformance evidence, but those claims still require representative
deployment and operational evidence.

## Acceptance Criteria

- [x] Node 24 TypeScript workspace with replaceable runtime ports.
- [x] Core has no provider/application-specific composition schema.
- [x] Strict, controlled-namespace, shadow-only host configuration.
- [x] SemWitness consumed through public exports at immutable commit
      `dc306c653f86ea6c33a46514d44de20a39caa97b` (`v0.7.0-alpha.1`).
- [x] Trusted operation-to-route-input binding; mismatches bypass measurement.
- [x] Ordinary Agentic SDLC route always executes and solely determines output.
- [x] Nomination store cannot return content; positive probes stay unverified;
      every decision has `applied: false`.
- [x] Configured paraphrases converge to one keyed shadow intent correlation.
- [x] Negation, effect, route-input, and scope mismatches bypass.
- [x] Malformed inspector/store data and optional-path faults preserve ordinary
      availability.
- [x] Sink/store ports receive abort signals and idempotency IDs; timeout is
      reported as `unacknowledged`.
- [x] Evidence contains no prompt, output, scope label, raw Intent IR, or raw
      intent/witness SHA digest.
- [x] Evidence is MAC-authenticated before delivery and kept separate from
      ordinary stdout.
- [x] Agentic SDLC adapter accepts current object-shaped canonical intents,
      excludes raw text, redacts child errors, snapshots options, and handles
      paths with spaces.
- [x] Codex SDK shadow host composes the public SemWitness preparer without
      copying its evaluator, corpus, or promotion rules.
- [x] Codex transport receives only the captured original input; verified
      candidates are HMAC-only observations and cannot be submitted.
- [x] Non-text input, malformed/faulted/timed-out preparation, opaque options,
      and evidence-sink failure preserve the ordinary Codex path.
- [x] Factory-bound `Thread.run` adapter preserves exact input, options
      identity, output, and missing-options call shape against pinned official
      SDK `0.144.4` types.
- [x] Codex evidence uses scope-bound HMACs, strict detached verification, and
      an atomic replay-guard port; no envelope is emitted without a binding.
- [x] Complete host-attested intent-cache evidence can be exported as
      deterministic SemWitness JSONL; closed schemas reject candidate payloads,
      and underfilled corpora remain unqualified under the real evaluator.
- [x] The host promotion facade composes SemWitness assembly, exact JSONL
      reparse, and SemWitness evaluation without deriving evidence or exposing
      provider, network, store, cache, or candidate payloads, and it no longer
      retains a duplicate parsed fixture beside the exact JSONL bytes.

> Alpha migration: `HostAttestedPromotionRunResult.fixture` was removed from
> the private source-workspace adapter. Consumers should retain
> `evidenceJsonl` only when they need the portable evidence artifact and use
> `workbench` for the authoritative SemWitness result.

## Promotion Gates

Active cache work is forbidden until all of these are true:

1. a representative held-out corpus proves useful paraphrase recall;
2. distinct near-miss and adversarial false merges stay inside a declared
   statistical bound;
3. scope, principal, authorization, freshness, effect, dependency, and
   revocation oracles are complete and host-derived;
4. task-quality regression and cost/latency measurements show net value;
5. SemWitness promotion evidence passes for the intended artifact tier;
6. a scope-bound authenticated store replaces the memory adapter;
7. a complete SemWitness cache binding/key and post-read admission check exist;
8. an explicit versioned contract authorizes active mode.

Until then, `mode: "active"` is rejected and no candidate-content API exists.

Transformed Codex submission is a separate promotion gate. It additionally
requires counterbalanced ordinary/candidate runs, deterministic task/diff
oracles, provider-reported SDK or App Server usage, tool and approval parity,
zero measured task regressions, and positive net value under the existing
SemWitness host-promotion contract. SDK shadow evidence cannot authorize it.

## Source-alpha Definition of Done

`pnpm check` must pass formatting, warning-free lint, strict TypeScript builds,
and tests. CI must repeat it on Node 24 for Ubuntu, macOS, and Windows, plus a
production dependency audit and CLI smoke. A source-alpha publication also
requires a clean frozen install from the pinned SemWitness Git dependency and a
real local Agentic SDLC route smoke.

Package publication is a separate gate: SemWitness needs an immutable registry
artifact, every package must build during pack, and clean consumers must install,
import exports, and run the CLI without Git/SSH-specific configuration.

## Qualification Lab Increment

The delivered increment is specified in
[Qualification Lab](qualification-lab.md). It adds bounded provider-neutral
planning and evidence orchestration while preserving SemWitness as the sole
qualification authority. Its conformance result remains diagnostic and cannot
relax any active-cache or transformed-Codex promotion gate above.

- [x] Counterbalanced plans contain only HMAC-bound case/cell references.
- [x] The generic core rejects hostile getters, proxies, sparse arrays,
      cancellation, duplicate record digests, and authority/plan mismatches.
- [x] `intentabi-qualify validate` performs no execution or authority call;
      `plan` is content-free; `run` requires `--execute`.
- [x] Exact sealed evidence is independently reparsed and re-evaluated by
      SemWitness before a decision is projected.
- [x] Public receipts remain content-free and activation-forbidden; exact
      evidence/workbench bytes exist only in an atomic owner-only artifact.
- [x] Agentic SDLC AB/BA replay is read-only, version-pinned, state-stable, and
      returns HMAC-only route/contract/outcome observations.
- [x] Shared CLI I/O rejects path substitution and publishes complete `0600`
      artifacts with no-clobber semantics.

## Cache Impact Lab Increment

The [Cache Impact Lab](cache-impact-lab.md) adds the missing workload-level
value loop without weakening the active-cache prohibition.

- [x] Reuses `SemWitnessIntentInspector`; no Intent IR or normalizer is copied.
- [x] Compares HMAC exact-request keys with scope/route-bound intent keys.
- [x] Uses a private host value digest to separate safe from unsafe candidate
      hits and excludes unsafe hits from token savings.
- [x] Accounts ordinary model input/output tokens and normalization overhead
      separately with exact integer arithmetic.
- [x] Bypass and inspection faults fall back to exact keys; calls are bounded.
- [x] Emits an HMAC-authenticated content-free report with activation forbidden
      and statistical readiness false.
- [x] Binds exact registry bytes, the pinned adapter implementation, policy,
      scope, and route map into report provenance and the dataset digest.
- [x] Labels host-supplied workload, unverified token counters, and unmodeled
      freshness directly in the report instead of implying external attestation.
- [x] Exit `0` requires zero unsafe hits/failures, positive safe-hit lift, and a
      positive net token delta; exit `2` preserves valid negative evidence.
- [x] CLI inputs use shared bounded, stable, non-symlink file reads and closed
      schemas.

## External Normalizer Pilot Increment

The [CLINC150 external normalizer pilot](clinc150-normalizer-pilot.md) tests a
replaceable SemWitness proposal compiler on language that is absent from the
trusted registry aliases. It is a separate quality stage, not cache-impact or
promotion evidence.

- [x] External compiler injection preserves exact-alias compatibility and
      compiles each observation once.
- [x] The declarative registry remains authoritative for operation-to-IntentIR
      and effect resolution; unknown, conflicting, malformed, failed, and
      side-effecting proposals bypass.
- [x] Compiler manifest and exact registry configuration are bound into adapter
      lineage.
- [x] The official CLINC150 source is pinned by full revision and SHA-256; its
      selected test/OOS phrases cannot enter registry aliases.
- [x] The checked-in configuration deterministically selects 128 English cases
      across 12 read labels and 192 explicit equivalent/distinct comparisons.
- [x] Validation makes zero compiler calls; execution requires `--execute` and
      `--allow-network`; artifacts are atomically owner-only and no-clobber.
- [x] SemWitness remains the sole evaluator for exact intent, bypass,
      repeatability, convergence, unsafe accepts, and false merges.
- [x] Every artifact denies statistical qualification, economic qualification,
      promotion, and activation regardless of the conformance result.
- [ ] Add representative Italian and deployment-specific held-out evidence.
- [ ] Observe compiler token cost and latency separately before making an
      economic claim.
- [ ] Add independently sampled deployment evidence large enough for the
      declared statistical safety bound before any release or pin decision.
- [x] Persist owner-private, content-free per-attempt claims and checkpoints;
      resume completed work without duplicate compiler calls and fail-stop on
      indeterminate claimed attempts.
