# Delivery Contract

## Product Claim

IntentABI `v0.1.0-alpha.1` demonstrates that a source-installed host can measure
typed intent convergence beside an application route while cryptographically
binding the normalized operation to the exact executed input, without creating
an active cache or duplicating SemWitness.

It does **not** demonstrate broad paraphrase equivalence, production cache
safety, token savings, lower model latency, transparent Codex prompt rewriting,
or an installable npm release. Those require held-out and operational evidence.

## Acceptance Criteria

- [x] Node 24 TypeScript workspace with replaceable runtime ports.
- [x] Core has no provider/application-specific composition schema.
- [x] Strict, controlled-namespace, shadow-only host configuration.
- [x] SemWitness consumed through public exports at immutable commit
      `ea205667b53ded6fb18ce8fdfa477488a361a3f2`.
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
      provider, network, store, cache, or candidate payloads.

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
