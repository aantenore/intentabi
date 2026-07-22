# IntentABI Documentation

Start with the project [README](../README.md) for the plain-language outcome,
source-alpha commands, and maturity boundary.

## Core Boundaries

- [Architecture](architecture.md) — runtime, adapters, evidence, and ownership.
- [Threat model](threat-model.md) — trust boundaries, controls, and residual
  risks.
- [Delivery contract](delivery-contract.md) — supported behavior and release
  expectations.
- [Landscape](landscape.md) — build-vs-buy decisions and differentiated scope.

## Experiments and Qualification

- [Guarded observation reuse](guarded-observation-reuse.md) — compare exact,
  intent-only, and SemWitness-guarded reuse without serving a cached value.
- [Cache Impact Lab](cache-impact-lab.md) — measure workload-specific safe-hit
  and token deltas.
- [CLINC150 external normalizer pilot](clinc150-normalizer-pilot.md) — evaluate
  an external proposal compiler on held-out public language.
- [Diagnostic provider capture](diagnostic-capture.md) — collect resumable
  provider usage observations for the cache-impact workload.
- [Qualification Lab](qualification-lab.md) — hand host-sealed evidence to the
  authoritative SemWitness evaluator.
- [Codex benchmark](codex-benchmark.md) — paired provider research with explicit
  execution and network consent.
- [Codex integration](codex-integration.md) — passthrough-only SDK boundary.

Every current experiment is shadow-only. A passing report is evidence, not
permission to activate caching, rewrite a request, or serve prior content.
