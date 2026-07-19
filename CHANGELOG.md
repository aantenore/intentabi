# Changelog

All notable changes to this project are documented here. The project is still
source-alpha and follows semantic-versioned prereleases.

## Unreleased

### Added

- Added a deterministic CLINC150 external normalizer pilot with pinned source
  provenance, train/validation-to-registry and test/OOS-to-held-out split
  isolation, explicit equivalent/distinct comparisons, and content-free
  SemWitness reports.
- Added an injectable SemWitness proposal compiler boundary while keeping the
  declarative operation registry authoritative for typed intent and effect.
- Added a resumable, config-driven OpenAI-compatible capture app that writes
  atomic per-case observations and deterministically assembles the existing
  cache-impact workload only after host-oracle matches.
- Added explicit reasoning-budget failure classification, provider usage and
  reasoning digests, and machine-readable non-qualification/non-activation
  labels on every record and manifest.
- Added owner-private append-only normalizer evaluation claims and checkpoints,
  bounded per-invocation progress, zero-call replay, recovery of fully published
  records after lost acknowledgement, and fail-stop handling for attempts whose
  outcome is indeterminate.

### Changed

- Upgraded the normalizer-pilot config and artifact contracts to `v1alpha2`,
  replaced one-shot `--out` with resumable `--run-dir`, added optional
  `--limit` plus `maxCheckpointBytes`, and publish the final artifact only after
  every planned observation completes.
- Source-alpha TypeScript callers now pass `runDirectory` instead of
  `outputPath` and handle the `incomplete | indeterminate | complete`
  discriminated execution result instead of receiving an artifact directly.
- Pinned SemWitness `v0.7.0-alpha.1` at immutable revision
  `dc306c653f86ea6c33a46514d44de20a39caa97b` for its checkpoint-aware evaluator.

### Fixed

- Fail closed on external compiler errors, malformed proposals, unknown
  operations, registry/compiler disagreement, and non-read effects.
- Bind external pilot reports to deployment revision, credential identity,
  compiler manifest, registry, corpus, pinned evaluator, and attempt policy;
  validate compiler configuration without a model call and reject the example
  deployment placeholder on execution.
- Validate raw provider usage before SDK normalization and reject missing,
  partial, or inconsistent counters instead of recording synthetic zeroes.
- Bind resumable records to host-owned deployment and credential identities,
  reject redirected run directories, and preflight every persisted-artifact
  budget before a provider call.

## 0.2.0-alpha.2 - 2026-07-17

### Fixed

- Bound cache-impact dataset identity to the exact normalization registry,
  pinned adapter, policy, scope, and route configuration.
- Made unattested workload, usage-counter, and freshness provenance explicit in
  every cache-impact report.

## 0.2.0-alpha.1 - 2026-07-17

### Added

- Provider-neutral cache-impact study comparing exact-request and normalized
  intent keys over an ordered workload.
- Oracle-safe hit, collision, hit-rate lift, and normalization-aware input and
  output token metrics.
- Bounded offline `intentabi cache-impact evaluate` CLI with HMAC-authenticated,
  content-free reports and deterministic fixtures.

### Safety

- Candidate hits with mismatched expected-value digests fail the diagnostic
  gate and never count as token savings.
- Reports remain shadow-only, statistically unqualified, and unable to
  authorize cache activation.

## 0.1.0-alpha.1 - 2026-07-17

- Initial shadow-only IntentABI runtime, SemWitness anti-corruption adapter,
  Agentic SDLC and Codex research compositions, and Qualification Lab.
