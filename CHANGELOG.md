# Changelog

All notable changes to this project are documented here. The project is still
source-alpha and follows semantic-versioned prereleases.

## Unreleased

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
