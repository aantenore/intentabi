# Threat Model

## Protected Assets

- user prompts and ordinary route outputs;
- tenant, principal, authorization, and workload equality information;
- semantic witnesses and source-to-execution lineage;
- ordinary-route availability and integrity;
- the future decision about whether any form of reuse is safe.

## Trust Boundaries

Trusted deployment inputs are the HMAC key, SemWitness registry/policy, exact
operation-to-route bindings, host-derived scope, route revision binding, and the
configured Agentic SDLC entrypoint. The request text, probabilistic compiler,
nomination store, route output, and remote evidence sink are untrusted or may
fail independently.

The CLI's scope labels come from configuration, not request JSON. They are still
deployment labels, not authentication. A production host must derive current
principal and authorization state from its authenticated context.

## Threats and Controls

| Threat                              | Current control                                                                                                        | Residual risk                                                                          |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| Source/route substitution           | trusted operation-to-exact-route-input binding; mismatch bypasses measurement                                          | a malicious registry/binding author can configure a false relationship                 |
| False semantic merge                | exact aliases, SemWitness witness, strict bypass, no active serving                                                    | natural-language coverage is deliberately narrow                                       |
| Negation/effect confusion           | unlisted negation abstains; non-read effects bypass                                                                    | implicit effects remain an upstream modeling problem                                   |
| Cross-scope disclosure              | scope-derived HMAC keys; no scope in request JSON; no content-serving API                                              | equality is visible within one key/scope epoch; host authentication is external        |
| Prompt/output disclosure            | source/output use keyed HMACs; raw semantic SHA digests stay inside adapter; result and evidence use different streams | ordinary output remains visible to its intended stdout consumer                        |
| Dictionary attack                   | domain-separated HMACs with deployment secret                                                                          | weak/exposed keys defeat the control                                                   |
| Malformed adapter data              | strict runtime schemas and exact object reconstruction                                                                 | trusted code can still be replaced by a hostile implementation                         |
| Store forgery/poisoning             | positive probes explicitly labeled unverified; no candidate content/admission API                                      | false nomination metrics remain possible until records are authenticated               |
| Evidence tampering/splicing         | atomic `{eventId,keyId,evidence,mac}` envelope binds policy/scope/route/input/outcome                                  | sink must persist event IDs to detect replay                                           |
| Optional-path denial of service     | concurrent execution, bounded waits, cooperative abort signals                                                         | public result is bounded-blocking; hostile adapters can ignore abort                   |
| Late/duplicate side effects         | abort-aware ports and event ID idempotency contract; timeout called `unacknowledged`                                   | only process/worker isolation can force-stop arbitrary third-party code                |
| Shell/command injection             | fixed `route decide`, strict schema, `execFile`, `shell:false`, canonical paths                                        | trusted child still interprets its own canonical intent                                |
| Child error leakage                 | no raw prompt argument; constant structured error mapping                                                              | canonical intent remains visible in local process listings                             |
| Secret propagation                  | secret env names cannot collide with child allowlist; selected name is explicitly removed                              | allowed executables can inspect project files and their own arguments                  |
| Mutable/symlink path substitution   | realpath/stat checks and options snapshot; entrypoint file hash in route revision                                      | transitive imports and post-check filesystem replacement need OS hardening             |
| Dependency drift                    | SemWitness pinned to immutable commit and lock integrity                                                               | Git dependency prevents normal package distribution and depends on GitHub availability |
| Codex candidate substitution        | host calls exact transport once with captured original; candidate is HMAC-only and absent from result/transport types  | hostile replacement of the host or transport remains inside the trusted application    |
| Preparer common-mode error          | SemWitness owns preparation/evaluation; IntentABI adds no second evaluator; Codex path stays original-only             | generator and proof components still need independent held-out task evaluation         |
| SDK option/output observation       | host never reflects on either object; exact options and output identities pass through with explicit unbound sentinels | a trusted SDK adapter may separately map provider receipts                             |
| Sink mutation/replay                | strict verifier checks shape/key/binding/MAC; uncertain acknowledgement returns the same event for idempotent retry    | production guard needs persistent unique insert/SETNX and key rotation                 |
| Uncancellable preparation           | bounded success-path wait is labeled; transport errors abort observation and rethrow immediately                       | third-party preparer work may continue until process/worker isolation terminates it    |
| Benchmark provider-key disclosure   | real key remains in parent gateway; Codex child receives a random per-arm proxy credential                             | a hostile parent process or same-user debugger remains inside the trusted host         |
| Benchmark transport bypass          | custom no-WebSocket/no-retry provider; fail-closed static URL; public canary; exact one-request loopback gateway       | system/MDM hooks and legacy notifications still require a dedicated clean host         |
| Benchmark content persistence       | fresh private runtime, normal cleanup, dead-lease startup scavenger, content-free receipts                             | abrupt termination leaves raw sessions until the next cleanup or manual removal        |
| Benchmark receipt mutation          | domain-separated HMAC over the complete canonical receipt body with explicit key lineage                               | local verifier still depends on secure key custody and trusted host code               |
| Qualification selective dropping    | contiguous ordinals and one sealed record for every attempted case                                                     | a malicious case source can bias the population before admission                       |
| Qualification order bias            | AB/BA balance per declared stratum and fresh execution scope per arm                                                   | provider-side caches outside the host may remain shared                                |
| Qualification oracle laundering     | versioned deterministic oracle; incomplete or failed oracle is a negative record                                       | a wrong trusted oracle can still certify the wrong task property                       |
| Qualification payload leakage       | opaque core values, content-free result schemas, privacy canaries, bounded constant errors                             | trusted case, execution, oracle, and evidence adapters necessarily see private content |
| Cache-impact authority substitution | keyed binding covers exact registry bytes, pinned adapter, policy, scope epoch, and route map                          | the trusted host still controls key custody and supplied configuration                 |
| Cache-impact metric fabrication     | report labels workload and usage as unattested and freshness as unmodeled; activation stays forbidden                  | a trusted host can still submit false counters or value digests                        |
| Detached qualification authority    | exact JSONL is reparsed and independently re-evaluated; identity, ordered records, and plan cells must match           | a compromised pinned SemWitness evaluator remains inside the trusted computing base    |
| Qualification artifact race         | trusted owner-only parent, hidden `0600` sibling, inode/link checks, fsync, atomic no-clobber publication              | a malicious same-UID process remains inside the local filesystem trust boundary        |

## Key Handling

The HMAC secret comes from a configured environment variable, is copied into
private key material, never written to repository configuration, and is excluded
from child environments. Deployments must generate random keys, separate
security domains, rotate by policy, and restrict telemetry access. Rotation and
scope-epoch changes intentionally break longitudinal equality linkage.

No raw prompt, output, semantic SHA digest, or scope label is used as a fallback
identifier. Failures before trusted bindings exist use constant
`unavailable:*` sentinels; HMAC failure suppresses the evidence envelope.

The Codex host also forbids raw candidate/proof material in evidence. Candidate
and original text plus safe SemWitness metadata become scope-bound HMACs; proof
content becomes presence only. Thread configuration is covered by a keyed
binding. Opaque turn options and output are not inspected and use explicit
unbound sentinels. The SDK exposes provider-reported usage and basic lifecycle
events, but this slice maps rather than persists them; App Server remains useful
for richer approvals, tools, history, and control-plane events.

## Explicit Non-production Components

The fixture route and memory nomination store are test/development adapters.
The memory store is not multi-tenant safe, durable, authenticated,
freshness-aware, or revocation-aware. The Agentic SDLC child is not sandboxed.
The private workspace packages are source-only until SemWitness has a registry
artifact and clean-consumer packaging gates pass.
