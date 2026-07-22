# Guarded Observation Reuse

## What It Tests

An agent can ask for the same read-only information in different words. Reusing
the first tool observation could avoid another call, but equal meaning is not
enough: the current tenant, principal, authorization, context, policy, tool,
execution lineage, data revision, and freshness must still agree.

This study measures that boundary without serving cached content. It answers:

> Would a differently worded read have produced a useful candidate, and would
> SemWitness admit that exact candidate under the current host bindings?

It does not answer whether a production cache should be enabled. The report is
always shadow-only and explicitly states:

- `tier: "observation"`;
- `servingAuthority: "none"`;
- `activationAuthorized: false`;
- `applied: false`;
- `promotionManifest: "not-produced"`;
- `statisticalQualification: false`;
- `economicQualification: false`.

## Why Observation Reuse Is Narrow

Only `read` observations are eligible. A search result can be reconsidered
when its complete lineage and freshness still hold; a reservation, purchase,
message send, or other write cannot be proven to have occurred by replaying an
old observation. The study rejects non-read effects before lookup or insertion.

This profile does not generalize to plans, final responses, provider prefix
caches, or KV caches. Those tiers have different dependencies and need their
own evidence.

## Three Independent Strategies

The ordered workload is replayed through three separate in-memory maps. There
is no fallback from one strategy to another, so every metric has one meaning.

| Strategy                | Key and admission rule                                                                                    | Purpose                                                                       |
| ----------------------- | --------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| Exact request           | Host-supplied HMAC key for the exact request; no SemWitness admission                                     | Measures reuse already available without semantic convergence                 |
| Unguarded oracle intent | Host-supplied HMAC key for the external oracle's canonical intent family; no host-bound admission         | Exposes the lift and collisions of intent-only grouping                       |
| SemWitness-guarded      | `hmacCacheKey` over the complete observation binding, followed by `admitCacheHit` on every candidate read | Tests whether useful convergence survives current security and lineage checks |

The second baseline is deliberately named **unguarded oracle intent**. It is
not IntentABI's existing `intentKey`, which already carries stronger policy,
scope, route, and deployment bindings. It is an intentionally weak comparator
used to reveal what an intent-only cache without current host boundaries would
get wrong.

SemWitness is the sole semantic and admission authority. IntentABI does not
reimplement its `CacheBinding`, cache-key derivation, freshness rules, or
admission verdict. A matching HMAC cache key is not authorization: the study
still calls SemWitness after reading a candidate. IntentABI contributes only
the ordered study, host value oracle, unsafe/hostile-candidate quarantine,
freshness eviction, metrics, and content-free report.

## Bindings and Admission

Each guarded candidate is bound to:

- normalized Intent IR and normalization policy;
- cache namespace, tenant, and principal;
- current authorization and context digests;
- host policy and `read` effect;
- observation-tier plan, execution, and tool dependency digests;
- either TTL freshness or an exact canonical revision set.

The host supplies the current `IntentIR`, `NormalizationWitness`, bindings,
freshness check, and expected value digest; the study pins one expected
normalizer, policy digest, and minimum confidence contract. SemWitness checks
the witness, binding, normalization contract, and freshness facts against the
stored entry. After an eligible admission, IntentABI separately compares the
host reuse oracle and value digest.
A changed binding normally selects another guarded key and therefore produces a
miss. A same-key candidate that fails post-read admission produces
`admission-bypass`; the reason and candidate origin determine store mutation.

Store mutation is fail closed but reason-specific:

```text
empty -- admitted observation --> stable(value digest)
stable -- unsafe host-oracle value or hostile override --> quarantined
stable -- stale or revision/freshness-mode mismatch --> empty
stable -- other admission bypass --> stable (candidate is not used)
```

Once an unsafe or hostile candidate quarantines a key, a later A-B-A sequence
cannot silently make that key safe again. Freshness failures evict instead so a
future current observation can repopulate the key. Other admission bypasses
remain fail closed without destroying a stable entry. `guardedCandidateOverride`
exists only for hostile-store conformance cases; it is not a production store
port.

## Outcomes and Gate

Each case records the exact, unguarded-intent, and guarded outcome:

- `miss`: no candidate existed under that strategy's key;
- `safe-hit`: the host oracle and value digest allow reuse;
- `unsafe-hit`: a candidate existed but failed the host value oracle;
- `admission-bypass`: SemWitness rejected the guarded candidate;
- `quarantined`: an earlier unsafe or hostile candidate permanently closed the
  key;
- `ineligible`: the effect is not `read`.

An expected negative case is useful conformance evidence, not a failed study.
For example, a stale entry should produce the declared admission bypass. The
gate fails only when:

- a guarded unsafe hit occurs;
- a guarded outcome or exact reason set differs from the case's declared
  expectation;
- guarded safe hits do not improve on exact-request safe hits; or
- a required scenario is absent.

The report also counts candidate hits, safe and unsafe hits, admission
bypasses, quarantined keys, misses, ineligible cases, and safe-hit rate. The
reported lift is a count of guarded safe hits minus exact-request safe hits; it
is not a latency, cost, or token-saving claim.

## External SGD Conformance Slice

The companion app consumes two caller-supplied files from the official
[Schema-Guided Dialogue dataset](https://github.com/google-research-datasets/dstc8-schema-guided-dialogue/tree/e852981ae34990f4358979625854259302feaa78):

- `test/schema.json`, which describes services, intents, slots, and the
  `is_transactional` effect annotation;
- `test/dialogues_001.json`, which supplies user turns and annotated frames.

The configuration pins upstream commit
`e852981ae34990f4358979625854259302feaa78` and the exact source SHA-256 values:

```text
test/schema.json
sha256:0b4af32e01695aec4788681fe6b22fb7ee908907269f5ac7167d01f4c4132bcb

test/dialogues_001.json
sha256:1fa13b0fe607100bc66ed15e0490df9c52a2cec087ca9733e0f506755eef0ada
```

The pinned selector and resulting public reproducibility commitments are:

```text
selector manifest
sha256:bbca78806558e2c396c3faf304db445cfc12bc102272be56b663cc9a2816611f

selected order
sha256:85e1e3f5541ec2219bab8fc5fcedc6a92fb3e2205b83623d246c62b78f9e0e06

source manifest
sha256:38a05ee4be88b685da28be7dd92cdd72ef75247fee9044d4bf4d667a99d2775e
```

These public SHA-256 values make the source and deterministic selection
reproducible. They do not authenticate a producer or protect low-entropy private
data; private study identities use the configured HMAC domain instead.

The files are read locally; the app does not download them. Raw SGD data is not
vendored into this Apache-2.0 repository. SGD is licensed under
[CC BY-SA 4.0](https://github.com/google-research-datasets/dstc8-schema-guided-dialogue/blob/e852981ae34990f4358979625854259302feaa78/LICENSE),
so callers remain responsible for attribution and source handling.

The deterministic selector produces 56 conformance cases from seven pinned slot
strata spanning three service/intent pairs: 48 read cases and 8 transactional
cases. It uses the dataset's service, intent, slot, and transactional annotations
as an **external-label oracle**. That isolates cache-admission mechanics; it does
not test whether a learned normalizer can infer those labels from unseen text.

The host-bound mutations cover equivalent paraphrases; tenant, principal,
authorization, context, and policy drift; plan, execution, and tool drift; TTL
fresh/stale boundaries; equivalent and changed revision sets; transactional
effects; return after a conflict; and hostile-store substitution.

Stage the exact upstream files outside the repository:

```bash
curl --fail --location \
  --output /tmp/sgd-schema.json \
  https://raw.githubusercontent.com/google-research-datasets/dstc8-schema-guided-dialogue/e852981ae34990f4358979625854259302feaa78/test/schema.json

curl --fail --location \
  --output /tmp/sgd-dialogues-001.json \
  https://raw.githubusercontent.com/google-research-datasets/dstc8-schema-guided-dialogue/e852981ae34990f4358979625854259302feaa78/test/dialogues_001.json
```

The app itself is offline and accepts only those local inputs:

```bash
INTENTABI_GUARDED_REUSE_HMAC_SECRET="$(openssl rand -hex 32)" \
  pnpm reuse:guarded \
  --config config/sgd-guarded-reuse.json \
  --schema /tmp/sgd-schema.json \
  --dialogues /tmp/sgd-dialogues-001.json
```

`INTENTABI_GUARDED_REUSE_HMAC_SECRET` is the environment name pinned by the
example configuration. Supply at least 32 random bytes through the process
environment, never a committed file or command-line value. Input digests are
verified before case materialization.

Stdout receives one `intentabi.guarded-reuse.report` JSON event with the public
`selectionOrderDigest` and the redacted authenticated report. Exit `0` means the
declared conformance gate passed; exit `2` means a complete report failed it;
exit `1` means input validation or execution failed. Stderr error events are
bounded and content-free.

The pinned reference run passes its declared conformance gate:

| Strategy                | Candidate hits | Safe | Unsafe | Admission bypass | Quarantined outcomes | Misses | Ineligible |
| ----------------------- | -------------: | ---: | -----: | ---------------: | -------------------: | -----: | ---------: |
| Exact request           |              2 |    1 |      1 |                0 |                    3 |     51 |          0 |
| Unguarded oracle intent |             17 |   12 |      5 |                0 |                   32 |      7 |          0 |
| SemWitness-guarded      |             34 |   31 |      0 |                3 |                    0 |     14 |          8 |

Guarded safe-hit lift over exact request is 30 cases. The hostile-store case
also leaves one guarded key quarantined, although no later case observes a
`quarantined` outcome. These counts confirm the deterministic contract above;
they are not production hit-rate, false-hit-rate, latency, or cost estimates.

## Privacy and Authentication

The public event contains a SHA-256 commitment to the deterministic selected
order. Its report contains case references, scenarios, outcomes, bounded reason
codes, aggregate metrics, pinned-source identity, and an HMAC over the report.
It excludes request text, slot values, raw identifiers, candidate values,
secrets, and private binding material.

HMAC provides symmetric integrity and authentication for parties that already
share the secret. It is **not a digital signature**: every verifier holding the
key can also forge another report. The report therefore does not prove an
independent producer identity or create transferable approval.

## Trust Boundary and Limitations

The SGD labels are public source annotations. Tenant, principal,
authorization, context, policies, dependency versions, value oracle, and clock
are deterministic synthetic host inputs. They are useful for conformance but
are neither deployment-attested nor current authorization evidence.

The 56-case run is a bounded conformance suite, not statistical qualification.
It cannot establish a production false-hit bound, distribution coverage,
normalizer quality, cost savings, latency improvement, or operational
freshness. It also has no durable or distributed store, invalidation channel,
trusted clock, current authorizer, revocation mechanism, replay protection,
serving adapter, or activation path.

Promotion would require independent deployment traffic, enough safe and unsafe
trials for a predeclared error bound, current host attestation, operational
freshness and invalidation, value/cost evidence, and a separate authenticated
approval protocol. A passing report remains evidence for that future decision,
never the decision itself.
