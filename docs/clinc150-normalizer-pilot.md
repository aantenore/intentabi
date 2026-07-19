# CLINC150 external normalizer pilot

## What this changes in the real world

Before comparing semantic-cache hit rates, a team can now ask a simpler safety
question on language it did not write itself: does the selected normalizer map
ways of asking for the same read operation that were held out from its registry
aliases to one typed intent, keep different operations separate, and refuse
requests outside its catalogue?

This pilot prepares a frozen external **conformance** corpus. It does not serve
cached content, prove production traffic coverage, or authorize activation.

## Reproducible source

The checked-in configuration pins the official CLINC150 `data_full.json` at:

- repository: <https://github.com/clinc/oos-eval>
- revision: `828f8093932c8fe6ca7936c3d2e52903b1c523de`
- file: <https://raw.githubusercontent.com/clinc/oos-eval/828f8093932c8fe6ca7936c3d2e52903b1c523de/data/data_full.json>
- SHA-256: `36923c3705a59e08fe9c3883d8bc2dd966ef93e22cb78ac41171782a698d56e0`

`prepareClinc150Pilot` is a pure prepare-stage function. It performs no network
or model call. The caller supplies the source bytes, and preparation stops if
their SHA-256, UTF-8 encoding, closed six-split shape, labels, or budgets differ
from the declared pin.

## Split boundary and leakage control

The deterministic public seed selects:

- registry aliases from `train` and `val` only;
- positive held-out cases from `test` only;
- expected bypasses from `oos_test` only.

The selected test and OOS text is normalized with the same small lexical rule
used by SemWitness exact aliases (NFKC, lowercase, ASCII-whitespace collapse)
and is forbidden from the registry. Alias collisions are also removed before
SemWitness strictly reparses the generated registry. No phrase is translated,
rewritten, expanded by a model, or copied from evaluation into few-shot data.

The example slice contains 12 manually reviewed English information/read labels,
eight held-out phrasings per label, and 32 OOS cases: 128 cases total. CLINC's
label is represented as a benchmark `identify` operation with `effect: read`;
this describes classification behavior, not permission to execute or cache the
request that the utterance mentions.

Configuration can select a subset of those reviewed labels, but cannot assign a
read effect to arbitrary CLINC labels. Extending the allowlist requires a code
and contract review rather than an unchecked configuration edit.

Each positive family gets explicit equivalent comparisons. Adjacent label
families get balanced explicit distinct comparisons. OOS cases are expected
bypasses and therefore do not enter pair statistics. All output records use the
SemWitness `held-out` split and remain subject to its content-free report,
unsafe-accept, false-merge, convergence, and repeatability gates.

## Validate and run

`validate` checks the pinned source, materializes and reparses both contracts,
constructs the compiler configuration, and proves the request budget without
calling the compiler:

```bash
pnpm pilot validate \
  --config config/clinc150-normalizer-pilot.json \
  --source /absolute/path/data_full.json
```

Before execution, bind `deploymentRevisionDigest` to the exact compiler
deployment and configure any OpenAI-compatible endpoint/model. The destination
must not exist and its parent must be an owner-only directory:

```bash
pnpm pilot run \
  --config config/clinc150-normalizer-pilot.json \
  --source /absolute/path/data_full.json \
  --out /absolute/private/path/normalizer-report.json \
  --execute \
  --allow-network
```

The output is atomically published with no-clobber owner-only permissions. It
contains SemWitness metrics and opaque digests, not the selected utterances.
Exit `0` means the conformance gate passed, `2` means a valid evaluation failed
the gate (including compiler/provider failures captured per case), and `1`
means input, configuration, orchestration, or publication failure.

The compiler is invoked once per attempt. Its proposal cannot supply Intent IR
or change an effect: the declarative registry resolves both. Unknown,
conflicting, malformed, failed, and non-read proposals bypass.

The report's `pilotRunBindingDigest` covers source, registry, corpus, compiler
manifest, host-declared deployment revision, credential identity, evaluator
revision, attempts, and request count. The example deployment digest is a
placeholder: validation reports `executionReady: false`, and execution rejects
it before reserving output or calling the model.

This alpha run is one-shot. The full configuration makes 256 compiler requests;
there is no progress artifact or resume yet, and an interrupted evaluation must
restart. Resumable append-only observations are a release/pin gate, not a
capability claimed by this increment.

## Observed local diagnostic

On 2026-07-19, a reduced transport smoke used the pinned public source, four
reviewed labels, nine cases, two attempts per case, and local `qwen3:4b`. The
content-free result was a valid failed gate:

- exact intent accuracy: `0/8`;
- correct OOS bypasses: `1/1`;
- unsafe accepts and false merges: `0`;
- execution failures: `9`;
- statistical, economic, promotion, and activation authority: `false`.

The model did not satisfy the strict structured compiler contract. This is not
a quality ranking or a release artifact; it demonstrates why endpoint
compatibility must be measured rather than inferred from an API label. The
held-out cases were not changed after observing the failure.

## Limits of the evidence

CLINC150 is English, single-turn, public, and intent-level. It has no trusted
tenant, principal, authorization, freshness, dependency, canonical-argument,
or answer-quality labels. A foundation model may also have encountered the
public dataset during pretraining. The risk-focused sample is curated and not
an IID deployment sample, so SemWitness must continue to report
`IID_SAMPLING_NOT_ATTESTED`, a null automatic false-merge confidence bound, and
`activeCacheQualified: false`.

SemWitness currently has no dedicated `out-of-scope` phenomenon enum, so the
generated OOS cases use the corpus-level `paraphrase` tag. Treat exact-intent
and expected/correct-bypass counters as the authoritative in-scope/OOS slices;
do not interpret that per-phenomenon row as pure paraphrase recall.

Provider execution is a later, explicit process stage. Before a real run,
replace the example `deploymentRevisionDigest` with a digest for the exact
local or remote deployment. A green run remains external conformance evidence;
it is not a cache-admission credential.

## License and attribution

CLINC150 is distributed by its authors under the Creative Commons Attribution
3.0 Unported license: <https://github.com/clinc/oos-eval/blob/828f8093932c8fe6ca7936c3d2e52903b1c523de/LICENSE>.
If a generated subset is redistributed, keep the source URL, revision, license,
and a notice that IntentABI selected a deterministic subset and added registry,
typed-intent, bypass, and comparison annotations. Do not imply endorsement.

Please also cite the source publication:

> Stefan Larson et al. “An Evaluation Dataset for Intent Classification and
> Out-of-Scope Prediction.” EMNLP-IJCNLP 2019.
> <https://aclanthology.org/D19-1131/>

The IntentABI implementation remains Apache-2.0. That license does not replace
the CC BY 3.0 terms on redistributed CLINC-derived data.
