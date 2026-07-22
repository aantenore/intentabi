# Landscape and Build-vs-Buy

IntentABI is intentionally a thin host runtime around existing components. The
market already has strong tools for adjacent problems; reproducing them would
reduce safety and slow validation.

## Reuse

- [SemWitness](https://github.com/aantenore/semwitness) supplies typed Intent
  IR, source/scope bindings, proof-carrying normalization, evaluation, and
  promotion qualification. IntentABI does not fork those contracts.
- [LLMLingua](https://github.com/microsoft/LLMLingua) is prior art for prompt
  compression. It is not an authorization mechanism for semantic reuse.
- [GPTCache](https://github.com/zilliztech/GPTCache) and
  [RedisVL](https://redis.io/docs/latest/develop/ai/redisvl/api/cache/) provide
  cache and vector infrastructure that could become replaceable adapters after
  safety gates pass. RedisVL already owns threshold, TTL, vectorizer, metadata,
  and filter mechanics; IntentABI should not reproduce them.
- [vCache](https://github.com/vcache-project/vCache) evaluates verified semantic
  caching and is useful benchmark prior art. IntentABI does not reproduce its
  cache implementation; the guarded study isolates host-bound observation
  admission and keeps serving disabled.
- [Semantic Router](https://github.com/aurelio-labs/semantic-router) provides
  pluggable encoder and thresholded routing patterns. SemWitness remains the
  configured typed-normalization authority here rather than introducing a
  second router.
- Apple's [Krites](https://machinelearning.apple.com/research/semantic-caching)
  explores asynchronous semantic-cache verification. It reinforces the value
  of separating candidate retrieval from verification, but does not replace
  this project's tenant-, principal-, authorization-, dependency-, effect-, and
  freshness-bound SemWitness admission contract.
- [LMCache](https://docs.lmcache.ai/) and engine-level prefix/KV caching target
  inference reuse below this application boundary. IntentABI should export
  evidence to those layers, not imitate them.

## Differentiated Wedge

The useful missing layer is a deployable **qualification data plane** between a
user request and an ordinary agentic application route:

- observe whether differently phrased requests converge on a typed contract;
- bind evidence to scope and semantic witnesses;
- measure misses, false merges, failures, and value before serving anything;
- preserve the ordinary route as the only authority during qualification.

This is narrower than a semantic cache and more operational than an evaluation
library. It gives SemWitness a real host without splitting or duplicating its
bounded context.

The Cache Impact Lab now validates this wedge with a direct raw-versus-intent
key replay. It borrows the useful query/hit/token separation visible in
[vLLM cache metrics](https://github.com/vllm-project/vllm/blob/main/vllm/v1/metrics/loggers.py),
but adds oracle-safe hits and normalization overhead instead of pretending that
all candidate hits save tokens.

The Guarded Observation Reuse study adds the next narrow layer: exact request,
unguarded oracle intent, and SemWitness-guarded observation reuse are measured
as independent strategies. It exercises identity, authorization, dependency,
effect, value, and freshness drift without adding a database, vector index,
router, or serving path. SemWitness remains the only admission authority.

## Deliberately Deferred

- embedding candidate generation and vector databases;
- network LLM providers;
- generalized prompt compression;
- active response/plan/observation reuse;
- Codex hook-based prompt replacement (the supported hook surface can observe
  or add context but is not treated here as an ingress-rewrite boundary);
- production Redis or distributed stores.

The 56-case SGD slice is conformance for admission mechanics, not statistical
qualification or a test of learned normalization. The next investment should
pair a real normalizer with independently held-out deployment-like reads, enough
unsafe trials for a predeclared false-hit bound, and provider-observed value,
then pass the existing Qualification Lab. It should not add more cache
infrastructure. If those benchmarks do not show safe paraphrase recall and
measurable application value, IntentABI should remain a research host or be
removed rather than promoted into a cache product.
