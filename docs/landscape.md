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
- [Semantic Router](https://github.com/aurelio-labs/semantic-router) provides
  pluggable encoder and thresholded routing patterns. SemWitness remains the
  configured typed-normalization authority here rather than introducing a
  second router.
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

## Deliberately Deferred

- embedding candidate generation and vector databases;
- network LLM providers;
- generalized prompt compression;
- active response/plan/observation reuse;
- Codex hook-based prompt replacement (the supported hook surface can observe
  or add context but is not treated here as an ingress-rewrite boundary);
- production Redis or distributed stores.

The next investment should use the Cache Impact Lab with an external held-out
workload and provider-observed counters, then pass the existing Qualification
Lab. It should not add more cache infrastructure. If those benchmarks do not
show safe paraphrase recall and measurable application value, IntentABI should
remain a research host or be removed rather than promoted into a cache product.
