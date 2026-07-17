import {
  digestIntentCachePromotionAdversarialCorpus,
  digestIntentCachePromotionPopulationCorpus,
  parseIntentCachePromotionEvidenceFixture,
  recomputeIntentCachePromotionEvidenceBindingDigest,
  type IntentCachePromotionEvidenceAssemblyInput,
  type IntentCachePromotionEvidenceAttestation,
  type IntentCachePromotionEvidenceFixture,
} from "semwitness/intent/host";

const digest = (character: string) => `sha256:${character.repeat(64)}` as const;

const dependency = (id: string, character: string) => ({
  status: "enabled" as const,
  artifact: { id, version: "1", digest: digest(character) },
});

export function createEmptyPromotionFixture(): IntentCachePromotionEvidenceFixture {
  const binding: Record<string, unknown> = {
    schema: "semwitness.dev/intent-cache-promotion-evidence/v1alpha1",
    kind: "binding",
    artifact: {
      id: "semwitness-intent-cache-promotion-evidence",
      version: "1",
    },
    provenance: "host-attested-unsigned",
    evidenceAuthentication: "none",
    activationCeiling: "shadow-only",
    mode: "shadow",
    tier: "plan",
    qualifiedOperation: {
      operation: `hmac-sha256:operation:${"1".repeat(64)}`,
      domain: `hmac-sha256:intent-domain:${"2".repeat(64)}`,
      effect: "read",
    },
    scope: {
      cacheNamespace: `hmac-sha256:cache-namespace:${"3".repeat(64)}`,
      tenant: `hmac-sha256:tenant:${"4".repeat(64)}`,
      deploymentScopeDigest: digest("5"),
    },
    validity: {
      notBeforeEpochMs: 1,
      notAfterEpochMs: 2,
      revocationId: `hmac-sha256:revocation:${"6".repeat(64)}`,
    },
    intentContract: {
      intentIrSchema: "semwitness.dev/intent-ir/v1alpha1",
      ontology: { id: "ontology", version: "1", digest: digest("7") },
      normalizer: {
        id: "normalizer",
        version: "1",
        artifactDigest: digest("8"),
        configDigest: digest("9"),
      },
      operationRegistry: {
        id: "operation-registry",
        version: "1",
        digest: digest("a"),
      },
      resolver: { id: "resolver", version: "1", digest: digest("b") },
      normalizationPolicyDigest: digest("c"),
      cacheAdmissionPolicyDigest: digest("d"),
      sourceHmacKeyVersionDigest: digest("e"),
    },
    dependencies: {
      prompt: dependency("prompt", "1"),
      tool: dependency("tool", "2"),
      planner: dependency("planner", "3"),
      provider: dependency("provider", "4"),
      model: dependency("model", "5"),
      output: dependency("output", "6"),
      safety: dependency("safety", "7"),
      personalization: dependency("personalization", "8"),
      determinism: dependency("determinism", "9"),
      tokenizer: dependency("tokenizer", "a"),
      embedding: dependency("embedding", "b"),
      candidateIndex: dependency("candidate-index", "c"),
      store: dependency("store", "d"),
      recordAuthentication: dependency("record-authentication", "e"),
      freshness: dependency("freshness", "f"),
      invalidation: dependency("invalidation", "0"),
      key: dependency("key", "1"),
    },
    population: {
      populationFrameDigest: digest("2"),
      corpusDigest: digestIntentCachePromotionPopulationCorpus([]),
      sourceLogRootDigest: digest("3"),
      samplingProtocolDigest: digest("4"),
      inclusionPolicyDigest: digest("5"),
      samplingWindowDigest: digest("6"),
      independenceUnit: "cluster",
      attempted: 0,
      emitted: 0,
      dropped: 0,
      complete: 0,
      failed: 0,
    },
    adversarial: {
      corpusDigest: digestIntentCachePromotionAdversarialCorpus([]),
      coverageDigest: digest("7"),
      expected: 0,
      emitted: 0,
      complete: 0,
      failed: 0,
    },
    evaluation: {
      split: "held-out",
      evaluationProtocolDigest: digest("8"),
      evaluatorDigest: digest("9"),
      oracleDigest: digest("a"),
      accountingContractDigest: digest("b"),
      costModel: { id: "cost-model", version: "1", digest: digest("c") },
      currencyUnitDigest: digest("d"),
    },
    bindingDigest: digest("0"),
  };
  binding.bindingDigest =
    recomputeIntentCachePromotionEvidenceBindingDigest(binding);
  return parseIntentCachePromotionEvidenceFixture({ binding, cases: [] });
}

export function attestationFromFixture(
  fixture: IntentCachePromotionEvidenceFixture,
): IntentCachePromotionEvidenceAttestation {
  const binding = fixture.binding;
  return {
    qualifiedOperation: {
      operation: binding.qualifiedOperation.operation,
      domain: binding.qualifiedOperation.domain,
    },
    scope: binding.scope,
    validity: binding.validity,
    intentContract: {
      ontology: binding.intentContract.ontology,
      normalizer: binding.intentContract.normalizer,
      operationRegistry: binding.intentContract.operationRegistry,
      resolver: binding.intentContract.resolver,
      normalizationPolicyDigest:
        binding.intentContract.normalizationPolicyDigest,
      cacheAdmissionPolicyDigest:
        binding.intentContract.cacheAdmissionPolicyDigest,
      sourceHmacKeyVersionDigest:
        binding.intentContract.sourceHmacKeyVersionDigest,
    },
    dependencies: binding.dependencies,
    population: {
      populationFrameDigest: binding.population.populationFrameDigest,
      sourceLogRootDigest: binding.population.sourceLogRootDigest,
      samplingProtocolDigest: binding.population.samplingProtocolDigest,
      inclusionPolicyDigest: binding.population.inclusionPolicyDigest,
      samplingWindowDigest: binding.population.samplingWindowDigest,
      attempted: binding.population.attempted,
    },
    adversarial: {
      coverageDigest: binding.adversarial.coverageDigest,
      expected: binding.adversarial.expected,
    },
    evaluation: {
      evaluationProtocolDigest: binding.evaluation.evaluationProtocolDigest,
      evaluatorDigest: binding.evaluation.evaluatorDigest,
      oracleDigest: binding.evaluation.oracleDigest,
      accountingContractDigest: binding.evaluation.accountingContractDigest,
      costModel: binding.evaluation.costModel,
      currencyUnitDigest: binding.evaluation.currencyUnitDigest,
    },
  };
}

export function createEmptyPromotionAssemblyInput(): IntentCachePromotionEvidenceAssemblyInput {
  const fixture = createEmptyPromotionFixture();
  return {
    attestation: attestationFromFixture(fixture),
    cases: fixture.cases,
  };
}
