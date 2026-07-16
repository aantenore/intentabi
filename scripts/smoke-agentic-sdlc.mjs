import {
  AgenticSdlcCliRoute,
  agenticSdlcRouteIntentSchema,
} from "../packages/adapter-agentic-sdlc/dist/index.js";

const entrypointPath = required("AGENTIC_SDLC_ENTRYPOINT");
const allowedRoot = required("AGENTIC_SDLC_ROOT");
const deploymentRevisionDigest = required(
  "AGENTIC_SDLC_DEPLOYMENT_REVISION_DIGEST",
);
if (!/^sha256:[a-f0-9]{64}$/u.test(deploymentRevisionDigest)) {
  throw new Error(
    "AGENTIC_SDLC_DEPLOYMENT_REVISION_DIGEST must be a SHA-256 digest",
  );
}

const intent = agenticSdlcRouteIntentSchema.parse({
  requested_action: "technical_analysis",
  confidence: 1,
  referenced_entities: [],
  provided_artifacts: [],
  missing_context: [],
  proposed_phase: "analysis",
  artifact_type: "technical-analysis",
  skip_phases: [],
});
const route = new AgenticSdlcCliRoute({
  entrypointPath,
  allowedRoot,
  deploymentRevisionDigest,
  timeoutMs: 10_000,
  maxOutputBytes: 1024 * 1024,
  environment: {
    PATH: process.env.PATH,
    SystemRoot: process.env.SystemRoot,
    WINDIR: process.env.WINDIR,
    TEMP: process.env.TEMP,
    TMP: process.env.TMP,
    TMPDIR: process.env.TMPDIR,
  },
});
const output = await route.execute({ root: allowedRoot, intent });
const decision = JSON.parse(output.stdout);

process.stdout.write(
  `${JSON.stringify(
    {
      schema:
        "io.github.aantenore.intentabi/agentic-sdlc-smoke-report/v1alpha1",
      exitCode: output.exitCode,
      route: decision.route,
      status: decision.status,
      requestedAction: decision.intent?.requested_action,
      revisionDigest: route.revisionDigest,
      stderrEmpty: output.stderr.length === 0,
    },
    null,
    2,
  )}\n`,
);

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}
