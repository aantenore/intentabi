# Security policy

Do not open public issues for suspected vulnerabilities, authorization bypasses,
or prompt, response, scope, or secret disclosure. Use GitHub's private
vulnerability reporting for this repository.

IntentABI is experimental, source-only software. It defaults to shadow mode and
must never use candidate cache data as application output. Treat normalizer,
route, store, configuration, and evidence-sink inputs as untrusted across every
adapter boundary.

Security fixes target the current `main` branch. Reports should include the
commit SHA, operating system, Node.js and pnpm versions, a minimal reproduction,
the expected invariant, and whether sensitive content may have crossed a trust
boundary. Do not include live secrets, private prompts, or production data.
