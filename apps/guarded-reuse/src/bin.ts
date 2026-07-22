#!/usr/bin/env node

import { runGuardedReuseCli } from "./cli.js";

process.exitCode = await runGuardedReuseCli(
  process.argv.slice(2),
  process.env,
  {
    stdout: (value) => process.stdout.write(value),
    stderr: (value) => process.stderr.write(value),
  },
);
