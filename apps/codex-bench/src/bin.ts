#!/usr/bin/env node

import { runCodexBenchCli } from "./cli.js";

const exitCode = await runCodexBenchCli(process.argv.slice(2), process.env, {
  stdout: (value) => process.stdout.write(value),
  stderr: (value) => process.stderr.write(value),
});
process.exitCode = exitCode;
