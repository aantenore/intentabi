#!/usr/bin/env node

import { runCli } from "./cli.js";

const exitCode = await runCli(process.argv.slice(2), process.env, {
  stdout: (value) => process.stdout.write(value),
  stderr: (value) => process.stderr.write(value),
});
process.exitCode = exitCode;
