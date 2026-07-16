const args = process.argv.slice(2);
const intentIndex = args.indexOf("--intent-json");
const intent = JSON.parse(args[intentIndex + 1] ?? "null");

if (intent?.requested_action === "fixture_fail") {
  process.stderr.write(`child failed with ${JSON.stringify(args)}\n`);
  process.exitCode = 2;
} else if (intent?.requested_action === "fixture_timeout") {
  await new Promise((resolve) => setTimeout(resolve, 5_000));
} else if (intent?.requested_action === "fixture_overflow") {
  process.stdout.write("x".repeat(16_384));
} else {
  process.stdout.write(
    `${JSON.stringify({
      args,
      hmacSecret: process.env.INTENTABI_HMAC_SECRET ?? null,
    })}\n`,
  );
}
