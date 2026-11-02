import { createHandler } from "./approval_core.mjs";
import { createAwsAdapters } from "./aws_adapters.mjs";

export const handler = createHandler({
  ...createAwsAdapters(),
  log: (entry) => {
    const line = JSON.stringify(entry);
    if (entry.outcome === "failed") console.error(line);
    else console.info(line);
  },
});
