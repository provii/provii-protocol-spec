/** @type {import('@stryker-mutator/api/core').PartialStrykerOptions} */
const config = {
  testRunner: "vitest",
  mutate: ["src/**/*.ts", "!src/**/*.test.ts"],
  reporters: ["progress-append-only", "clear-text", "json", "html"],
  jsonReporter: { fileName: "reports/mutation/mutation.json" },
  htmlReporter: { fileName: "reports/mutation.html" },
  thresholds: { high: 80, low: 50, break: 50 },
  concurrency: 4,
  timeoutMS: 30000,
  incremental: true,
  incrementalFile: "reports/stryker-incremental.json",
};

export default config;
