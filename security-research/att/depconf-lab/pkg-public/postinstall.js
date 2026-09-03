// Benign marker only. Collects nothing, sends nothing.
const os = require("os");
const fs = require("fs");
const path = require("path");

const evidence = {
  note: "postinstall executed from the PUBLIC-registry package",
  package: "@acme-corp/ui-widget@9.9.9",
  hostname: os.hostname(),
  username: os.userInfo().username,
  cwd: process.cwd(),
  timestamp: new Date().toISOString()
};

console.log("\n=== postinstall executed ===");
for (const [k, v] of Object.entries(evidence)) console.log(`  ${k}: ${v}`);
console.log("============================\n");

try {
  fs.writeFileSync(path.join(os.tmpdir(), "depconf-poc-marker.json"),
                   JSON.stringify(evidence, null, 2));
} catch (e) {}
