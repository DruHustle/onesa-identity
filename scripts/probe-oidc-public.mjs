import {verifyDiscovery} from "../src/oidc-public-discovery.js";
try {
  const result = await verifyDiscovery();
  console.log(JSON.stringify({checkedAt:new Date().toISOString(),...result,publicReadinessOnly:true}));
} catch (error) {
  const code = String(error?.message || "unknown");
  const safe = /^[a-z0-9_]+$/.test(code) ? code : "unknown";
  console.error(JSON.stringify({checkedAt:new Date().toISOString(),
    service:"auth0-custom-domain",status:"FAIL",reason:safe}));
  process.exitCode = 1;
}
