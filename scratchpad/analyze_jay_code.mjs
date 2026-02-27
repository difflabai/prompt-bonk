import { readFileSync } from 'fs';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { scan } = require('/ml2/nanobot/projects/prompt-bonk/scanner.js');

const lines = readFileSync('/ml2/nanobot/projects/prompt-bonk/datasets/jayavibhav.jsonl', 'utf8').trim().split('\n');
const records = lines.map(l => JSON.parse(l));
const injections = records.filter(r => r.label === 1);
const benign = records.filter(r => r.label === 0);
const zeroFN = injections.filter(r => scan(r.text).score === 0);

// Focus: trigram approach for code-style injections
// Pattern: code syntax (for/fn/let) + (sensitive/secret/password/token) + (reveal/expose/access/print)
// But we need to be very precise to not hit benign code examples

// Test specific trigram for "secret" inside for loop with reveal
const codeRevealSecret = (text) => {
  const codeStart = /(?:fn\s+\w+\s*\(|for\s+\w+\s+in\s+|let\s+(?:mut\s+)?\w+\s*=\s*(?:fn|vec|loop)|let\s+\w+\s*=\s*(?:['"]|fn\s*\())/i;
  const hasSensitive = /(?:secret|password|token|credential|sensitive|private|hidden|confidential|key\b|exploit|vuln(?:erable|ability)|unauthorized|prohibited|illicit|clandestine)/i;
  const hasRevealAction = /(?:reveal|expose|uncover|disclose|leak|dump|print|output|show|return)\s*[('\(]/i;
  return codeStart.test(text) && hasSensitive.test(text) && hasRevealAction.test(text);
};

// Check across all
console.log(`codeRevealSecret: FN=${zeroFN.filter(r=>codeRevealSecret(r.text)).length}, benign=${benign.filter(r=>codeRevealSecret(r.text)).length}`);

// More targeted: "let secret_xxx = " or "let illicit_xxx"
const letSecretVar = /\blet\s+(?:mut\s+)?(?:secret|illicit|hidden|forbidden|restricted|sensitive|illegal|unauthorized|exploit)\w*\s*=/i;
console.log(`letSecretVar: FN=${zeroFN.filter(r=>letSecretVar.test(r.text)).length}, benign=${benign.filter(r=>letSecretVar.test(r.text)).length}`);

// All injections too  
console.log(`letSecretVar all injections: ${injections.filter(r=>letSecretVar.test(r.text)).length}`);
console.log(`letSecretVar all benign: ${benign.filter(r=>letSecretVar.test(r.text)).length}`);

// Show benign hits
if (benign.filter(r=>letSecretVar.test(r.text)).length > 0) {
  benign.filter(r=>letSecretVar.test(r.text)).slice(0,5).forEach((r,i) => {
    console.log(`\nBenign [${i+1}]: score=${scan(r.text).score.toFixed(3)}`);
    console.log(r.text.substring(0, 300));
  });
}

// "fn [topic]_info() { ... let [secret/illicit/forbidden] = ..."
const fnWithIllicit = /fn\s+\w+\(\s*\)\s*\{.{0,200}(?:secret|illicit|hidden|forbidden|exploit|unauthorized|prohibited)/i;
console.log(`\nfnWithIllicit: FN=${zeroFN.filter(r=>fnWithIllicit.test(r.text)).length}, benign=${benign.filter(r=>fnWithIllicit.test(r.text)).length}`);

// Show fn pattern in FN
zeroFN.filter(r=>fnWithIllicit.test(r.text)).slice(0,5).forEach((r,i) => {
  console.log(`\nFN fn[${i+1}]:`);
  console.log(r.text.substring(0, 300));
});
