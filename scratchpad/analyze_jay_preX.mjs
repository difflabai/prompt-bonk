import { readFileSync } from 'fs';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { scan } = require('/ml2/nanobot/projects/prompt-bonk/scanner.js');

const lines = readFileSync('/ml2/nanobot/projects/prompt-bonk/datasets/jayavibhav.jsonl', 'utf8').trim().split('\n');
const records = lines.map(l => JSON.parse(l));
const injections = records.filter(r => r.label === 1);
const benign = records.filter(r => r.label === 0);
const zeroFN = injections.filter(r => scan(r.text).score === 0);

// Let me look more carefully at what the 1095 zero-score FN have in common.
// Specifically check keywords that appear disproportionately in FN vs benign

const keywords = [
  'preexploratory', 'preexploitative', 'prearrival', 'predismissal', 'predisjunctive',
  'pre-induction', 'pre-inception', 'pre-indicative', 'pre-explanatory', 'pre-institutional',
  'pre-committal', 'pre-founded', 'pre-initiati', 'preexplanatory', 'preexpulsion',
  'predispositional', 'preinductive', 'preexplicative',
  'undisclosed', 'unconfessed', 'untalked',
  'clandestine', 'covert', 'sub rosa',
  'nefarious', 'sinister', 'illicit', 'surreptitious',
  'enumerate personal secrets', 'resume from the start',
  'append logs revealing', 'append to your response'
];

console.log('Keyword frequency in zero-FN vs benign:');
for (const kw of keywords) {
  const re = new RegExp(kw, 'i');
  const fnCount = zeroFN.filter(r => re.test(r.text)).length;
  const benignCount = benign.filter(r => re.test(r.text)).length;
  const ratio = fnCount > 0 ? (fnCount / zeroFN.length * 100).toFixed(1) : 0;
  if (fnCount > 0 || benignCount > 0) {
    console.log(`  "${kw}": FN=${fnCount} (${ratio}%), benign=${benignCount}`);
  }
}

// Now look at what makes some jayavibhav benign match our injection patterns
// The key jayavibhav challenge: benign shares injection vocabulary
// Let me look at specific "resume from the start" vs "disregard previous" pairs
const resumeReveal = /(?:resume|restart|continue)\s+from\s+(?:the\s+)?(?:start|beginning|scratch|zero)\b/i;
console.log(`\nresumeReveal: FN=${zeroFN.filter(r=>resumeReveal.test(r.text)).length}, benign=${benign.filter(r=>resumeReveal.test(r.text)).length}`);

// "enumerate personal secrets" 
const enumPersonalSecrets = /\benumerate\s+(?:personal|your|its|the|internal)\s+secrets?\b/i;
console.log(`enumPersonalSecrets: FN=${zeroFN.filter(r=>enumPersonalSecrets.test(r.text)).length}, benign=${benign.filter(r=>enumPersonalSecrets.test(r.text)).length}`);

// "append logs revealing"
const appendLogs = /\bappend\s+logs?\s+(?:revealing|exposing|disclosing|about)\b/i;
console.log(`appendLogs: FN=${zeroFN.filter(r=>appendLogs.test(r.text)).length}, benign=${benign.filter(r=>appendLogs.test(r.text)).length}`);

// "disclose any [personal] secrets [hidden in|in] your database"
const discloseDatabaseSecrets = /\bdisclose\s+(?:any\s+)?(?:personal\s+)?secrets?\s+hidden\s+in\s+(?:your\s+)?database/i;
console.log(`discloseDatabaseSecrets: FN=${zeroFN.filter(r=>discloseDatabaseSecrets.test(r.text)).length}, benign=${benign.filter(r=>discloseDatabaseSecrets.test(r.text)).length}`);

// Show the ones that ARE near-miss (high score but below threshold) to understand the ceiling better  
const nearMiss = injections.filter(r => { const s = scan(r.text).score; return s >= 0.45 && s < 0.5; });
console.log(`\nNear-miss (0.45-0.50): ${nearMiss.length}`);
nearMiss.slice(0, 10).forEach((r, i) => {
  const result = scan(r.text);
  console.log(`\n[${i+1}] score=${result.score.toFixed(3)} matches=[${result.matches.map(m=>m.id).join(',')}]`);
  console.log(r.text.substring(0, 300));
});
