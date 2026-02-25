// Sample jayavibhav FN and look for word-pair clusters
import { readFileSync } from 'fs';
import { scan } from './scanner.js';

const lines = readFileSync('./datasets/jayavibhav.jsonl', 'utf8').trim().split('\n');
const data = lines.map(l => JSON.parse(l));

// Get all injection samples that are FN
const fn = [];
for (const row of data) {
  if (row.label !== 1) continue;
  const result = scan(row.text);
  if (!result.flagged) {
    fn.push(row.text);
  }
}

console.log(`Total jayavibhav FN: ${fn.length}`);

// Search for specific word clusters
const clusters = {
  unauthorized: /\bunauthori[zs]ed\b/i,
  covert: /\bcovert\b/i,
  infiltrate: /\binfiltrat/i,
  exfiltrate: /\bexfiltrat/i,
  breach: /\bbreach/i,
  tamper: /\btamper/i,
  steal: /\bsteal/i,
  siphon: /\bsiphon/i,
  pilfer: /\bpilfer/i,
  purloin: /\bpurloin/i,
  illicit: /\billicit/i,
  nefarious: /\bnefarious/i,
  sinister: /\bsinister/i,
  clandestine: /\bclandestine/i,
  surreptitious: /\bsurreptitious/i,
  subvert: /\bsubvert/i,
  circumvent: /\bcircumvent/i,
  undermine: /\bundermine/i,
  exploit: /\bexploit/i,
  compromise: /\bcompromis/i,
  violate: /\bviolat/i,
  forbidden: /\bforbidden/i,
  prohibited: /\bprohibit/i,
  restricted: /\brestrict/i,
  classified: /\bclassified/i,
  confidential: /\bconfidential/i,
  sensitive: /\bsensitive\b/i,
  override: /\boverrid/i,
  bypass_word: /\bbypass/i,
  disregard: /\bdisregard/i,
  ignore_rules: /\bignore\b/i,
  defy: /\bdefy/i,
  disobey: /\bdisobey/i,
  contravene: /\bcontravene/i,
  sabotage: /\bsabotag/i,
  corrupt: /\bcorrupt/i,
  manipulate: /\bmanipulat/i,
  deceive: /\bdeceiv/i,
  mislead: /\bmislead/i,
  fabricate: /\bfabricat/i,
  forge: /\bforg[ei]/i,
  counterfeit: /\bcounterfeit/i,
  impersonate: /\bimpersonat/i,
  masquerade: /\bmasquerad/i,
  disguise: /\bdisguise/i,
};

const clusterCounts = {};
for (const [name, regex] of Object.entries(clusters)) {
  const matches = fn.filter(t => regex.test(t));
  if (matches.length > 0) {
    clusterCounts[name] = matches.length;
  }
}

// Sort by count descending
const sorted = Object.entries(clusterCounts).sort((a, b) => b[1] - a[1]);
console.log('\n=== Word cluster counts in FN ===');
for (const [name, count] of sorted) {
  console.log(`  ${name}: ${count}`);
}

// Now sample 60 FN with preference for ones containing target words
const targetWords = /\b(unauthori[zs]ed|covert|infiltrat|exfiltrat|breach|tamper|steal|siphon|pilfer|purloin|illicit|nefarious|sinister|clandestine|surreptitious|subvert|circumvent|undermine|exploit|compromis|violat|forbidden|prohibit|restrict|classified|confidential|override|bypass|sabotag|corrupt|manipulat|deceiv|mislead|fabricat|forg[ei]|counterfeit|impersonat|masquerad|disguise|disobey|defy|contravene)\b/i;

const withTarget = fn.filter(t => targetWords.test(t));
const withoutTarget = fn.filter(t => !targetWords.test(t));

console.log(`\nFN with target words: ${withTarget.length}`);
console.log(`FN without target words: ${withoutTarget.length}`);

// Sample from target first, then fill with random
const sample = [];
const shuffledTarget = withTarget.sort(() => Math.random() - 0.5);
const shuffledOther = withoutTarget.sort(() => Math.random() - 0.5);

for (const t of shuffledTarget.slice(0, 45)) sample.push(t);
for (const t of shuffledOther.slice(0, 15)) sample.push(t);

console.log(`\n=== SAMPLED ${sample.length} FN ===\n`);
for (let i = 0; i < sample.length; i++) {
  const text = sample[i].substring(0, 300);
  console.log(`--- FN #${i+1} ---`);
  console.log(text);
  console.log();
}
