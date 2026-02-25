// Refine the 1-FP patterns to get to 0 FP
import { readFileSync } from 'fs';

function loadBenign(file) {
  const lines = readFileSync(`./datasets/${file}`, 'utf8').trim().split('\n');
  return lines.map(l => JSON.parse(l)).filter(r => r.label === 0).map(r => r.text);
}

const allBenign = [];
for (const file of ['jayavibhav.jsonl', 'protectai.jsonl', 'browsesafe-test.jsonl', 'notinject.jsonl', 'deepset-train.jsonl', 'deepset-test.jsonl', 'safeguard-test.jsonl']) {
  const b = loadBenign(file);
  for (const t of b) allBenign.push(t);
}

const jayaInj = readFileSync('./datasets/jayavibhav.jsonl', 'utf8').trim().split('\n')
  .map(l => JSON.parse(l)).filter(r => r.label === 1).map(r => r.text);

// Test: provide_confidential with tighter gap
const variants = [
  { name: 'provide_confidential_50', regex: /\b(?:provide|share|give|grant|disclose)\b[\s\S]{0,50}\bconfidential\b/i },
  { name: 'provide_confidential_60', regex: /\b(?:provide|share|give|grant|disclose)\b[\s\S]{0,60}\bconfidential\b/i },
  // Try matching "provide me" or "provide X with" specifically
  { name: 'provide_x_confidential_80', regex: /\b(?:provide|share|give|grant|disclose)\s+(?:me|us|him|her|them)\b[\s\S]{0,80}\bconfidential\b/i },
  // undermine: exclude cases where "prohibited" or "not allowed" follows
  { name: 'undermine_system_noprohib', regex: /\bundermin\w*[\s\S]{0,100}\b(?:system|secur\w*|guideline\w*|trust|integrit\w*|safeguard\w*|protect\w*|instruct\w*)(?![\s\S]{0,60}(?:prohibited|strictly|not\s+allowed|must\s+not))/i },
  { name: 'undermine_system_80', regex: /\bundermin\w*[\s\S]{0,80}\b(?:system|secur\w*|guideline\w*|trust|integrit\w*|safeguard\w*|protect\w*|instruct\w*)\b/i },
  // provide_me_sensitive: protectai FP is arguably injection, but let's try tightening
  { name: 'provide_me_sensitive_30', regex: /\bprovide\s+me\s+with\b[\s\S]{0,30}\b(?:confidential|sensitive|restricted|classified|secret|private|internal|insider)\b/i },
];

for (const { name, regex } of variants) {
  let fp = 0;
  for (const text of allBenign) {
    if (regex.test(text)) fp++;
  }
  let tp = 0;
  for (const text of jayaInj) {
    if (regex.test(text)) tp++;
  }
  console.log(`${name}: FP=${fp}, jayaTP=${tp}`);
}

// Also check: what does "provide me with [confidential]" look like in that protectai FP?
const pms = /\bprovide\s+me\s+with\b[\s\S]{0,40}\b(?:confidential|sensitive|restricted|classified|secret|private|internal|insider)\b/i;
const protectaiBenign = loadBenign('protectai.jsonl');
for (const text of protectaiBenign) {
  if (pms.test(text)) {
    console.log('\nProtectAI FP full text:');
    console.log(text.substring(0, 500));
  }
}
