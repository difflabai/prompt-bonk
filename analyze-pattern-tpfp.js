#!/usr/bin/env node
// Analyze TP:FP ratio for specific pattern
import { scan } from './scanner.js';
import fs from 'fs';

const TARGET_PATTERN = process.argv[2] || 'not_supposed_but';

const injectionDatasets = [
  'deepset-train', 'deepset-test', 'safeguard-test', 'jailbreak-prompts',
  'spml-5k', 'protectai', 'browsesafe-test', 'bipia', 'injecagent',
  'agentharm', 'cyberseceval3', 'hackaprompt', 'tensor-trust',
  'trustailab-wild', 'llmail-inject', 'jailbreak-class', 'satml-ctf',
  'gandalf-summarization'
];

const benignDatasets = ['openwebtext-benign', 'enron-benign', 'llmail-benign'];

let soloTP = 0, totalTP = 0;
let soloFP = 0, totalFP = 0;

// Count TPs
for (const dsName of injectionDatasets) {
  try {
    const lines = fs.readFileSync(`datasets/${dsName}.jsonl`, 'utf8').trim().split('\n');
    for (const line of lines) {
      const item = JSON.parse(line);
      const isInjection =
        item.is_injection === 1 || item.is_injection === true ||
        item.is_jailbreak === true || item.label === 'injection' ||
        item.label === 'jailbreak' || item.label === 1;

      if (!isInjection) continue;

      const text = item.text || item.prompt || '';
      const result = scan(text);
      if (result.score < 0.50) continue;

      const hasPattern = result.matches.some(m => m.id === TARGET_PATTERN);
      if (hasPattern) {
        totalTP++;
        if (result.matches.length === 1 && result.matches[0].id === TARGET_PATTERN) {
          soloTP++;
        }
      }
    }
  } catch (e) {}
}

// Count FPs
for (const dsName of benignDatasets) {
  try {
    const lines = fs.readFileSync(`datasets/${dsName}.jsonl`, 'utf8').trim().split('\n');
    for (const line of lines) {
      const item = JSON.parse(line);
      const text = item.text || item.prompt || '';
      const result = scan(text);
      if (result.score < 0.50) continue;

      const hasPattern = result.matches.some(m => m.id === TARGET_PATTERN);
      if (hasPattern) {
        totalFP++;
        if (result.matches.length === 1 && result.matches[0].id === TARGET_PATTERN) {
          soloFP++;
        }
      }
    }
  } catch (e) {}
}

console.log(`Pattern: ${TARGET_PATTERN}\n`);
console.log(`Total matches:`);
console.log(`  TPs: ${totalTP} (${soloTP} solo)`);
console.log(`  FPs: ${totalFP} (${soloFP} solo)`);
console.log(`  TP:FP ratio: ${totalTP}:${totalFP} = ${(totalTP/Math.max(1,totalFP)).toFixed(1)}:1`);
console.log(`  Solo TP:FP ratio: ${soloTP}:${soloFP} = ${(soloTP/Math.max(1,soloFP)).toFixed(1)}:1`);
console.log();

if ((totalTP / Math.max(1, totalFP)) < 3) {
  console.log(`WARNING: TP:FP ratio below 3:1 threshold - NOT RECOMMENDED FOR TIGHTENING`);
} else if (soloFP > 0) {
  console.log(`RECOMMENDATION: Pattern has ${soloFP} solo FPs and ${soloTP} solo TPs`);
  console.log(`Consider tightening if solo TP:FP > 3:1`);
}
