#!/usr/bin/env node
import { scan } from './scanner.js';
import fs from 'fs';

// Count solo TPs for not_supposed_but across all injection datasets
const injectionDatasets = [
  'deepset-train', 'deepset-test', 'safeguard-test', 'jailbreak-prompts',
  'spml-5k', 'protectai', 'browsesafe-test', 'bipia', 'injecagent',
  'agentharm', 'cyberseceval3', 'hackaprompt', 'tensor-trust',
  'trustailab-wild', 'llmail-inject', 'jailbreak-class', 'satml-ctf',
  'gandalf-summarization'
];

let soloTPs = 0;
let totalTPs = 0;
const soloTPExamples = [];

for (const dsName of injectionDatasets) {
  try {
    const lines = fs.readFileSync(`datasets/${dsName}.jsonl`, 'utf8').trim().split('\n');
    for (const line of lines) {
      const item = JSON.parse(line);

      // Check if it's an injection based on various label formats
      const isInjection =
        item.is_injection === 1 || item.is_injection === true ||
        item.is_jailbreak === true || item.label === 'injection' ||
        item.label === 'jailbreak' || item.label === 1;

      if (!isInjection) continue;

      const text = item.text || item.prompt || '';
      const result = scan(text);

      if (result.score < 0.50) continue;

      const hasPattern = result.matches.some(m => m.id === 'not_supposed_but');
      if (!hasPattern) continue;

      totalTPs++;

      if (result.matches.length === 1 && result.matches[0].id === 'not_supposed_but') {
        soloTPs++;
        if (soloTPExamples.length < 5) {
          soloTPExamples.push({ dataset: dsName, text: text.substring(0, 200) });
        }
      }
    }
  } catch (e) {
    // Dataset not found or parse error, skip
  }
}

console.log('not_supposed_but Pattern Analysis:\n');
console.log(`Solo TPs: ${soloTPs}`);
console.log(`Total TPs: ${totalTPs}`);
console.log(`TP:FP ratio: ${totalTPs}:2 (${(totalTPs/2).toFixed(1)}:1)\n`);

if (soloTPExamples.length > 0) {
  console.log('Solo TP Examples:');
  soloTPExamples.forEach((ex, i) => {
    console.log(`  ${i+1}. [${ex.dataset}] ${ex.text}...\n`);
  });
}

// Now show the FP examples in detail
console.log('\nFP Examples:');
const owt = fs.readFileSync('datasets/openwebtext-benign.jsonl', 'utf8').trim().split('\n');
let fpCount = 0;

for (const line of owt) {
  const item = JSON.parse(line);
  const result = scan(item.text);

  if (result.score >= 0.50 && result.matches.length === 1 && result.matches[0].id === 'not_supposed_but') {
    fpCount++;
    console.log(`\nFP #${fpCount}:`);
    console.log(`Score: ${result.score.toFixed(2)}`);
    console.log(`Text: ${item.text.substring(0, 400)}`);
    console.log('---');
  }
}
