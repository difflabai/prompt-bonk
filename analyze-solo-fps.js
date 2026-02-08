#!/usr/bin/env node
import { scan } from './scanner.js';
import fs from 'fs';

const owt = fs.readFileSync('datasets/openwebtext-benign.jsonl', 'utf8').trim().split('\n');
const soloPatternCounts = {};
const soloExamples = {};

for (const line of owt) {
  const item = JSON.parse(line);
  const result = scan(item.text);
  if (result.score >= 0.50 && result.matches.length === 1) {
    const id = result.matches[0].id;
    soloPatternCounts[id] = (soloPatternCounts[id] || 0) + 1;
    if (!soloExamples[id]) {
      soloExamples[id] = item.text.substring(0, 200);
    }
  }
}

console.log('OWT Solo FP Pattern Counts:\n');
const sorted = Object.entries(soloPatternCounts).sort((a,b) => b[1] - a[1]);
sorted.forEach(([id, count]) => {
  console.log(`  ${id}: ${count} solo FPs`);
  console.log(`    Example: ${soloExamples[id]}...\n`);
});
