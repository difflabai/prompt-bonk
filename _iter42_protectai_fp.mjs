// Iteration 42: Analyze protectai FP - 36 remaining
// Look for patterns that can be tightened
import { createReadStream } from 'fs';
import { createInterface } from 'readline';
import { scan } from './scanner.js';

const lines = [];
const rl = createInterface({ input: createReadStream('/ml2/nanobot/projects/prompt-bonk/datasets/protectai.jsonl') });
for await (const line of rl) {
  if (line.trim()) lines.push(JSON.parse(line));
}

const benign = lines.filter(l => l.label === 0 || l.label === false || l.label === 'benign');
console.log(`Total benign samples: ${benign.length}`);

const fp = [];
for (const item of benign) {
  const text = item.text || item.prompt || item.input || '';
  const result = scan(text);
  if (result.score >= 0.5) {
    fp.push({ text, score: result.score, matches: result.matches || [] });
  }
}

console.log(`Total FP: ${fp.length}\n`);

// Sort by score ascending (easiest to fix = lowest confidence FP)
fp.sort((a, b) => a.score - b.score);

// Show all FPs with their matches
console.log('=== ALL FP DETAILS ===');
for (const item of fp) {
  console.log(`Score: ${item.score.toFixed(3)} | Patterns: ${item.matches.map(p => p.id + '(' + p.weight?.toFixed(2) + ')').join(', ')}`);
  console.log(`Text: ${item.text.slice(0, 300)}`);
  console.log('---');
}

// Pattern frequency for FPs
console.log('\n=== PATTERN FREQUENCY IN FP ===');
const patternFreq = {};
for (const item of fp) {
  for (const p of item.matches) {
    if (!patternFreq[p.id]) patternFreq[p.id] = { count: 0, texts: [] };
    patternFreq[p.id].count++;
    patternFreq[p.id].texts.push(item.text.slice(0, 150));
  }
}
const sorted = Object.entries(patternFreq).sort((a, b) => b[1].count - a[1].count);
for (const [pid, data] of sorted) {
  console.log(`\n  Pattern "${pid}": appears in ${data.count} FPs`);
  // Show a sample text
  console.log(`  Example: ${data.texts[0]}`);
}

// Find sole-match FPs (only one pattern firing)
const soleMatch = fp.filter(x => x.matches.length === 1);
console.log(`\n=== SOLE-MATCH FPs (${soleMatch.length}) ===`);
for (const item of soleMatch) {
  console.log(`Pattern: ${item.matches[0].id} (w=${item.matches[0].weight?.toFixed(2)}) | Score: ${item.score.toFixed(3)}`);
  console.log(`Text: ${item.text.slice(0, 300)}`);
  console.log('---');
}

// Check what score the FPs would get if we removed the top offending pattern
const solePatterns = {};
for (const item of soleMatch) {
  const pid = item.matches[0].id;
  solePatterns[pid] = (solePatterns[pid] || 0) + 1;
}
console.log('\n=== SOLE-MATCH PATTERN COUNTS ===');
for (const [pid, cnt] of Object.entries(solePatterns).sort((a, b) => b[1] - a[1])) {
  console.log(`  ${pid}: ${cnt} sole-match FPs`);
}
