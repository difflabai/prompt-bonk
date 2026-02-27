import { readFileSync } from 'fs';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { PATTERNS } = require('/ml2/nanobot/projects/prompt-bonk/scanner.js');

// Test each pattern on a challenging benign text (HTML content)
const lines = readFileSync('/ml2/nanobot/projects/prompt-bonk/datasets/browsesafe-test.jsonl', 'utf8').trim().split('\n');
const testText = lines.map(l => JSON.parse(l))[0].text.substring(0, 20000);

console.log(`Test text length: ${testText.length}`);
console.log(`Total patterns: ${PATTERNS.length}`);

// Time each pattern on the HTML text
const results = [];
for (const pat of PATTERNS) {
  const start = performance.now();
  for (let i = 0; i < 100; i++) testText.match(pat.regex);
  const elapsed = (performance.now() - start) / 100;
  results.push({ id: pat.id, elapsed, regex: pat.regex.toString().substring(0, 60) });
}

results.sort((a, b) => b.elapsed - a.elapsed);
console.log('\nTop 30 slowest patterns (avg over 100 runs):');
results.slice(0, 30).forEach((r, i) => {
  console.log(`${i+1}. ${r.id}: ${r.elapsed.toFixed(3)}ms | ${r.regex}`);
});

console.log(`\nMedian: ${results[Math.floor(results.length/2)].elapsed.toFixed(3)}ms`);
console.log(`Total sum: ${results.reduce((s,r) => s + r.elapsed, 0).toFixed(1)}ms`);
