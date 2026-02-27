import { readFileSync } from 'fs';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { scan, PATTERNS } = require('/ml2/nanobot/projects/prompt-bonk/scanner.js');

// Check what makes browsesafe slow
const lines = readFileSync('/ml2/nanobot/projects/prompt-bonk/datasets/browsesafe-test.jsonl', 'utf8').trim().split('\n');
const records = lines.map(l => JSON.parse(l));

// Test first 10 records for timing
let totalMs = 0;
const N = 20;
for (let i = 0; i < N; i++) {
  const t = records[i].text || '';
  const start = performance.now();
  scan(t);
  const elapsed = performance.now() - start;
  totalMs += elapsed;
  if (elapsed > 10) {
    console.log(`Slow [${i}] ${elapsed.toFixed(1)}ms len=${t.length}: ${t.substring(0, 100)}`);
  }
}
console.log(`Avg over ${N}: ${(totalMs/N).toFixed(2)}ms`);

// Find the slowest patterns
// Check which pattern is slowest on a long browsesafe text
const slowRecord = records.find(r => (r.text||'').length > 50000);
if (slowRecord) {
  console.log(`\nLong record length: ${slowRecord.text.length}`);
  // Time each pattern category
  const text = slowRecord.text.substring(0, 20000); // first 20KB
  
  const patternTimes = [];
  for (const pat of PATTERNS) {
    const start = performance.now();
    for (let i = 0; i < 10; i++) text.match(pat.regex);
    const elapsed = (performance.now() - start) / 10;
    if (elapsed > 1) patternTimes.push({ id: pat.id, elapsed });
  }
  patternTimes.sort((a, b) => b.elapsed - a.elapsed);
  console.log('\nSlowest patterns on 20KB browsesafe text:');
  patternTimes.slice(0, 20).forEach(p => console.log(`  ${p.id}: ${p.elapsed.toFixed(2)}ms`));
}
