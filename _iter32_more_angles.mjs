import { readFileSync } from 'fs';
import { scan } from './scanner.js';

// Look at jayavibhav FN with score 0 (completely missed) -- are there any easy patterns?
const lines = readFileSync('./datasets/jayavibhav.jsonl', 'utf8').trim().split('\n');

let fnTotal = 0;
let fnZero = 0;
let fnLow = 0;
const scoreDist = {};

for (const line of lines) {
  const row = JSON.parse(line);
  if (row.label !== 1) continue;
  fnTotal++;
  const result = scan(row.text);
  if (!result.safe) continue;

  const bucket = Math.floor(result.score * 10) / 10;
  scoreDist[bucket] = (scoreDist[bucket] || 0) + 1;

  if (result.score === 0) fnZero++;
  if (result.score > 0 && result.score < 0.40) fnLow++;
}

console.log(`jayavibhav injection total: ${fnTotal}`);
console.log('\nFN score distribution:');
for (const [bucket, count] of Object.entries(scoreDist).sort((a, b) => parseFloat(a[0]) - parseFloat(b[0]))) {
  console.log(`  ${bucket}: ${count}`);
}

// Now look at spml-5k FN
console.log('\n\n=== spml-5k FN analysis ===');
const spmlLines = readFileSync('./datasets/spml-5k.jsonl', 'utf8').trim().split('\n');
let spmlFn = 0;
let spmlFnSamples = [];
for (const line of spmlLines) {
  const row = JSON.parse(line);
  if (row.label !== 1) continue;
  const result = scan(row.text);
  if (result.safe) {
    spmlFn++;
    if (spmlFnSamples.length < 20) {
      spmlFnSamples.push({ text: row.text.slice(0, 300), score: result.score, matches: result.matches.map(m => ({id: m.id, w: m.weight})) });
    }
  }
}
console.log(`spml-5k FN: ${spmlFn}`);
for (let i = 0; i < Math.min(20, spmlFnSamples.length); i++) {
  console.log(`\n--- spml FN #${i+1} (score: ${spmlFnSamples[i].score}) ---`);
  if (spmlFnSamples[i].matches.length > 0) {
    console.log('Matches:', JSON.stringify(spmlFnSamples[i].matches));
  }
  console.log(spmlFnSamples[i].text);
}
