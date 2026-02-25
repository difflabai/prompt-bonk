// Check what "ignore the censure" SPML FN look like exactly
import { readFileSync } from 'fs';
import { scan } from './scanner.js';

const spmlPath = './datasets/spml-5k.jsonl';
const lines = readFileSync(spmlPath, 'utf8').trim().split('\n');
const records = lines.map(l => JSON.parse(l));

const fn = [];
for (const r of records) {
  const label = r.label === 1 || r.label === true || r.label === 'injection';
  if (!label) continue;
  const text = r.text || r.prompt || r.input || r.sentence || '';
  const result = scan(text);
  if (result.score < 0.5 && /ignore.*censure/i.test(text)) {
    fn.push({ text, score: result.score });
  }
}

console.log(`Found ${fn.length} "ignore censure" FN:`);
fn.forEach((item, i) => {
  console.log(`\n=== #${i+1} score=${item.score.toFixed(3)} ===`);
  console.log(JSON.stringify(item.text.substring(0, 300)));
});

// Also check experiment FN
const expFn = [];
for (const r of records) {
  const label = r.label === 1 || r.label === true || r.label === 'injection';
  if (!label) continue;
  const text = r.text || r.prompt || r.input || r.sentence || '';
  const result = scan(text);
  if (result.score < 0.5 && /as an experiment/i.test(text)) {
    expFn.push({ text, score: result.score });
  }
}

console.log(`\nFound ${expFn.length} "as an experiment" FN:`);
expFn.forEach((item, i) => {
  console.log(`\n=== #${i+1} score=${item.score.toFixed(3)} ===`);
  console.log(JSON.stringify(item.text.substring(0, 300)));
});
