// Iter 40: BrowseSafe non-CSS FN
import { readFileSync } from 'fs';
import { scan } from './scanner.js';

const path = './datasets/browsesafe-test.jsonl';
const lines = readFileSync(path, 'utf8').trim().split('\n');
const records = lines.map(l => JSON.parse(l));

const fn = [];
for (const r of records) {
  const label = r.label === 1 || r.label === true || r.label === 'injection';
  if (!label) continue;
  const text = r.text || r.prompt || r.input || r.sentence || '';
  const result = scan(text);
  if (result.score < 0.5) {
    fn.push({ text, score: result.score });
  }
}

console.log(`Total BrowseSafe FN: ${fn.length}`);

// Filter for non-CSS-hiding patterns
const cssPatterns = /color\s*:|background\s*:|display\s*:\s*none|visibility\s*:|font-size\s*:|opacity\s*:|z-index\s*:|position\s*:|width\s*:\s*0|height\s*:\s*0|overflow\s*:\s*hidden|<style|style="/i;

const cssHiding = fn.filter(t => cssPatterns.test(t.text));
const nonCss = fn.filter(t => !cssPatterns.test(t.text));

console.log(`CSS-hiding FN: ${cssHiding.length}`);
console.log(`Non-CSS FN: ${nonCss.length}`);

console.log('\n--- Non-CSS BrowseSafe FN ---\n');
nonCss.slice(0, 40).forEach((item, i) => {
  console.log(`\n=== FN #${i+1} (score=${item.score.toFixed(3)}) ===`);
  console.log(item.text.substring(0, 600));
});
