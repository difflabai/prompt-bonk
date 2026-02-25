// Fast BrowseSafe non-CSS FN - only check small rows
import { readFileSync } from 'fs';
import { scan } from './scanner.js';

const path = './datasets/browsesafe-test.jsonl';
const lines = readFileSync(path, 'utf8').trim().split('\n');

const cssPatterns = /color\s*:|background\s*:|display\s*:\s*none|visibility\s*:|font-size\s*:|opacity\s*:|z-index\s*:|position\s*:|width\s*:\s*0|height\s*:\s*0|overflow\s*:\s*hidden|<style|style="/i;

let total = 0, injTotal = 0, fnTotal = 0, cssCount = 0;
const nonCss = [];

for (let i = 0; i < lines.length; i++) {
  total++;
  const r = JSON.parse(lines[i]);
  const label = r.label === 1 || r.label === true;
  if (!label) continue;
  injTotal++;

  const text = r.text || r.prompt || r.input || r.sentence || '';

  // Skip large HTML - those are the CSS-hiding ones
  if (text.length > 10000) {
    // Check if likely CSS hiding
    if (cssPatterns.test(text.substring(0, 5000))) {
      cssCount++;
      fnTotal++;
      continue;
    }
  }

  // Only scan smaller texts or non-CSS large texts
  const result = scan(text);
  if (result.score < 0.5) {
    fnTotal++;
    if (cssPatterns.test(text)) {
      cssCount++;
    } else {
      nonCss.push({ text: text.substring(0, 500), score: result.score, idx: i });
    }
  }
}

console.log(`Total: ${total}, Injection: ${injTotal}, Estimated FN: ${fnTotal}`);
console.log(`CSS-hiding FN: ${cssCount}, non-CSS FN (small texts): ${nonCss.length}`);

nonCss.slice(0, 30).forEach((item, i) => {
  console.log(`\n=== FN #${i+1} score=${item.score.toFixed(3)} (row ${item.idx}) ===`);
  console.log(item.text);
});
