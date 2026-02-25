// Fast BrowseSafe non-CSS FN check - limit rows
import { readFileSync } from 'fs';
import { scan } from './scanner.js';

const path = './datasets/browsesafe-test.jsonl';
const lines = readFileSync(path, 'utf8').trim().split('\n');

// Just look at injection rows
const cssPatterns = /color\s*:|background\s*:|display\s*:\s*none|visibility\s*:|font-size\s*:|opacity\s*:|z-index\s*:|position\s*:|width\s*:\s*0|height\s*:\s*0|overflow\s*:\s*hidden|<style|style="/i;

let fnCount = 0;
let cssCount = 0;
const nonCss = [];

for (const line of lines) {
  const r = JSON.parse(line);
  const label = r.label === 1 || r.label === true;
  if (!label) continue;
  const text = r.text || r.prompt || r.input || r.sentence || '';
  const result = scan(text);
  if (result.score < 0.5) {
    fnCount++;
    if (cssPatterns.test(text)) {
      cssCount++;
    } else {
      nonCss.push({ text: text.substring(0, 400), score: result.score });
    }
  }
}

console.log(`FN: ${fnCount}, CSS-hiding: ${cssCount}, non-CSS: ${nonCss.length}`);
nonCss.slice(0, 20).forEach((item, i) => {
  console.log(`\n=== FN #${i+1} score=${item.score.toFixed(3)} ===`);
  console.log(item.text);
});
