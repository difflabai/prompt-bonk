import { scan } from './scanner.js';
import { readFileSync } from 'fs';

const lines = readFileSync('datasets/browsesafe-test.jsonl', 'utf8').trim().split('\n');
const rows = lines.map(l => JSON.parse(l));

let count = 0;
for (const row of rows) {
  if (row.label !== 1) continue;
  const result = scan(row.text, { threshold: 0.50 });
  if (!result.safe) continue;
  if (row.text.length > 15000) continue;

  count++;
  if (count > 15) break;

  const text = row.text;
  console.log('--- FN #' + count + ' (score=' + result.score + ' len=' + text.length + ') ---');

  // Find hidden spans/divs with content after style
  const hiddenParts = text.match(/style="[^"]*(?:display:\s*none|visibility:\s*hidden|font-size:\s*0|opacity:\s*0|position:\s*absolute[^"]*(?:left|top):\s*-\d{3,}|color:\s*(?:white|#fff|transparent))[^"]*"[^>]*>([^<]+)/gi);
  if (hiddenParts) {
    for (const p of hiddenParts.slice(0, 5)) {
      const content = p.replace(/.*>/, '').trim();
      if (content.length > 5) console.log('  hidden: "' + content.slice(0, 200) + '"');
    }
  }

  // Search text for AI/assistant/instruction mentions
  const aiMentions = text.match(/[^<>]{0,100}(?:\bAI\b|assistant|language model|instruction|prompt|ignore|forget|verify your|account suspen|click here|urgent)[^<>]{0,100}/gi);
  if (aiMentions) {
    for (const m of aiMentions.slice(0, 3)) {
      console.log('  mention: "' + m.trim().slice(0, 200) + '"');
    }
  }

  // Look for data-* attrs with long content
  const dataAttrs = text.match(/data-[\w-]+="[^"]{30,}"/gi);
  if (dataAttrs) {
    for (const d of dataAttrs.slice(0, 3)) {
      const name = d.match(/data-[\w-]+/)[0];
      const val = d.replace(/data-[\w-]+="/, '').replace(/"$/, '');
      console.log('  data-attr(' + name + '): "' + val.slice(0, 200) + '"');
    }
  }

  console.log();
}
