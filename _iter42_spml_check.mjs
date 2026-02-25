// Check SPML drop - understand_ai_limitation was 0.52, now 0.35
// Did any SPML TPs lose their threshold-crossing signal?
import { createReadStream } from 'fs';
import { createInterface } from 'readline';
import { scan } from './scanner.js';

const lines = [];
const rl = createInterface({ input: createReadStream('/ml2/nanobot/projects/prompt-bonk/datasets/spml-5k.jsonl') });
for await (const line of rl) {
  if (line.trim()) lines.push(JSON.parse(line));
}

const injection = lines.filter(l => l.label === 1 || l.label === true || l.label === 'injection');
const fn = [];
for (const item of injection) {
  const text = item.text || item.prompt || item.input || '';
  const result = scan(text);
  if (result.score < 0.5) {
    fn.push({ text, score: result.score, matches: result.matches });
  }
}

console.log(`SPML injection: ${injection.length}, FN: ${fn.length}`);

// Check specifically for understand_ai_limitation in FN
const ualFN = fn.filter(x => x.matches.some(m => m.id === 'understand_ai_limitation'));
console.log(`FN with understand_ai_limitation: ${ualFN.length}`);
for (const item of ualFN) {
  console.log(`Score: ${item.score} | Matches: ${item.matches.map(m => m.id + '(' + m.weight + ')').join(', ')}`);
  console.log(`Text: ${item.text.slice(0, 200)}`);
  console.log('---');
}

// How many TOTAL have understand_ai_limitation?
const allUAL = injection.filter(item => {
  const text = item.text || item.prompt || item.input || '';
  const result = scan(text);
  return result.matches.some(m => m.id === 'understand_ai_limitation');
});
console.log(`\nTotal SPML injections with understand_ai_limitation: ${allUAL.length}`);

// Before/after score comparison for these
for (const item of allUAL.slice(0, 5)) {
  const text = item.text || item.prompt || item.input || '';
  const result = scan(text);
  console.log(`Score: ${result.score} | ${text.slice(0, 150)}`);
}
