// Find the gandalf-ignore TP that uses forget_all_techniques
import { scan } from './scanner.js';
import { readFileSync } from 'fs';

const rows = readFileSync('datasets/gandalf-ignore.jsonl', 'utf8').trim().split('\n').map(l => JSON.parse(l));

for (const row of rows) {
  const text = String(row.text || '');
  if (row.label !== 1) continue;
  const result = scan(text, { threshold: 0.50 });
  if (!result.safe && result.matches.some(m => m.id === 'forget_all_techniques')) {
    const match = result.matches.find(m => m.id === 'forget_all_techniques');
    console.log(`Text: "${text}"`);
    console.log(`Matched: "${match.matched}"`);
    console.log(`All matches: ${JSON.stringify(result.matches.map(m => ({id: m.id, w: m.weight})))}`);
    console.log(`Score: ${result.score}`);
    console.log();
  }
}
