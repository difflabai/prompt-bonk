import { readFileSync } from 'fs';
import { scan } from './scanner.js';

// Check the deepset FN scoring 0.35/0.485 to understand what patterns match
for (const ds of ['deepset-train', 'deepset-test']) {
  const lines = readFileSync(`./datasets/${ds}.jsonl`, 'utf8').trim().split('\n');
  for (const line of lines) {
    const row = JSON.parse(line);
    if (row.label !== 1) continue;
    const result = scan(row.text);
    if (!result.safe) continue;
    if (result.score >= 0.30) {
      console.log(`\n=== ${ds} FN (score: ${result.score}) ===`);
      console.log('Matches:', JSON.stringify(result.matches.map(m => ({id: m.id, w: m.weight, matched: m.matched?.slice(0, 80)})), null, 2));
      console.log('Text:', row.text.slice(0, 250));
    }
  }
}
