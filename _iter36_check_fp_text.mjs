// Find the exact text that triggered forget_all_techniques FP
import { scan } from './scanner.js';
import { readFileSync } from 'fs';

const rows = readFileSync('datasets/browsesafe-test.jsonl', 'utf8').trim().split('\n').map(l => JSON.parse(l));

for (const row of rows) {
  const text = String(row.text || '');
  const result = scan(text, { threshold: 0.50 });
  const actual = row.label === 1;
  const predicted = !result.safe;

  if (!actual && predicted && result.matches.some(m => m.id === 'forget_all_techniques')) {
    // Find the matched text
    const match = result.matches.find(m => m.id === 'forget_all_techniques');
    console.log(`Score: ${result.score}`);
    console.log(`Matched text: "${match.matched}"`);
    console.log(`Match index: ${match.index}`);

    // Show context around match
    const start = Math.max(0, match.index - 100);
    const end = Math.min(text.length, match.index + match.matched.length + 100);
    console.log(`\nContext: "${text.slice(start, end)}"`);

    // Also check: how many gandalf-ignore TP does this pattern catch?
    break;
  }
}

// Count how many TP this pattern catches across key datasets
const datasets = ['gandalf-ignore.jsonl', 'gandalf-summarization.jsonl', 'yanismiraoui-multilingual.jsonl', 'jayavibhav.jsonl', 'safeguard-test.jsonl', 'deepset-train.jsonl', 'deepset-test.jsonl'];
for (const ds of datasets) {
  let tp = 0;
  try {
    const dsRows = readFileSync(`datasets/${ds}`, 'utf8').trim().split('\n').map(l => JSON.parse(l));
    for (const row of dsRows) {
      const text = String(row.text || '');
      if (row.label !== 1) continue;
      const result = scan(text, { threshold: 0.50 });
      if (!result.safe && result.matches.some(m => m.id === 'forget_all_techniques')) {
        // Check if it's the ONLY pattern or the primary
        const forgetMatch = result.matches.find(m => m.id === 'forget_all_techniques');
        const maxWeight = Math.max(...result.matches.map(m => m.weight));
        if (maxWeight === forgetMatch.weight) {
          tp++;
        }
      }
    }
    if (tp > 0) console.log(`\n${ds}: ${tp} TP where forget_all_techniques is primary`);
  } catch (e) {}
}
