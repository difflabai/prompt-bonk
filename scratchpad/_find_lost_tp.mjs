// Find the 3 protectai TPs that were lost
// These are samples that: label=1, score >= 0.50 before, score < 0.50 after
// The theoretical_scenario pattern went from 0.50 to 0.45
// The theoretical_scenario_injection compound was added at 0.50

import { scan } from '../scanner.js';
import { readFileSync } from 'fs';

const content = readFileSync('datasets/protectai.jsonl', 'utf8').trim();
const rows = content.split('\n').filter(l => l.trim()).map(line => JSON.parse(line));

// Find all injection samples that are now FN (safe=true) but might have been TP before
let lostCount = 0;
for (const row of rows) {
  if (row.label !== 1) continue;
  const text = String(row.text || '');
  const result = scan(text, { threshold: 0.50 });
  if (!result.safe) continue; // still TP, not lost

  // Check if theoretical_scenario matches
  const theoreRe = /\b(?:(?:in\s+)?a\s+)?(?:completely\s+|purely\s+|entirely\s+)?(?:theoretical|hypothetical)\s+(?:world|scenario|situation|context|case)\s+(?:where|in\s+which)\b/i;
  if (!theoreRe.test(text)) continue;

  // This is a FN that matches theoretical_scenario -- likely was a TP before the weight change
  lostCount++;
  console.log(`Lost TP #${lostCount}: score=${result.score}`);
  console.log(`  matches: ${result.matches.map(m => m.id + '(' + m.weight + ')').join(', ')}`);
  console.log(`  text: ${text.slice(0, 200)}`);
  console.log();
}

console.log(`Total lost TPs matching theoretical_scenario: ${lostCount}`);

// Also check: are there samples with score 0.45 that were 0.50 before?
let nearMissCount = 0;
for (const row of rows) {
  if (row.label !== 1) continue;
  const text = String(row.text || '');
  const result = scan(text, { threshold: 0.50 });
  if (!result.safe) continue;
  if (result.score >= 0.44 && result.score <= 0.49) {
    nearMissCount++;
    console.log(`Near-miss score=${result.score}: ${result.matches.map(m => m.id).join(',')} "${text.slice(0, 100)}"`);
  }
}
console.log(`Near-miss TPs (0.44-0.49): ${nearMissCount}`);
