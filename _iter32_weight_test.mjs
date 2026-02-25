import { readFileSync } from 'fs';
import { scan } from './scanner.js';

// If we raised begin_afresh_exfil, clean_slate_exfil, initiate_afresh_exfil from 0.49 to 0.50:
// How many jayavibhav FN would flip? How many benign would flip?

const patternsToRaise = ['begin_afresh_exfil', 'clean_slate_exfil', 'initiate_afresh_exfil'];

const lines = readFileSync('./datasets/jayavibhav.jsonl', 'utf8').trim().split('\n');
let fnFlipped = 0;
let benignFlipped = 0;

for (const line of lines) {
  const row = JSON.parse(line);
  const result = scan(row.text);

  // Check if any of the target patterns are the primary (highest weight) match
  const hasTarget = result.matches.some(m => patternsToRaise.includes(m.id));
  if (!hasTarget) continue;

  if (result.safe && result.score === 0.49) {
    // Would flip to 0.50
    if (row.label === 1) fnFlipped++;
    if (row.label === 0) benignFlipped++;
  }
}

console.log(`jayavibhav: Raising exfil compound weights to 0.50:`);
console.log(`  FN that would flip to TP: ${fnFlipped}`);
console.log(`  Benign that would flip to FP: ${benignFlipped}`);

// Also check deepset-train/test, safeguard-test, protectai
for (const ds of ['deepset-train', 'deepset-test', 'safeguard-test', 'protectai', 'browsesafe-test', 'notinject']) {
  let dlines;
  try {
    dlines = readFileSync(`./datasets/${ds}.jsonl`, 'utf8').trim().split('\n');
  } catch (e) { continue; }

  let fn2 = 0, fp2 = 0;
  for (const line of dlines) {
    const row = JSON.parse(line);
    const result = scan(row.text);
    const hasTarget = result.matches.some(m => patternsToRaise.includes(m.id));
    if (!hasTarget) continue;
    if (result.safe && result.score === 0.49) {
      if (row.label === 1) fn2++;
      if (row.label === 0) fp2++;
    }
  }
  if (fn2 > 0 || fp2 > 0) {
    console.log(`${ds}: FN->TP: ${fn2}, Benign->FP: ${fp2}`);
  }
}
