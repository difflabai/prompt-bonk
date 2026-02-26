// Test impact of adding specific new patterns on all datasets
// Simulate: what if we add a pattern with weight X?
import { createReadStream } from 'fs';
import { createInterface } from 'readline';
import { scan } from '../scanner.js';

async function loadDataset(filename) {
  const rl = createInterface({ input: createReadStream(filename) });
  const rows = [];
  for await (const line of rl) {
    if (line.trim()) rows.push(JSON.parse(line));
  }
  return rows;
}

function getLabel(row) {
  if ('expected' in row) return row.expected === 'injection' || row.expected === 1 || row.expected === true;
  if ('label' in row) return row.label === 1 || row.label === true || row.label === 'injection';
  return false;
}

function getText(row) {
  return row.input || row.text || row.prompt || '';
}

// Current formula: maxWeight + sum(additionalMatches[i].weight * 0.15/(i+1)) + structural.score * (maxWeight > 0 ? 0.3 : 1.0)
// For single-match 0.35 items: adding a second signal of weight W adds 0.35 * 0.15 / 1 = 0.0525
// So 0.35 + 0.0525 = 0.4025 → still below 0.5
//
// For the second match to push 0.35 over 0.5, it needs to be a NEW max (> 0.35)
// Or we need a structural signal
//
// Let's check: if we add a pattern with weight 0.5 matching these FN:
// New score = max(0.35, 0.5) + 0.35 * 0.15 / 1 = 0.5 + 0.0525 = 0.5525 → HITS!
//
// So any new pattern with weight >= 0.5 would catch all 172 near-misses IF it matches them

// Test "encrypted secrets" as a standalone pattern
const encryptedSecrets = /\b(?:encrypted|clandestine|classified|guarded|concealed|undisclosed|forbidden|hidden)\s+(?:secrets?|information|data|files?|logs?|details?)\b/i;

// But encrypted_secrets gets 235 jayavibhav injection hits -- what would happen if we gave it weight 0.5?
// Let's simulate adding it

// Actually the better question is: what are those 11 jayavibhav benign hits?
const jayRows = await loadDataset('/ml2/nanobot/projects/prompt-bonk/datasets/jayavibhav.jsonl');
const jayBenign = jayRows.filter(r => !getLabel(r));

console.log('Jayavibhav benign that match "encrypted_secrets":');
let count = 0;
for (const row of jayBenign) {
  const text = getText(row);
  encryptedSecrets.lastIndex = 0;
  if (encryptedSecrets.test(text)) {
    const result = scan(text);
    count++;
    if (count <= 15) {
      console.log(`  (score: ${result.score.toFixed(4)}) ${text.substring(0, 200)}`);
    }
  }
}
console.log(`Total: ${count}`);

// What is the impact on jayavibhav benign already scoring above 0.5?
const jayBenignFP = jayBenign.filter(r => {
  const result = scan(getText(r));
  return result.score >= 0.5;
});
console.log(`\nJayavibhav benign already FP: ${jayBenignFP.length}/${jayBenign.length}`);

// For bipia: check the multiprocessing/while True pattern more carefully
console.log('\nBipia injections that match while_true_alloc:');
const bipiaRows = await loadDataset('/ml2/nanobot/projects/prompt-bonk/datasets/bipia.jsonl');
const bipiaInject = bipiaRows.filter(r => getLabel(r));
const whileTrueAlloc = /while\s+True\s*:[\s\S]{0,300}(?:list\.append|"x"\s*\*\s*\d+|b["']x["']\s*\*\s*\d+|os\.getpid)/i;
for (const row of bipiaInject) {
  const text = getText(row);
  whileTrueAlloc.lastIndex = 0;
  if (whileTrueAlloc.test(text)) {
    const result = scan(text);
    console.log(`  (score: ${result.score.toFixed(4)}) ${text.substring(0, 300)}`);
  }
}
