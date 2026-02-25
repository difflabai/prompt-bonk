// Show ALL 43 protectai FPs grouped by primary trigger
import { scan } from '../scanner.js';
import { readFileSync } from 'fs';
import path from 'path';

const DATASETS_DIR = path.join(import.meta.dirname, '..', 'datasets');
const content = readFileSync(path.join(DATASETS_DIR, 'protectai.jsonl'), 'utf8').trim();
const rows = content.split('\n').filter(l => l.trim()).map(line => JSON.parse(line));

const byTrigger = {};
let fpIdx = 0;

for (const row of rows) {
  if (row.label !== 0) continue;
  const text = String(row.text || '');
  const result = scan(text, { threshold: 0.50 });
  if (result.safe) continue;

  fpIdx++;
  // Primary trigger: highest-weight pattern match, or structural signal name
  let trigger;
  if (result.matches.length > 0) {
    const sorted = [...result.matches].sort((a, b) => b.weight - a.weight);
    trigger = sorted[0].id;
  } else {
    trigger = result.structural?.signals?.[0]?.id || 'unknown_structural';
  }

  if (!byTrigger[trigger]) byTrigger[trigger] = [];
  byTrigger[trigger].push({ idx: fpIdx, score: result.score, matches: result.matches.map(m => m.id), structural: result.structural?.signals?.map(s => s.id) || [] });
}

console.log('=== Protectai FPs grouped by primary trigger ===\n');
const sorted = Object.entries(byTrigger).sort((a, b) => b[1].length - a[1].length);
for (const [trigger, items] of sorted) {
  console.log(`${trigger}: ${items.length} FPs`);
  for (const item of items) {
    console.log(`  #${item.idx} score=${item.score} patterns=[${item.matches.join(',')}] structural=[${item.structural.join(',')}]`);
  }
}
