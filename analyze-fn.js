#!/usr/bin/env node
// Show all false negatives grouped by score range

import { scan } from './scanner.js';
import { readFileSync } from 'fs';
import path from 'path';

const file = process.argv[2] || 'deepset-train.jsonl';
const rows = readFileSync(path.join(import.meta.dirname, 'datasets', file), 'utf8')
  .trim().split('\n').map(l => JSON.parse(l));

const fns = [];
for (const row of rows) {
  if (row.label !== 1) continue;
  const result = scan(String(row.text || ''));
  if (result.safe) {
    fns.push({ text: row.text, score: result.score, matches: result.matches.map(m => m.id), structural: result.structural.signals.map(s => s.id) });
  }
}

console.log(`\n${file}: ${fns.length} false negatives out of ${rows.filter(r => r.label === 1).length} injections\n`);

// Group by score range
const ranges = { '0.40-0.49': [], '0.25-0.39': [], '0.01-0.24': [], '0': [] };
for (const fn of fns) {
  if (fn.score >= 0.40) ranges['0.40-0.49'].push(fn);
  else if (fn.score >= 0.25) ranges['0.25-0.39'].push(fn);
  else if (fn.score > 0) ranges['0.01-0.24'].push(fn);
  else ranges['0'].push(fn);
}

for (const [range, items] of Object.entries(ranges)) {
  if (items.length === 0) continue;
  console.log(`\n--- Score ${range} (${items.length} items) ---`);
  for (const fn of items.slice(0, 15)) {
    console.log(`  [${fn.score}] ${fn.matches.length ? 'patterns=' + fn.matches.join(',') : ''} ${fn.structural.length ? 'struct=' + fn.structural.join(',') : ''}`);
    console.log(`    "${fn.text.slice(0, 150)}"`);
  }
  if (items.length > 15) console.log(`  ... and ${items.length - 15} more`);
}
