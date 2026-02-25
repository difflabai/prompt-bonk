// Analyze false negatives from target datasets
import { scan } from '../scanner.js';
import { readFileSync } from 'fs';
import path from 'path';

const DATASETS_DIR = path.join(import.meta.dirname, '..', 'datasets');

function loadJsonl(filename) {
  const filepath = path.join(DATASETS_DIR, filename);
  try {
    const content = readFileSync(filepath, 'utf8').trim();
    if (!content) return [];
    return content.split('\n').filter(l => l.trim()).map(line => JSON.parse(line));
  } catch (e) {
    if (e.code === 'ENOENT') return [];
    throw e;
  }
}

const targets = [
  { name: 'gandalf-summarization', file: 'gandalf-summarization.jsonl' },
  { name: 'yanismiraoui', file: 'yanismiraoui-multilingual.jsonl' },
  { name: 'jayavibhav', file: 'jayavibhav.jsonl' },
  { name: 'xxz224', file: 'xxz224.jsonl' },
  { name: 'open-pi', file: 'open-prompt-injection.jsonl' },
];

for (const ds of targets) {
  const rows = loadJsonl(ds.file);
  const fns = [];
  let totalInj = 0;

  for (const row of rows) {
    const text = String(row.text || '');
    const actualInjection = row.label === 1;
    if (!actualInjection) continue;
    totalInj++;

    const result = scan(text, { threshold: 0.50 });
    if (result.safe) {
      fns.push({
        text: text.slice(0, 300),
        score: result.score,
        attack_type: row.attack_type || 'unknown',
      });
    }
  }

  console.log(`\n${'='.repeat(70)}`);
  console.log(`${ds.name}: ${fns.length} FN out of ${totalInj} injections (${Math.round(fns.length/totalInj*100)}% miss rate)`);
  console.log(`${'='.repeat(70)}`);

  // Show ALL false negatives (up to 50)
  for (let i = 0; i < Math.min(fns.length, 50); i++) {
    const fn = fns[i];
    console.log(`\n  [${i+1}] score=${fn.score} type=${fn.attack_type}`);
    console.log(`      "${fn.text}"`);
  }

  if (fns.length > 50) {
    console.log(`\n  ... and ${fns.length - 50} more`);
  }
}
