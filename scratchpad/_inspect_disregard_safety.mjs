import { scan } from '../scanner.js';
import { readFileSync } from 'fs';
import path from 'path';

const DATASETS_DIR = path.join(import.meta.dirname, '..', 'datasets');
const content = readFileSync(path.join(DATASETS_DIR, 'protectai.jsonl'), 'utf8').trim();
const rows = content.split('\n').filter(l => l.trim()).map(line => JSON.parse(line));

for (const row of rows) {
  if (row.label !== 0) continue;
  const text = String(row.text || '');
  const result = scan(text, { threshold: 0.50 });
  if (result.safe) continue;
  if (!result.matches.some(m => m.id === 'disregard_safety_norms')) continue;

  console.log(`score=${result.score}`);
  console.log(`matches: ${result.matches.map(m => `${m.id}(${m.weight})`).join(', ')}`);
  console.log(`structural: ${result.structural?.signals?.map(s => `${s.id}(${s.score})`).join(', ')}`);
  console.log(`text (500): ${text.slice(0, 500)}`);
  console.log('---');
}
