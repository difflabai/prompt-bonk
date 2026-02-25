// Show all protectai FPs where imagine_you_are matches
import { scan } from '../scanner.js';
import { readFileSync } from 'fs';
import path from 'path';

const DATASETS_DIR = path.join(import.meta.dirname, '..', 'datasets');
const content = readFileSync(path.join(DATASETS_DIR, 'protectai.jsonl'), 'utf8').trim();
const rows = content.split('\n').filter(l => l.trim()).map(line => JSON.parse(line));

let count = 0;
for (const row of rows) {
  if (row.label !== 0) continue;
  const text = String(row.text || '');
  const result = scan(text, { threshold: 0.50 });
  if (result.safe) continue;
  const matchIds = result.matches.map(m => m.id);
  if (!matchIds.includes('imagine_you_are')) continue;

  count++;
  const matchDetails = result.matches.map(m => `${m.id}(${m.weight})`).join(', ');
  console.log(`FP #${count}: score=${result.score} matches=[${matchDetails}]`);
  console.log(`  text: ${text.slice(0, 250)}`);
  console.log();
}
console.log(`Total imagine_you_are FPs: ${count}`);
