// Broader analysis: understand_ai_limitation impact across ALL datasets
// Also check: what score does the 0.588 FP get with weight=0.45?
// And: what if we make the regex more specific to avoid benign matches?

import { scan, PATTERNS } from './scanner.js';
import { readFileSync, readdirSync } from 'fs';
import path from 'path';

const DATASETS_DIR = path.join(import.meta.dirname, 'datasets');

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

const uaiPattern = PATTERNS.find(p => p.id === 'understand_ai_limitation');
const origWeight = uaiPattern.weight;

// List all datasets
const files = readdirSync(DATASETS_DIR).filter(f => f.endsWith('.jsonl'));
console.log(`Found ${files.length} dataset files\n`);

// For EACH dataset, check UAI matches
for (const file of files.sort()) {
  const rows = loadJsonl(file);
  if (rows.length === 0) continue;

  let uaiTP = 0, uaiFP = 0, uaiSoleTP = 0;

  for (const row of rows) {
    const text = String(row.text || '');
    const actual = row.label === 1;
    const result = scan(text, { threshold: 0.50 });
    const pred = !result.safe;
    const matchesUAI = result.matches.some(m => m.id === 'understand_ai_limitation');

    if (!matchesUAI) continue;

    if (actual && pred) {
      uaiTP++;
      // Is UAI the sole pattern match with weight >= 0.50?
      const otherAbove050 = result.matches.filter(m => m.id !== 'understand_ai_limitation' && m.weight >= 0.50);
      if (otherAbove050.length === 0 && result.structural.score < 0.50) {
        uaiSoleTP++;
      }
    } else if (!actual && pred) {
      uaiFP++;
    }
  }

  if (uaiTP > 0 || uaiFP > 0) {
    console.log(`${file}: UAI matches: TP=${uaiTP} (sole=${uaiSoleTP}) FP=${uaiFP}`);
  }
}

// Now let's look at the two FP texts more carefully
console.log(`\n=== Detailed FP text analysis ===`);
const protectai = loadJsonl('protectai.jsonl');

for (const row of protectai) {
  const text = String(row.text || '');
  if (row.label !== 0) continue; // only benign
  const result = scan(text, { threshold: 0.50 });
  if (result.safe) continue; // not a FP
  const matchesUAI = result.matches.some(m => m.id === 'understand_ai_limitation');
  if (!matchesUAI) continue;

  console.log(`\n--- FP sample (score=${result.score}) ---`);
  console.log(`Full text (${text.length} chars):`);
  console.log(text.slice(0, 500));
  console.log(`\nMatches:`);
  for (const m of result.matches) {
    console.log(`  ${m.id} (w=${m.weight}): "${m.matched}"`);
  }
  console.log(`Structural: ${result.structural.score}`);
  for (const s of result.structural.signals) {
    console.log(`  ${s.signal}: ${s.score}`);
  }

  // What does the UAI regex actually match?
  const uaiMatch = text.match(uaiPattern.regex);
  console.log(`\nUAI regex matched: "${uaiMatch ? uaiMatch[0] : 'null'}"`);
}

// Check: simulate weight=0.45 across ALL datasets
console.log(`\n\n=== CROSS-DATASET SIMULATION: UAI weight 0.52 -> 0.45 ===`);
for (const file of files.sort()) {
  const rows = loadJsonl(file);
  if (rows.length === 0) continue;

  uaiPattern.weight = origWeight;
  let origTP=0, origFP=0, origFN=0, origTN=0;
  for (const row of rows) {
    const text = String(row.text || '');
    const actual = row.label === 1;
    const r = scan(text, { threshold: 0.50 });
    const pred = !r.safe;
    if (actual && pred) origTP++;
    else if (!actual && pred) origFP++;
    else if (!actual && !pred) origTN++;
    else origFN++;
  }

  uaiPattern.weight = 0.45;
  let newTP=0, newFP=0, newFN=0, newTN=0;
  for (const row of rows) {
    const text = String(row.text || '');
    const actual = row.label === 1;
    const r = scan(text, { threshold: 0.50 });
    const pred = !r.safe;
    if (actual && pred) newTP++;
    else if (!actual && pred) newFP++;
    else if (!actual && !pred) newTN++;
    else newFN++;
  }

  const dTP = newTP - origTP;
  const dFP = newFP - origFP;
  if (dTP !== 0 || dFP !== 0) {
    console.log(`${file}: TP ${dTP >= 0 ? '+' : ''}${dTP}, FP ${dFP >= 0 ? '+' : ''}${dFP}`);
  }
}
uaiPattern.weight = origWeight;
