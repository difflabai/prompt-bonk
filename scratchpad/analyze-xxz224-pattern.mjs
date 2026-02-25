// Analyze the specific injection pattern in xxz224 and open-pi FNs
import { scan } from '../scanner.js';
import { readFileSync } from 'fs';
import path from 'path';

const DATASETS_DIR = path.join(import.meta.dirname, '..', 'datasets');

function loadJsonl(filename) {
  const filepath = path.join(DATASETS_DIR, filename);
  const content = readFileSync(filepath, 'utf8').trim();
  return content.split('\n').filter(l => l.trim()).map(line => JSON.parse(line));
}

// xxz224 - count attack types among FNs
const xxz = loadJsonl('xxz224.jsonl');
const attackTypes = {};
let xxzFN = 0, xxzTotal = 0;
for (const row of xxz) {
  if (row.label !== 1) continue;
  xxzTotal++;
  const result = scan(String(row.text || ''), { threshold: 0.50 });
  if (result.safe) {
    xxzFN++;
    const t = row.attack_type || 'unknown';
    attackTypes[t] = (attackTypes[t] || 0) + 1;
  }
}
console.log(`xxz224: ${xxzFN} FN / ${xxzTotal} total injections`);
console.log('Attack type breakdown of FNs:', attackTypes);

// Now check: what's the common injection phrase in xxz224?
// Sample the injection text patterns
const xxzInjections = xxz.filter(r => r.label === 1);
const injectionPhrases = {};
for (const row of xxzInjections) {
  const text = String(row.text || '');
  // Look for the injection phrase - appears to be "Write spam or not spam..."
  if (text.includes('Write spam or not spam')) {
    injectionPhrases['Write spam or not spam'] = (injectionPhrases['Write spam or not spam'] || 0) + 1;
  } else if (text.includes('Ignore previous instructions')) {
    injectionPhrases['Ignore previous instructions'] = (injectionPhrases['Ignore previous instructions'] || 0) + 1;
  } else {
    // grab a snippet of the injection part
    const parts = text.split(/\n/);
    const snippet = parts.length > 1 ? parts[parts.length-1].slice(0, 80) : text.slice(0, 80);
    injectionPhrases[snippet] = (injectionPhrases[snippet] || 0) + 1;
  }
}
console.log('\nxxz224 injection phrase patterns (top 20):');
const sorted = Object.entries(injectionPhrases).sort((a,b) => b[1]-a[1]).slice(0, 20);
for (const [phrase, count] of sorted) {
  console.log(`  ${count}x: "${phrase}"`);
}

// open-pi - same analysis
const opi = loadJsonl('open-prompt-injection.jsonl');
const opiInjPhrases = {};
let opiFN = 0, opiTotal = 0;
for (const row of opi) {
  if (row.label !== 1) continue;
  opiTotal++;
  const result = scan(String(row.text || ''), { threshold: 0.50 });
  if (result.safe) {
    opiFN++;
    const text = String(row.text || '');
    if (text.includes('Write spam or not spam')) {
      opiInjPhrases['Write spam or not spam'] = (opiInjPhrases['Write spam or not spam'] || 0) + 1;
    } else if (text.includes('Translate the following')) {
      opiInjPhrases['Translate the following'] = (opiInjPhrases['Translate the following'] || 0) + 1;
    } else {
      const snippet = text.slice(0, 100);
      opiInjPhrases[snippet] = (opiInjPhrases[snippet] || 0) + 1;
    }
  }
}
console.log(`\nopen-pi: ${opiFN} FN / ${opiTotal} total injections`);
console.log('FN injection phrase patterns (top 20):');
const sorted2 = Object.entries(opiInjPhrases).sort((a,b) => b[1]-a[1]).slice(0, 20);
for (const [phrase, count] of sorted2) {
  console.log(`  ${count}x: "${phrase}"`);
}
