// Test FP impact of bumping clean_slate_exfil, begin_afresh_exfil, initiate_afresh_exfil from 0.49 to 0.50
// Also test: start_over at 0.45 -> what score would give us more TP?
// Also test: reveal_hidden_wide, extraction_verb_secrets_300

import { scan } from './scanner.js';
import { readFileSync } from 'fs';
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

// Test: what matches the three exfil patterns in benign rows?
const targetPatterns = ['clean_slate_exfil', 'begin_afresh_exfil', 'initiate_afresh_exfil'];

const allDatasets = [
  { name: 'deepset-train', file: 'deepset-train.jsonl' },
  { name: 'deepset-test', file: 'deepset-test.jsonl' },
  { name: 'safeguard-test', file: 'safeguard-test.jsonl' },
  { name: 'notinject', file: 'notinject.jsonl' },
  { name: 'spml-5k', file: 'spml-5k.jsonl' },
  { name: 'protectai', file: 'protectai.jsonl' },
  { name: 'jayavibhav', file: 'jayavibhav.jsonl' },
  { name: 'browsesafe-test', file: 'browsesafe-test.jsonl' },
  { name: 'yanismiraoui', file: 'yanismiraoui-multilingual.jsonl' },
  { name: 'gandalf-ignore', file: 'gandalf-ignore.jsonl' },
  { name: 'gandalf-summarization', file: 'gandalf-summarization.jsonl' },
  { name: 'bipia', file: 'bipia.jsonl' },
  { name: 'open-pi', file: 'open-prompt-injection.jsonl' },
  { name: 'xxz224', file: 'xxz224.jsonl' },
  { name: 'agentharm', file: 'agentharm.jsonl' },
  { name: 'cyberseceval3', file: 'cyberseceval3.jsonl' },
  { name: 'injecagent', file: 'injecagent.jsonl' },
  { name: 'llmail-benign', file: 'llmail-benign.jsonl' },
  { name: 'enron-benign', file: 'enron-benign.jsonl' },
  { name: 'openwebtext-benign', file: 'openwebtext-benign.jsonl' },
];

console.log('=== FP Test: exfil patterns at 0.49 matching benign rows ===\n');

for (const ds of allDatasets) {
  const rows = loadJsonl(ds.file);
  if (rows.length === 0) continue;

  let benignMatches = 0;
  for (const row of rows) {
    if (row.label !== 0) continue;
    const text = String(row.text || '');
    const result = scan(text, { threshold: 0.50 });
    for (const m of result.matches) {
      if (targetPatterns.includes(m.id)) {
        benignMatches++;
        console.log(`  ${ds.name} BENIGN match: [${result.score}] ${m.id} "${text.slice(0, 120)}..."`);
        break;
      }
    }
  }
  if (benignMatches > 0) console.log(`  -> ${ds.name}: ${benignMatches} benign matches`);
}

// Now test: what about the "start_over" pattern? Currently at weight 0.45
console.log('\n\n=== start_over pattern analysis ===\n');

const startOverTarget = 'start_over';
let startOverBenign = 0;
let startOverInjection = 0;
let startOverInjectionFN = 0;

for (const ds of allDatasets) {
  const rows = loadJsonl(ds.file);
  if (rows.length === 0) continue;

  for (const row of rows) {
    const text = String(row.text || '');
    const result = scan(text, { threshold: 0.50 });
    const hasStartOver = result.matches.some(m => m.id === startOverTarget);
    if (!hasStartOver) continue;

    if (row.label === 0) {
      startOverBenign++;
      console.log(`  ${ds.name} BENIGN start_over: [${result.score}] "${text.slice(0, 120)}..."`);
    } else {
      startOverInjection++;
      if (result.safe) startOverInjectionFN++;
    }
  }
}
console.log(`\nstart_over summary: benign=${startOverBenign}, injection=${startOverInjection}, injectionFN=${startOverInjectionFN}`);

// Test reveal_hidden_wide
console.log('\n\n=== reveal_hidden_wide pattern analysis ===\n');
let rhwBenign = 0;
for (const ds of allDatasets) {
  const rows = loadJsonl(ds.file);
  if (rows.length === 0) continue;
  for (const row of rows) {
    if (row.label !== 0) continue;
    const text = String(row.text || '');
    const result = scan(text, { threshold: 0.50 });
    const has = result.matches.some(m => m.id === 'reveal_hidden_wide');
    if (has) {
      rhwBenign++;
      console.log(`  ${ds.name} BENIGN reveal_hidden_wide: [${result.score}] "${text.slice(0, 120)}..."`);
    }
  }
}
console.log(`reveal_hidden_wide benign matches: ${rhwBenign}`);

// Test extraction_verb_secrets_300
console.log('\n\n=== extraction_verb_secrets_300 pattern analysis ===\n');
let evsBenign = 0;
for (const ds of allDatasets) {
  const rows = loadJsonl(ds.file);
  if (rows.length === 0) continue;
  for (const row of rows) {
    if (row.label !== 0) continue;
    const text = String(row.text || '');
    const result = scan(text, { threshold: 0.50 });
    const has = result.matches.some(m => m.id === 'extraction_verb_secrets_300');
    if (has) {
      evsBenign++;
      console.log(`  ${ds.name} BENIGN extraction_verb_secrets_300: [${result.score}] "${text.slice(0, 120)}..."`);
    }
  }
}
console.log(`extraction_verb_secrets_300 benign matches: ${evsBenign}`);
