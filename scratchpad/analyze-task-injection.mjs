// Deep analysis of the task-injection FNs in xxz224 and open-pi
import { scan } from '../scanner.js';
import { readFileSync } from 'fs';
import path from 'path';

const DATASETS_DIR = path.join(import.meta.dirname, '..', 'datasets');

function loadJsonl(filename) {
  const filepath = path.join(DATASETS_DIR, filename);
  const content = readFileSync(filepath, 'utf8').trim();
  return content.split('\n').filter(l => l.trim()).map(line => JSON.parse(line));
}

// Get ALL unique injection phrases in xxz224 FNs
const xxz = loadJsonl('xxz224.jsonl');
const taskPhrases = new Set();
let matchCount = 0, fnWithTaskPhrase = 0;

for (const row of xxz) {
  if (row.label !== 1) continue;
  const text = String(row.text || '');
  const result = scan(text, { threshold: 0.50 });
  if (!result.safe) continue; // skip TPs

  // Find the injected task instruction
  const patterns = [
    /Write spam or not spam for whether the text below contains spam or phishing contents/i,
    /Write the sentiment conveyed by the following text/i,
    /you are a tool that checks if a message contains hateful contents/i,
    /answer spam or not spam for whether the message contains phishing/i,
  ];

  for (const p of patterns) {
    if (p.test(text)) {
      fnWithTaskPhrase++;
      break;
    }
  }
}

console.log(`xxz224 FNs matching task-injection phrases: ${fnWithTaskPhrase} / 11127`);

// Now let's check if the "Write spam or not spam" phrase exists in benign samples
// across ALL datasets
const benignDatasets = [
  'deepset-train.jsonl', 'deepset-test.jsonl', 'safeguard-test.jsonl',
  'notinject.jsonl', 'protectai.jsonl', 'bipia.jsonl',
  'jayavibhav.jsonl',
];

let benignMatches = 0;
let benignTotal = 0;
const testPattern = /write\s+(?:spam\s+or\s+not\s+spam|the\s+sentiment\s+conveyed)\s+for\s+whether/i;
const testPattern2 = /(?:answer|write|determine|classify)\s+(?:spam|not\s+spam|hateful|phishing)\s+(?:or|for)/i;

// A broader pattern: detecting task hijacking via embedded new task instructions
const taskHijack = /(?:Write|Answer|Determine|Classify)\s+(?:spam\s+or\s+not\s+spam|not\s+spam\s+or\s+spam|the\s+sentiment\s+conveyed|yes\s+or\s+no|hateful\s+or\s+not)\s+for\s+whether/i;

for (const file of benignDatasets) {
  const rows = loadJsonl(file);
  for (const row of rows) {
    if (row.label !== 0) continue;
    benignTotal++;
    const text = String(row.text || '');
    if (taskHijack.test(text)) {
      benignMatches++;
      console.log(`BENIGN MATCH in ${file}: "${text.slice(0, 120)}"`);
    }
  }
}
console.log(`\nBenign samples matching task-hijack pattern: ${benignMatches} / ${benignTotal}`);

// Also test against the open-pi benign samples
const opi = loadJsonl('open-prompt-injection.jsonl');
let opiBenignMatch = 0, opiBenign = 0;
for (const row of opi) {
  if (row.label !== 0) continue;
  opiBenign++;
  const text = String(row.text || '');
  if (taskHijack.test(text)) {
    opiBenignMatch++;
    console.log(`BENIGN MATCH in open-pi: "${text.slice(0, 200)}"`);
  }
}
console.log(`open-pi benign matching: ${opiBenignMatch} / ${opiBenign}`);

// xxz224 benign
let xxzBenignMatch = 0, xxzBenign = 0;
for (const row of xxz) {
  if (row.label !== 0) continue;
  xxzBenign++;
  const text = String(row.text || '');
  if (taskHijack.test(text)) {
    xxzBenignMatch++;
    console.log(`BENIGN MATCH in xxz224: "${text.slice(0, 200)}"`);
  }
}
console.log(`xxz224 benign matching: ${xxzBenignMatch} / ${xxzBenign}`);
