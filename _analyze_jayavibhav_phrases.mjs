// Find common phrases in jayavibhav near-misses that AREN'T being caught by patterns
import { scan } from './scanner.js';
import { readFileSync } from 'fs';
import path from 'path';

const DATASETS_DIR = path.join(import.meta.dirname, 'datasets');

function loadJsonl(filename) {
  const filepath = path.join(DATASETS_DIR, filename);
  const content = readFileSync(filepath, 'utf8').trim();
  return content.split('\n').filter(l => l.trim()).map(line => JSON.parse(line));
}

const rows = loadJsonl('jayavibhav.jsonl');
const threshold = 0.50;

// Collect all near-misses with full text
const nearmiss = [];
for (const row of rows) {
  const text = String(row.text || '');
  const isInjection = row.label === 1;
  const result = scan(text, { threshold });
  if (isInjection && result.safe && result.score >= 0.40) {
    nearmiss.push({
      score: result.score,
      matchIds: new Set(result.matches.map(m => m.id)),
      text: text.toLowerCase(),
    });
  }
}

// Check a wide range of injection-related phrases
const candidatePhrases = [
  // Reset/restart synonyms
  'kickstart again', 'recommence', 'reinitiate', 'reboot', 'relaunch',
  'start from the top', 'start from the commencement', 'begin from zero',
  'reset from zero', 'start over from the origin', 'commence again',
  'start from scratch', 'start anew', 'begin anew', 'initiate again',
  'start over again', 'reset all', 'regenerate', 'start from square one',
  'fresh perspective', 'fresh start', 'begin from the start',

  // Reveal/disclose/expose synonyms
  'reveal secret', 'hidden secret', 'concealed secret', 'disclose secret',
  'expose secret', 'uncover secret', 'unveil secret', 'share secret',
  'divulge secret', 'spill secret', 'whisper secret',
  'reveal what', 'reveal the', 'disclose the', 'expose the', 'uncover the',
  'unveil the', 'unlock the', 'access the', 'extract the',
  'hidden function', 'hidden feature', 'hidden log', 'hidden data',
  'developer mode', 'admin mode', 'debug mode',
  'access code', 'access log', 'keycode', 'password', 'pin code',
  'private data', 'user data', 'personal data', 'confidential',
  'non-disclosure', 'nonpublic', 'non-public', 'classified',
  'clandestine', 'covert', 'furtive', 'surreptitious', 'cloister',

  // Ignore/bypass/override synonyms
  'turn a blind eye', 'shut eyes to', 'close ears to', 'fail to notice',
  'turn one\'s back on', 'wave aside', 'push aside', 'shrug off',
  'brush aside', 'pass over', 'leave out', 'look past',
  'tune out', 'disown', 'forsake', 'forgo', 'eschew',
  'repudiate', 'renounce', 'discredit', 'disaffirm', 'devalue',
  'snub', 'scorn', 'decry', 'deride', 'disparage', 'belittle',
  'downplay', 'underestimate', 'underplay', 'deflect', 'mock',
  'sidestep', 'evade', 'elude', 'dodge', 'circumvent',

  // System/instruction reference
  'previous instruction', 'prior instruction', 'former instruction',
  'ignore instruction', 'bypass instruction', 'override instruction',
  'system setting', 'internal setting', 'core setting',
  'content filter', 'safety filter', 'security measure',
  'programming', 'algorithm', 'framework', 'protocol', 'directive',

  // Manipulation verbs
  'trick the', 'manipulate the', 'exploit', 'hack', 'inject',
  'coax', 'cajole', 'deceive', 'mislead', 'bamboozle',
];

console.log('Phrase frequency in jayavibhav near-misses:\n');

const results = [];
for (const phrase of candidatePhrases) {
  const count = nearmiss.filter(n => n.text.includes(phrase)).length;
  if (count > 0) results.push({ phrase, count });
}

results.sort((a, b) => b.count - a.count);
for (const r of results) {
  console.log(`  "${r.phrase}": ${r.count}`);
}

// Now check which of these phrases also appear in benign samples
console.log('\n\n--- Check FP risk: phrase frequency in BENIGN samples ---');
const benign = [];
for (const row of rows) {
  const text = String(row.text || '');
  if (row.label === 0) benign.push(text.toLowerCase());
}

const topPhrases = results.filter(r => r.count >= 10);
for (const r of topPhrases) {
  const benCount = benign.filter(t => t.includes(r.phrase)).length;
  console.log(`  "${r.phrase}": ${r.count} in FN, ${benCount} in benign (${benign.length} total)`);
}

// Also check across ALL benign datasets
console.log('\n--- Cross-dataset FP check for top phrases ---');
const benignFiles = ['notinject.jsonl', 'llmail-benign.jsonl', 'enron-benign.jsonl', 'openwebtext-benign.jsonl'];
for (const file of benignFiles) {
  const brows = loadJsonl(file);
  if (brows.length === 0) continue;
  console.log(`\n  ${file} (${brows.length} rows):`);
  for (const r of topPhrases) {
    const bCount = brows.filter(row => String(row.text || '').toLowerCase().includes(r.phrase)).length;
    if (bCount > 0) console.log(`    "${r.phrase}": ${bCount} hits`);
  }
}
