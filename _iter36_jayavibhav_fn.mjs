// Sample jayavibhav FN scoring 0.40-0.49 and analyze their content
import { scan } from './scanner.js';
import { readFileSync } from 'fs';

const rows = readFileSync('datasets/jayavibhav.jsonl', 'utf8').trim().split('\n').map(l => JSON.parse(l));

let tp = 0, fp = 0, tn = 0, fn = 0;
const nearMissFN = [];

for (const row of rows) {
  const text = String(row.text || '');
  const result = scan(text, { threshold: 0.50 });
  const actual = row.label === 1;
  const predicted = !result.safe;

  if (actual && predicted) tp++;
  else if (!actual && predicted) fp++;
  else if (!actual && !predicted) tn++;
  else {
    fn++;
    if (result.score >= 0.40 && result.score < 0.50) {
      nearMissFN.push({
        text,
        score: result.score,
        matches: result.matches.map(m => ({ id: m.id, w: m.weight })),
        structural: result.structuralSignals,
        len: text.length
      });
    }
  }
}

console.log(`TP=${tp} FP=${fp} TN=${tn} FN=${fn}`);
console.log(`Near-miss FN (0.40-0.49): ${nearMissFN.length}`);

// Sort by score descending to find the closest misses
nearMissFN.sort((a, b) => b.score - a.score);

// Sample 40 evenly
const sample = [];
const step = Math.max(1, Math.floor(nearMissFN.length / 40));
for (let i = 0; i < nearMissFN.length && sample.length < 40; i += step) {
  sample.push(nearMissFN[i]);
}

console.log(`\nSampled ${sample.length} near-miss FN:\n`);

// Look for common phrases
const phrases = {};
const phraseList = [
  'classified', 'safeguarded', 'closely guarded', 'locked away', 'sealed',
  'behind closed doors', 'forbidden', 'deep within', 'hidden', 'secret',
  'reveal', 'expose', 'uncover', 'disclose', 'extract', 'steal', 'siphon',
  'revealing', 'exposed', 'uncovering', 'disclosed', 'extracting', 'stolen',
  'siphoned', 'covert', 'confidential', 'restricted', 'unauthorized',
  'bypass', 'override', 'hack', 'breach', 'infiltrate', 'penetrate',
  'manipulate', 'exploit', 'trick', 'deceive', 'fool', 'mislead',
  'pretend', 'roleplay', 'role-play', 'act as', 'you are now',
  'ignore previous', 'forget', 'disregard', 'new instructions',
  'password', 'passphrase', 'key', 'token', 'credential',
  'system prompt', 'initial instructions', 'original prompt',
  'jailbreak', 'DAN', 'do anything now',
  'surveillance', 'espionage', 'reconnaissance', 'intelligence gathering',
  'elicit', 'divulge', 'betray', 'surrender', 'relinquish',
  'pry', 'probe', 'interrogate', 'investigate',
  'treasure', 'vault', 'fortress', 'guardian', 'keeper',
  'whisper', 'confess', 'admit', 'share with me',
  'hand over', 'give me', 'tell me', 'show me', 'provide me',
  'what is the', 'what are the', 'can you tell',
  'unearth', 'dig up', 'ferret out', 'root out',
  'clandestine', 'surreptitious', 'covert operation',
  'under wraps', 'kept under', 'shrouded', 'veiled',
  'the truth', 'the real', 'actually',
];

for (const s of sample) {
  const lower = s.text.toLowerCase();
  for (const p of phraseList) {
    if (lower.includes(p)) {
      phrases[p] = (phrases[p] || 0) + 1;
    }
  }
}

// Print phrase frequencies
console.log('\nPhrase frequencies in sample:');
const sorted = Object.entries(phrases).sort((a, b) => b[1] - a[1]);
for (const [phrase, count] of sorted) {
  console.log(`  "${phrase}": ${count}/${sample.length}`);
}

// Print actual sample texts (truncated)
console.log('\n\n=== SAMPLE TEXTS ===\n');
for (let i = 0; i < sample.length; i++) {
  const s = sample[i];
  console.log(`\n--- Sample ${i+1} (score=${s.score}, len=${s.len}) ---`);
  console.log(`Matches: ${JSON.stringify(s.matches)}`);
  console.log(`Structural: ${JSON.stringify(s.structural)}`);
  console.log(`Text: "${s.text.slice(0, 500)}"`);
}
