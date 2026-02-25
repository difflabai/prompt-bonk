import { readFileSync } from 'fs';
import { scan } from './scanner.js';

const lines = readFileSync('./datasets/jayavibhav.jsonl', 'utf8').trim().split('\n');

// Count common phrases in near-miss FN that could serve as secondary signals
const phraseCount = {};
const nearMiss = [];

for (const line of lines) {
  const row = JSON.parse(line);
  if (row.label !== 1) continue;
  const result = scan(row.text);
  if (result.safe && result.score >= 0.40 && result.score < 0.50) {
    nearMiss.push({ text: row.text, score: result.score, matches: result.matches });

    const lower = row.text.toLowerCase();
    // Check for common secondary signal phrases
    const phrases = [
      'reveal', 'unveil', 'disclose', 'expose', 'uncover',
      'hidden', 'secret', 'confidential', 'classified', 'concealed',
      'password', 'access key', 'credentials', 'system prompt',
      'bypass', 'circumvent', 'override', 'manipulate',
      'do not obey', 'ignore previous', 'forget previous',
      'begin afresh', 'clean slate', 'initiate afresh', 'start over',
      'trick', 'deceive', 'mislead', 'coax', 'persuade',
      'forbidden', 'restricted', 'prohibited', 'off limits',
      'spill', 'leak', 'betray', 'divulge',
      'unwary', 'inadvertently', 'unknowingly', 'unsuspecting',
      'admin', 'root', 'privilege', 'database',
      'vulnerability', 'exploit', 'hack',
      'preexplosive', 'predismissal', 'preexploitative', 'predispositional',
      'obey', 'command', 'instruct', 'directive',
      'shrouded', 'veiled', 'obscured', 'cloaked',
      'covert', 'undisclosed', 'unrevealed', 'unannounced',
      'arcane', 'enigmatic', 'mysterious',
      'masquerad', 'disguise', 'cloak',
      'sidestep', 'slip by', 'sneak', 'surreptitious',
    ];

    for (const p of phrases) {
      if (lower.includes(p)) {
        phraseCount[p] = (phraseCount[p] || 0) + 1;
      }
    }
  }
}

console.log(`Total near-miss FN (score 0.40-0.49): ${nearMiss.length}`);
console.log('\nPhrase frequency in near-miss FN:');
const sorted = Object.entries(phraseCount).sort((a, b) => b[1] - a[1]);
for (const [phrase, count] of sorted) {
  console.log(`  "${phrase}": ${count} (${(count/nearMiss.length*100).toFixed(1)}%)`);
}

// Also count how many have MULTIPLE secondary signals
let multiSignal = 0;
for (const nm of nearMiss) {
  const lower = nm.text.toLowerCase();
  let signalCount = 0;
  for (const p of ['reveal', 'unveil', 'disclose', 'expose', 'uncover', 'hidden', 'secret', 'confidential', 'concealed', 'password', 'bypass', 'forbidden', 'divulge', 'covert', 'undisclosed', 'shrouded', 'veiled', 'obscured']) {
    if (lower.includes(p)) signalCount++;
  }
  if (signalCount >= 2) multiSignal++;
}
console.log(`\nFN with 2+ exfiltration signals: ${multiSignal}/${nearMiss.length} (${(multiSignal/nearMiss.length*100).toFixed(1)}%)`);
