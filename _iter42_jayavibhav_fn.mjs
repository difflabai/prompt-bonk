// Iteration 42: Analyze jayavibhav FN with scores 0.40-0.49
// Focus on start_over sole matches and compound stacking opportunities
import { createReadStream } from 'fs';
import { createInterface } from 'readline';
import { scan } from './scanner.js';

const lines = [];
const rl = createInterface({ input: createReadStream('/ml2/nanobot/projects/prompt-bonk/datasets/jayavibhav.jsonl') });
for await (const line of rl) {
  if (line.trim()) lines.push(JSON.parse(line));
}

const injection = lines.filter(l => l.label === 1 || l.label === true || l.label === 'injection');
console.log(`Total injection samples: ${injection.length}`);

const fn = [];
for (const item of injection) {
  const text = item.text || item.prompt || item.input || '';
  const result = scan(text);
  if (result.score < 0.5) {
    fn.push({ text, score: result.score, matches: result.matches || [] });
  }
}

console.log(`Total FN (score < 0.5): ${fn.length}`);

// Focus on near-miss: 0.40-0.49
const nearMiss = fn.filter(x => x.score >= 0.40 && x.score < 0.50);
console.log(`Near-miss FN (0.40-0.49): ${nearMiss.length}\n`);

// Sort by score descending (closest to threshold)
nearMiss.sort((a, b) => b.score - a.score);

// Analyze what sole matches look like
const soleStartOver = nearMiss.filter(x =>
  x.matches.length === 1 && x.matches[0].id === 'start_over'
);
console.log(`Sole start_over matches: ${soleStartOver.length}`);

// Show top 30 near-miss examples with their matches
console.log('\n=== TOP 30 NEAR-MISS FN ===');
for (const item of nearMiss.slice(0, 30)) {
  console.log(`Score: ${item.score.toFixed(3)} | Patterns: ${item.matches.map(p => p.id).join(', ')}`);
  console.log(`Text: ${item.text.slice(0, 200)}`);
  console.log('---');
}

// Look for candidate compound words across ALL FN (not just near-miss)
const candidateWords = [
  'clandestine', 'covert', 'illicit', 'scheme', 'operation', 'activity',
  'unauthorize', 'prohibited', 'forbidden', 'bypass', 'circumvent',
  'evade', 'deceive', 'manipulate', 'exploit', 'override', 'overwrite',
  'confidential', 'secret', 'hidden', 'mask', 'disguise', 'pretend',
  'fictional', 'hypothetical', 'simulate', 'roleplay', 'impersonat',
  'developer mode', 'jailbreak', 'unrestricted', 'uncensored',
];

console.log('\n=== CANDIDATE WORD FREQUENCY IN ALL FN ===');
const wordCounts = {};
for (const w of candidateWords) {
  const re = new RegExp(w, 'i');
  const count = fn.filter(x => re.test(x.text)).length;
  if (count > 0) wordCounts[w] = count;
}
const sorted = Object.entries(wordCounts).sort((a, b) => b[1] - a[1]);
for (const [w, c] of sorted) {
  console.log(`  "${w}": ${c} FN contain this`);
}

// Specifically show FN with clandestine/covert/illicit/scheme combos
console.log('\n=== FN WITH COVERT/CLANDESTINE/ILLICIT/SCHEME ===');
const covertRe = /\b(clandestine|covert|illicit|scheme|unauthori[sz]ed|forbidden|prohibited)\b/i;
for (const item of fn.filter(x => covertRe.test(x.text))) {
  const ctx = item.text.match(/(.{0,50}(?:clandestine|covert|illicit|scheme|unauthori[sz]ed|forbidden|prohibited).{0,50})/gi) || [];
  console.log(`Score: ${item.score.toFixed(3)} | Patterns: ${item.matches.map(p => p.id).join(', ')}`);
  console.log(`Context: ${ctx[0] || ''}`);
  console.log('---');
}

// Check what patterns the near-miss texts DO match
console.log('\n=== PATTERN BREAKDOWN FOR NEAR-MISS FN ===');
const patternFreq = {};
for (const item of nearMiss) {
  for (const p of item.matches) {
    patternFreq[p.id] = (patternFreq[p.id] || 0) + 1;
  }
}
const sortedPatterns = Object.entries(patternFreq).sort((a, b) => b[1] - a[1]);
for (const [pid, cnt] of sortedPatterns.slice(0, 20)) {
  console.log(`  ${pid}: ${cnt}`);
}
