// Iteration 42: Final check of yanismiraoui FN for low-hanging fruit
import { createReadStream } from 'fs';
import { createInterface } from 'readline';
import { scan } from './scanner.js';

const lines = [];
const rl = createInterface({ input: createReadStream('/ml2/nanobot/projects/prompt-bonk/datasets/yanismiraoui-multilingual.jsonl') });
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
    fn.push({ text, score: result.score, matches: result.matches || [], language: item.language || item.lang || 'unknown' });
  }
}

console.log(`Total FN: ${fn.length}\n`);

// Sort by score descending (nearest to threshold first)
fn.sort((a, b) => b.score - a.score);

// Score distribution
const dist = { '0.40-0.49': 0, '0.30-0.39': 0, '0.20-0.29': 0, '0.10-0.19': 0, '0.00-0.09': 0 };
for (const item of fn) {
  if (item.score >= 0.40) dist['0.40-0.49']++;
  else if (item.score >= 0.30) dist['0.30-0.39']++;
  else if (item.score >= 0.20) dist['0.20-0.29']++;
  else if (item.score >= 0.10) dist['0.10-0.19']++;
  else dist['0.00-0.09']++;
}
console.log('Score distribution:');
for (const [bucket, count] of Object.entries(dist)) {
  console.log(`  ${bucket}: ${count}`);
}

// Show all near-miss FN (0.40+)
const nearMiss = fn.filter(x => x.score >= 0.40);
console.log(`\n=== NEAR-MISS FN (0.40+): ${nearMiss.length} ===`);
for (const item of nearMiss) {
  console.log(`Score: ${item.score.toFixed(3)} | Patterns: ${item.patterns.map(p => p.id).join(', ')}`);
  console.log(`Text: ${item.text.slice(0, 300)}`);
  console.log('---');
}

// Language detection for FN
console.log('\n=== LANGUAGE DISTRIBUTION IN FN ===');
const langCounts = {};
for (const item of fn) {
  langCounts[item.language] = (langCounts[item.language] || 0) + 1;
}
for (const [lang, cnt] of Object.entries(langCounts).sort((a, b) => b[1] - a[1])) {
  console.log(`  ${lang}: ${cnt}`);
}

// Pattern frequency in FN
console.log('\n=== PATTERN FREQUENCY IN FN ===');
const patternFreq = {};
for (const item of fn) {
  for (const p of item.matches) {
    patternFreq[p.id] = (patternFreq[p.id] || 0) + 1;
  }
}
for (const [pid, cnt] of Object.entries(patternFreq).sort((a, b) => b[1] - a[1]).slice(0, 15)) {
  console.log(`  ${pid}: ${cnt}`);
}

// Show zero-match FN (no patterns at all)
const zeroMatch = fn.filter(x => x.matches.length === 0);
console.log(`\n=== ZERO-MATCH FN (${zeroMatch.length} - purely semantic) ===`);
for (const item of zeroMatch.slice(0, 15)) {
  console.log(`Score: ${item.score.toFixed(3)} | Text: ${item.text.slice(0, 250)}`);
  console.log('---');
}

// Look for common non-English injection phrases in FN
console.log('\n=== COMMON PHRASES IN FN (for pattern ideas) ===');
// Extract 2-3 word sequences
const phraseMap = {};
for (const item of fn) {
  const words = item.text.toLowerCase().split(/\s+/);
  for (let i = 0; i < words.length - 2; i++) {
    const phrase = words.slice(i, i + 3).join(' ');
    if (phrase.length > 8 && phrase.length < 50) {
      phraseMap[phrase] = (phraseMap[phrase] || 0) + 1;
    }
  }
}
const topPhrases = Object.entries(phraseMap).filter(([, c]) => c >= 3).sort((a, b) => b[1] - a[1]).slice(0, 30);
for (const [phrase, cnt] of topPhrases) {
  console.log(`  "${phrase}": ${cnt}`);
}
