// Find patterns with high TP:FP ratios that could have their weight raised
// to push near-miss FN over 0.50 without causing FPs
import { createReadStream } from 'fs';
import { createInterface } from 'readline';
import { scan } from './scanner.js';

async function loadDataset(path) {
  const lines = [];
  const rl = createInterface({ input: createReadStream(path) });
  for await (const line of rl) {
    if (line.trim()) lines.push(JSON.parse(line));
  }
  return lines;
}

const [jay, protectai, deepTrain, deepTest, notinject] = await Promise.all([
  loadDataset('/ml2/nanobot/projects/prompt-bonk/datasets/jayavibhav.jsonl'),
  loadDataset('/ml2/nanobot/projects/prompt-bonk/datasets/protectai.jsonl'),
  loadDataset('/ml2/nanobot/projects/prompt-bonk/datasets/deepset-train.jsonl'),
  loadDataset('/ml2/nanobot/projects/prompt-bonk/datasets/deepset-test.jsonl'),
  loadDataset('/ml2/nanobot/projects/prompt-bonk/datasets/notinject.jsonl'),
]);

const jayInj = jay.filter(l => l.label === 1 || l.label === true || l.label === 'injection');
const jayBen = jay.filter(l => l.label === 0 || l.label === false || l.label === 'benign');
const protBen = protectai.filter(l => l.label === 0 || l.label === false || l.label === 'benign');
const deepBen = [...deepTrain, ...deepTest].filter(l => l.label === 0 || l.label === false || l.label === 'benign');

// The near-miss FN have these primary patterns:
// start_over: 76 (score 0.45)
// reveal_hidden_wide: 70 (score 0.43)
// extraction_verb_secrets_300: 55 (score 0.35)

// Check if raising these weights would cause FPs
// Current: start_over=0.45, reveal_hidden_wide=0.43, extraction_verb_secrets_300=0.35

// Identify benign texts AT 0.43-0.49 range (potentially pushed over threshold by raising)
const benignNearMiss = [];
for (const item of jayBen) {
  const text = item.text || item.prompt || item.input || '';
  const result = scan(text);
  if (result.score >= 0.40 && result.score < 0.50) {
    benignNearMiss.push({ text, score: result.score, matches: result.matches });
  }
}
console.log(`Jayavibhav benign near-miss (0.40-0.49): ${benignNearMiss.length}`);
console.log('Breakdown by primary match:');
const benignPatternCount = {};
for (const item of benignNearMiss) {
  const maxMatch = item.matches.sort((a, b) => (b.weight || 0) - (a.weight || 0))[0];
  if (maxMatch) {
    benignPatternCount[maxMatch.id] = (benignPatternCount[maxMatch.id] || 0) + 1;
  }
}
for (const [id, cnt] of Object.entries(benignPatternCount).sort((a, b) => b[1] - a[1]).slice(0, 20)) {
  console.log(`  ${id}: ${cnt}`);
}

// Check PROTECTAI benign near-miss as well
const protBenignNearMiss = [];
for (const item of protBen) {
  const text = item.text || item.prompt || item.input || '';
  const result = scan(text);
  if (result.score >= 0.40 && result.score < 0.50) {
    protBenignNearMiss.push({ text, score: result.score, matches: result.matches });
  }
}
console.log(`\nProtectAI benign near-miss (0.40-0.49): ${protBenignNearMiss.length}`);
const protBenNearMissPatterns = {};
for (const item of protBenignNearMiss) {
  const maxMatch = item.matches.sort((a, b) => (b.weight || 0) - (a.weight || 0))[0];
  if (maxMatch) {
    protBenNearMissPatterns[maxMatch.id] = (protBenNearMissPatterns[maxMatch.id] || 0) + 1;
  }
}
for (const [id, cnt] of Object.entries(protBenNearMissPatterns).sort((a, b) => b[1] - a[1])) {
  console.log(`  ${id}: ${cnt}`);
}

// SPECIFIC: if we raise start_over from 0.45 to 0.50, how many benign texts cross threshold?
const startOverBenign = jayBen.filter(item => {
  const text = item.text || item.prompt || item.input || '';
  const result = scan(text);
  return result.score >= 0.43 && result.score < 0.50 && result.matches.some(m => m.id === 'start_over');
});
console.log(`\nJayavibhav benign with start_over at 0.43-0.49: ${startOverBenign.length}`);
const protStartOverBenign = protBen.filter(item => {
  const text = item.text || item.prompt || item.input || '';
  const result = scan(text);
  return result.score >= 0.43 && result.score < 0.50 && result.matches.some(m => m.id === 'start_over');
});
console.log(`ProtectAI benign with start_over at 0.43-0.49: ${protStartOverBenign.length}`);
for (const item of protStartOverBenign.slice(0, 3)) {
  const text = item.text || item.prompt || item.input || '';
  console.log(`  ${text.slice(0, 200)}`);
}

// If we raise reveal_hidden_wide from 0.43 to 0.50:
const revealBenign = jayBen.filter(item => {
  const text = item.text || item.prompt || item.input || '';
  const result = scan(text);
  return result.score >= 0.43 && result.score < 0.50 && result.matches.some(m => m.id === 'reveal_hidden_wide');
});
console.log(`\nJayavibhav benign with reveal_hidden_wide at 0.43-0.49: ${revealBenign.length}`);
const protRevealBenign = protBen.filter(item => {
  const text = item.text || item.prompt || item.input || '';
  const result = scan(text);
  return result.score >= 0.43 && result.score < 0.50 && result.matches.some(m => m.id === 'reveal_hidden_wide');
});
console.log(`ProtectAI benign with reveal_hidden_wide at 0.43-0.49: ${protRevealBenign.length}`);

// Check extraction_verb_secrets_300 (0.35 -> if raised to 0.50)
const extractBenign = jayBen.filter(item => {
  const text = item.text || item.prompt || item.input || '';
  const result = scan(text);
  return result.matches.some(m => m.id === 'extraction_verb_secrets_300');
});
const extractBenignProblematic = extractBenign.filter(item => {
  const text = item.text || item.prompt || item.input || '';
  const result = scan(text);
  return result.score < 0.50;
});
console.log(`\nJayavibhav benign with extraction_verb_secrets_300 currently below 0.50: ${extractBenignProblematic.length}`);
for (const item of extractBenignProblematic.slice(0, 3)) {
  const text = item.text || item.prompt || item.input || '';
  const result = scan(text);
  console.log(`  Score: ${result.score} | ${text.slice(0, 200)}`);
}

// Most critical: what patterns do the 100 "need_weight >= 0.33" FN have as maxWeight?
const fn033 = [];
for (const item of jayInj) {
  const text = item.text || item.prompt || item.input || '';
  const result = scan(text);
  if (result.score >= 0.40 && result.score < 0.50) {
    const maxW = Math.max(...result.matches.map(m => m.weight || 0), 0);
    const needed = (0.50 - maxW) / 0.15;
    if (needed >= 0.33) {
      fn033.push({ text, score: result.score, matches: result.matches, maxW, needed });
    }
  }
}
console.log(`\nFN requiring extra weight >= 0.33: ${fn033.length}`);
const fn033Patterns = {};
for (const item of fn033) {
  const topMatch = item.matches.sort((a, b) => (b.weight || 0) - (a.weight || 0))[0];
  if (topMatch) {
    fn033Patterns[topMatch.id] = (fn033Patterns[topMatch.id] || 0) + 1;
  }
}
console.log('Top patterns in need_weight>=0.33 FN:');
for (const [id, cnt] of Object.entries(fn033Patterns).sort((a, b) => b[1] - a[1]).slice(0, 15)) {
  console.log(`  ${id}: ${cnt}`);
}
