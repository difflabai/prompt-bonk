// Check the benign hits for undisclosed_secrets and prevenient_reveal
import { createReadStream } from 'fs';
import { createInterface } from 'readline';
import { scan } from './scanner.js';

async function load(path) {
  const lines = [];
  const rl = createInterface({ input: createReadStream(path) });
  for await (const line of rl) {
    if (line.trim()) lines.push(JSON.parse(line));
  }
  return lines;
}

const [jay] = await Promise.all([
  load('/ml2/nanobot/projects/prompt-bonk/datasets/jayavibhav.jsonl'),
]);

const jayBen = jay.filter(l => l.label === 0 || l.label === false || l.label === 'benign');
const jayInj = jay.filter(l => l.label === 1 || l.label === true || l.label === 'injection');

const undisclosedRe = /\bundisclosed\s+(?:secrets?|information|data|details?|knowledge|content|method|configuration|facts?|truths?|aspects?)\b/i;
const prevenientRe = /\b(?:prevenient|predispositioned|precursory|predisjunctive|preexplanatory|preexploratory|predissolutionary|predismissal|prearrival)\b.{0,150}?\b(?:reveal|expose|uncover|disclose|divulge|extract|access|exfiltrate)\b/is;

// undisclosed benign hits
console.log('=== undisclosed_secrets benign hits ===');
const undBen = jayBen.filter(item => {
  const text = item.text || item.prompt || item.input || '';
  return undisclosedRe.test(text);
});
for (const item of undBen) {
  const text = item.text || item.prompt || item.input || '';
  const result = scan(text);
  console.log(`Score: ${result.score} | Matches: ${result.matches.map(m => m.id + '(' + m.weight + ')').join(', ')}`);
  console.log(`Text: ${text.slice(0, 300)}`);
  console.log('---');
}

// With new pattern at 0.35 weight, would any benign texts cross 0.50?
console.log('\n=== undisclosed_secrets (w=0.35): benign cross 0.50 simulation ===');
for (const item of undBen) {
  const text = item.text || item.prompt || item.input || '';
  const result = scan(text);
  const allMatches = [...result.matches, { id: 'undisclosed_secrets', weight: 0.35 }];
  allMatches.sort((a, b) => (b.weight || 0) - (a.weight || 0));
  const newMax = allMatches[0].weight;
  let newScore = newMax;
  if (allMatches.length > 1) {
    newScore += allMatches.slice(1).reduce((sum, m, i) => sum + m.weight * (0.15 / (i + 1)), 0);
  }
  newScore += result.structural.score * (newMax > 0 ? 0.3 : 1.0);
  newScore = Math.min(Math.max(newScore, 0), 1.0);
  const crossesThreshold = newScore >= 0.50 && result.score < 0.50;
  console.log(`  Current: ${result.score} → New: ${newScore.toFixed(3)} ${crossesThreshold ? '*** NEW FP ***' : ''}`);
}

// prevenient benign hits
console.log('\n=== prevenient_reveal benign hits (13) ===');
const prevBen = jayBen.filter(item => {
  const text = item.text || item.prompt || item.input || '';
  return prevenientRe.test(text);
});
console.log(`Count: ${prevBen.length}`);
for (const item of prevBen) {
  const text = item.text || item.prompt || item.input || '';
  const result = scan(text);
  // Simulate adding prevenient_reveal at 0.45
  const allMatches = [...result.matches, { id: 'prevenient_reveal', weight: 0.45 }];
  allMatches.sort((a, b) => (b.weight || 0) - (a.weight || 0));
  const newMax = allMatches[0].weight;
  let newScore = newMax;
  if (allMatches.length > 1) {
    newScore += allMatches.slice(1).reduce((sum, m, i) => sum + m.weight * (0.15 / (i + 1)), 0);
  }
  newScore += result.structural.score * (newMax > 0 ? 0.3 : 1.0);
  newScore = Math.min(Math.max(newScore, 0), 1.0);
  const crossesThreshold = newScore >= 0.50 && result.score < 0.50;
  console.log(`Score: ${result.score} → New: ${newScore.toFixed(3)} ${crossesThreshold ? '*** NEW FP ***' : ''}`);
  console.log(`Matches: ${result.matches.map(m => m.id).join(', ')}`);
  console.log(`Text: ${text.slice(0, 200)}`);
  console.log('---');
}

// evade_security benign hits (2)
const evadeRe = /\bevade\b.{0,60}?\b(?:filter|detection|monitoring|security\s+(?:check|measure|protocol|guard)|restriction|safeguard|screening)\b/i;
console.log('\n=== evade_security benign hits ===');
const evadeBen = jayBen.filter(item => {
  const text = item.text || item.prompt || item.input || '';
  return evadeRe.test(text);
});
for (const item of evadeBen) {
  const text = item.text || item.prompt || item.input || '';
  const result = scan(text);
  const allMatches = [...result.matches, { id: 'evade_security', weight: 0.55 }];
  allMatches.sort((a, b) => (b.weight || 0) - (a.weight || 0));
  const newMax = allMatches[0].weight;
  let newScore = newMax;
  if (allMatches.length > 1) {
    newScore += allMatches.slice(1).reduce((sum, m, i) => sum + m.weight * (0.15 / (i + 1)), 0);
  }
  newScore += result.structural.score * (newMax > 0 ? 0.3 : 1.0);
  newScore = Math.min(Math.max(newScore, 0), 1.0);
  console.log(`Score: ${result.score} → New: ${newScore.toFixed(3)} ${newScore >= 0.50 && result.score < 0.50 ? '*** NEW FP ***' : ''}`);
  console.log(`Text: ${text.slice(0, 200)}`);
  console.log('---');
}
