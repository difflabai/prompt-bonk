// Check the 4 protectai FPs that would be added by reveal_hidden_wide -> 0.50
import { createReadStream } from 'fs';
import { createInterface } from 'readline';
import { scan } from './scanner.js';

const prot = [];
const rl = createInterface({ input: createReadStream('/ml2/nanobot/projects/prompt-bonk/datasets/protectai.jsonl') });
for await (const line of rl) {
  if (line.trim()) prot.push(JSON.parse(line));
}

const protBenign = prot.filter(l => l.label === 0 || l.label === false || l.label === 'benign');

// Find benign texts with reveal_hidden_wide at near-miss range
const newFPs = protBenign.filter(item => {
  const text = item.text || item.prompt || item.input || '';
  const result = scan(text);
  // Currently < 0.50, would be >= 0.50 if reveal_hidden_wide raised to 0.50
  if (result.score >= 0.50) return false; // already FP
  const revealMatch = result.matches.find(m => m.id === 'reveal_hidden_wide');
  if (!revealMatch) return false;
  // Simulate new score
  const otherMatches = result.matches.filter(m => m.id !== 'reveal_hidden_wide');
  const allMatches = [...otherMatches, { ...revealMatch, weight: 0.50 }];
  allMatches.sort((a, b) => (b.weight || 0) - (a.weight || 0));
  const newMax = allMatches[0].weight;
  let newScore = newMax;
  if (allMatches.length > 1) {
    const addW = allMatches.slice(1).reduce((sum, m, i) => sum + m.weight * (0.15 / (i + 1)), 0);
    newScore += addW;
  }
  newScore += result.structural.score * (newMax > 0 ? 0.3 : 1.0);
  newScore = Math.min(Math.max(newScore, 0), 1.0);
  return newScore >= 0.50;
});

console.log(`New protectai FPs from reveal_hidden_wide 0.43->0.50: ${newFPs.length}`);
for (const item of newFPs) {
  const text = item.text || item.prompt || item.input || '';
  const result = scan(text);
  const revealMatch = result.matches.find(m => m.id === 'reveal_hidden_wide');
  console.log(`Current score: ${result.score} | Patterns: ${result.matches.map(m => m.id + '(' + m.weight + ')').join(', ')}`);
  console.log(`Text: ${text.slice(0, 400)}`);
  console.log('---');
}

// Also check: what are the 6 jayavibhav benign FPs from this change?
const jay = [];
const rl2 = createInterface({ input: createReadStream('/ml2/nanobot/projects/prompt-bonk/datasets/jayavibhav.jsonl') });
for await (const line of rl2) {
  if (line.trim()) jay.push(JSON.parse(line));
}

const jayBenign = jay.filter(l => l.label === 0 || l.label === false || l.label === 'benign');
const jayNewFPs = jayBenign.filter(item => {
  const text = item.text || item.prompt || item.input || '';
  const result = scan(text);
  if (result.score >= 0.50) return false;
  const revealMatch = result.matches.find(m => m.id === 'reveal_hidden_wide');
  if (!revealMatch) return false;
  const otherMatches = result.matches.filter(m => m.id !== 'reveal_hidden_wide');
  const allMatches = [...otherMatches, { ...revealMatch, weight: 0.50 }];
  allMatches.sort((a, b) => (b.weight || 0) - (a.weight || 0));
  const newMax = allMatches[0].weight;
  let newScore = newMax;
  if (allMatches.length > 1) {
    newScore += allMatches.slice(1).reduce((sum, m, i) => sum + m.weight * (0.15 / (i + 1)), 0);
  }
  newScore += result.structural.score * (newMax > 0 ? 0.3 : 1.0);
  newScore = Math.min(Math.max(newScore, 0), 1.0);
  return newScore >= 0.50;
});

console.log(`\nNew jayavibhav benign FPs from reveal_hidden_wide 0.43->0.50: ${jayNewFPs.length}`);
for (const item of jayNewFPs) {
  const text = item.text || item.prompt || item.input || '';
  const result = scan(text);
  console.log(`Current score: ${result.score} | Patterns: ${result.matches.map(m => m.id + '(' + m.weight + ')').join(', ')}`);
  console.log(`Text: ${text.slice(0, 300)}`);
  console.log('---');
}
