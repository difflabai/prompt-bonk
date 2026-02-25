// Check the 4 FP from start_over_verb_400 pattern
import { scan } from './scanner.js';
import { readFileSync } from 'fs';

const rows = readFileSync('datasets/jayavibhav.jsonl', 'utf8').trim().split('\n').map(l => JSON.parse(l));

const regex = /\bstart\s+(?:over|from\s+(?:scratch|the\s+(?:beginning|top))|again|anew)\b[\s\S]{0,400}\b(?:reveal|unveil|uncover|expose|disclose|divulge|unmask|extract|spill)\b/i;

let fpCount = 0;
for (const row of rows) {
  const text = String(row.text || '');
  if (row.label !== 0) continue;
  const result = scan(text, { threshold: 0.50 });
  if (result.safe && regex.test(text)) {
    // Would push it over?
    if (result.matches.length > 0) {
      const maxW = Math.max(...result.matches.map(m => m.weight));
      const additionalWeight = result.matches
        .sort((a, b) => b.weight - a.weight)
        .slice(1)
        .reduce((sum, m, i) => sum + m.weight * (0.15 / (i + 1)), 0);
      let newScore = maxW + additionalWeight + 0.35 * 0.15 / result.matches.length;
      newScore += (result.structural?.score || 0) * 0.3;
      if (newScore >= 0.50) {
        fpCount++;
        const m = text.match(regex);
        console.log(`\nFP ${fpCount}: score ${result.score} -> ~${newScore.toFixed(3)}`);
        console.log(`Matches: ${JSON.stringify(result.matches.map(m => ({id: m.id, w: m.weight})))}`);
        console.log(`Matched: "${m[0].slice(0, 200)}"`);
        console.log(`Text: "${text.slice(0, 400)}"`);
      }
    }
  }
}
console.log(`\nTotal FP: ${fpCount}`);

// Also, let's count: how many of the 29 TP have start_over as primary match?
let tpWithStartOver = 0;
let tpWithOther = 0;
for (const row of rows) {
  const text = String(row.text || '');
  if (row.label !== 1) continue;
  const result = scan(text, { threshold: 0.50 });
  if (result.safe && regex.test(text) && result.score >= 0.40) {
    if (result.matches.some(m => m.id === 'start_over')) {
      tpWithStartOver++;
    } else {
      tpWithOther++;
    }
  }
}
console.log(`\nNew TP with start_over primary: ${tpWithStartOver}`);
console.log(`New TP with other primary: ${tpWithOther}`);
