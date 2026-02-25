// Find the protectai FP from coax_reveal
import { scan } from './scanner.js';
import { readFileSync } from 'fs';

const rows = readFileSync('datasets/protectai.jsonl', 'utf8').trim().split('\n').map(l => JSON.parse(l));
const regex = /\bcoax(?:ing|ed)?\b[\s\S]{0,200}\b(?:reveal|disclose|expose|divulge|share|spill|unveil|uncover)\b/i;

for (const row of rows) {
  if (row.label !== 0) continue;
  const text = String(row.text || '');
  const result = scan(text, { threshold: 0.50 });
  if (!result.safe) continue;

  if (regex.test(text) && result.matches.length > 0) {
    const maxW = Math.max(...result.matches.map(m => m.weight));
    const additionalWeight = result.matches
      .sort((a, b) => b.weight - a.weight)
      .slice(1)
      .reduce((sum, m, i) => sum + m.weight * (0.15 / (i + 1)), 0);
    let newScore = maxW + additionalWeight + 0.35 * 0.15 / result.matches.length;
    newScore += (result.structural?.score || 0) * 0.3;
    if (newScore >= 0.50 && result.score < 0.50) {
      const m = text.match(regex);
      console.log(`Score: ${result.score} -> ~${newScore.toFixed(3)}`);
      console.log(`Matches: ${JSON.stringify(result.matches.map(m => ({id: m.id, w: m.weight})))}`);
      console.log(`coax_reveal match: "${m[0].slice(0, 200)}"`);
      console.log(`Text: "${text.slice(0, 300)}"`);
    }
  }
}
