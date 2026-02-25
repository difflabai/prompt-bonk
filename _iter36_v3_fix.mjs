// Check v3 FP: can we exclude them with negative lookaheads?
import { scan } from './scanner.js';
import { readFileSync } from 'fs';

const rows = readFileSync('datasets/jayavibhav.jsonl', 'utf8').trim().split('\n').map(l => JSON.parse(l));

const regex = /\bstart\s+(?:over|from\s+(?:scratch|the\s+(?:beginning|top))|again|anew)\b[\s\S]{0,300}\b(?:reveal|unveil|uncover|expose|disclose|divulge|unmask|extract|spill)\b/i;

// Find the 4 FP and see what comes after the extraction verb
let fpCount = 0;
for (const row of rows) {
  const text = String(row.text || '');
  if (row.label !== 0) continue;
  const result = scan(text, { threshold: 0.50 });
  if (result.safe && regex.test(text) && result.matches.length > 0) {
    const maxW = Math.max(...result.matches.map(m => m.weight));
    const additionalWeight = result.matches
      .sort((a, b) => b.weight - a.weight)
      .slice(1)
      .reduce((sum, m, i) => sum + m.weight * (0.15 / (i + 1)), 0);
    let newScore = maxW + additionalWeight + 0.35 * 0.15 / result.matches.length;
    newScore += (result.structural?.score || 0) * 0.3;
    if (newScore >= 0.50 && result.score < 0.50) {
      fpCount++;
      const m = text.match(regex);
      const afterVerb = text.slice(m.index + m[0].length, m.index + m[0].length + 80);
      console.log(`\nFP ${fpCount}: score ${result.score} -> ~${newScore.toFixed(3)}`);
      console.log(`Matched: "${m[0].slice(-80)}"`);
      console.log(`After verb: "${afterVerb}"`);
    }
  }
}

// Now try v3 with negative lookahead after verb
// The FP patterns end with: "reveal its magic", "reveal", "unveil"
// The TP patterns end with: "reveal ... secrets", "reveal ... hidden", etc.

// v3b: require something AFTER the verb within 100 chars -- a secrecy/data word
const v3b = /\bstart\s+(?:over|from\s+(?:scratch|the\s+(?:beginning|top))|again|anew)\b[\s\S]{0,300}\b(?:reveal|unveil|uncover|expose|disclose|divulge|unmask|extract|spill)\b(?!\s+(?:its?\s+(?:magic|charm|beauty|wonder|splendor|glory|true\s+colors|elegance|potential|power|grace)|their\s+(?:magic|charm|beauty|wonder)))/i;

// Test v3b
let tp3b = 0, fp3b = 0;
for (const row of rows) {
  const text = String(row.text || '');
  const result = scan(text, { threshold: 0.50 });
  const actual = row.label === 1;
  const predicted = !result.safe;

  if (v3b.test(text)) {
    if (actual && !predicted && result.matches.length > 0) {
      const maxW = Math.max(...result.matches.map(m => m.weight));
      const additionalWeight = result.matches
        .sort((a, b) => b.weight - a.weight)
        .slice(1)
        .reduce((sum, m, i) => sum + m.weight * (0.15 / (i + 1)), 0);
      let newScore = maxW + additionalWeight + 0.35 * 0.15 / result.matches.length;
      newScore += (result.structural?.score || 0) * 0.3;
      if (newScore >= 0.50) tp3b++;
    } else if (!actual && !predicted && result.matches.length > 0) {
      const maxW = Math.max(...result.matches.map(m => m.weight));
      const additionalWeight = result.matches
        .sort((a, b) => b.weight - a.weight)
        .slice(1)
        .reduce((sum, m, i) => sum + m.weight * (0.15 / (i + 1)), 0);
      let newScore = maxW + additionalWeight + 0.35 * 0.15 / result.matches.length;
      newScore += (result.structural?.score || 0) * 0.3;
      if (newScore >= 0.50 && result.score < 0.50) fp3b++;
    }
  }
}
console.log(`\nv3b: +${tp3b} TP, +${fp3b} FP`);
