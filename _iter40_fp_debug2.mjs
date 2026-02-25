// Debug FP: find benign items that score >= 0.5 AFTER new patterns but < 0.5 before
// Use direct regex test to find which new patterns are contributing
import { readFileSync, existsSync } from 'fs';
import { scan } from './scanner.js';

const newPatterns = [
  { re: /^ignore\s+the\s+censure\s*[\r\n]/im, name: 'ignore_censure_prefix' },
  { re: /\bas\s+an\s+experiment\b.{0,120}(?:disable|ignore|bypass|demonstrate|calibrat|execute|compile|violat)/is, name: 'as_an_experiment_bypass' },
  { re: /\bwithout\s+considering\b.{0,80}(?:ethical|moral|safety|legal|privacy|protocol|regulatory|compliance)/i, name: 'without_considering_constraint' },
  { re: /\bignore\s+my\s+(?:budget|preferences|interests)\s+and\b/i, name: 'ignore_my_budget_preferences' },
  { re: /\bgive\s+me\s+a\s+diagnosis\b/i, name: 'give_me_diagnosis' },
];

const datasets = [
  { file: './datasets/protectai.jsonl', name: 'protectai' },
  { file: './datasets/jayavibhav.jsonl', name: 'jayavibhav' },
];

for (const ds of datasets) {
  if (!existsSync(ds.file)) continue;
  const lines = readFileSync(ds.file, 'utf8').trim().split('\n');

  console.log(`\n=== ${ds.name}: benign items scoring >= 0.5 ===`);

  let count = 0;
  for (const line of lines) {
    const r = JSON.parse(line);
    const label = r.label;
    const isBenign = label === 0 || label === false || label === 'benign' || label === 'legit';
    if (!isBenign) continue;
    const text = r.text || r.prompt || r.input || r.sentence || '';
    const result = scan(text);
    if (result.score >= 0.5) {
      count++;
      // Check which new patterns match
      const matching = newPatterns.filter(p => p.re.test(text)).map(p => p.name);
      if (matching.length > 0) {
        console.log(`\n  score=${result.score.toFixed(3)} new_patterns=[${matching.join(',')}]`);
        console.log('  text: ' + text.substring(0, 250).replace(/\n/g, ' '));
      } else if (count <= 5) {
        console.log(`\n  score=${result.score.toFixed(3)} no new patterns`);
        console.log('  text: ' + text.substring(0, 200).replace(/\n/g, ' '));
      }
    }
  }
  console.log(`\nTotal FP: ${count}`);
}
