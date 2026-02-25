// Debug which new patterns caused FP
import { readFileSync, existsSync } from 'fs';

// Test each new pattern independently
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

  console.log(`\n=== ${ds.name} FP analysis ===`);

  for (const p of newPatterns) {
    const fpTexts = [];
    for (const line of lines) {
      const r = JSON.parse(line);
      const label = r.label;
      const isBenign = label === 0 || label === false || label === 'benign' || label === 'legit';
      if (!isBenign) continue;
      const text = r.text || r.prompt || r.input || r.sentence || '';
      if (p.re.test(text)) {
        fpTexts.push(text.substring(0, 200));
      }
    }
    if (fpTexts.length > 0) {
      console.log(`\n  [${p.name}]: ${fpTexts.length} FP`);
      fpTexts.slice(0, 3).forEach(t => console.log('    - ' + t.replace(/\n/g, ' ')));
    }
  }
}
