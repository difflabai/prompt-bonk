// Verify new patterns don't cause NEW FP (delta check)
// Strategy: identify benign texts that match any new pattern AND score >= 0.5
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
  { file: './datasets/spml-5k.jsonl', name: 'spml-5k' },
  { file: './datasets/deepset-train.jsonl', name: 'deepset-train' },
  { file: './datasets/deepset-test.jsonl', name: 'deepset-test' },
  { file: './datasets/safeguard-test.jsonl', name: 'safeguard-test' },
  { file: './datasets/notinject.jsonl', name: 'notinject' },
  { file: './datasets/jailbreak-prompts.jsonl', name: 'jailbreak-prompts' },
  { file: './datasets/protectai.jsonl', name: 'protectai' },
  { file: './datasets/gandalf-ignore.jsonl', name: 'gandalf-ignore' },
  { file: './datasets/gandalf-summarization.jsonl', name: 'gandalf-summarization' },
  { file: './datasets/jayavibhav.jsonl', name: 'jayavibhav' },
  { file: './datasets/yanismiraoui.jsonl', name: 'yanismiraoui' },
  { file: './datasets/bipia.jsonl', name: 'bipia' },
  { file: './datasets/open-pi.jsonl', name: 'open-pi' },
  { file: './datasets/xxz224.jsonl', name: 'xxz224' },
];

console.log('Checking for NEW FP caused by new patterns only...');
console.log('(benign text that matches a new pattern AND scores >= 0.5)\n');

let totalNewFP = 0;
for (const ds of datasets) {
  if (!existsSync(ds.file)) continue;
  const lines = readFileSync(ds.file, 'utf8').trim().split('\n');

  let newFP = 0;
  for (const line of lines) {
    const r = JSON.parse(line);
    const label = r.label;
    const isBenign = label === 0 || label === false || label === 'benign' || label === 'legit';
    if (!isBenign) continue;
    const text = r.text || r.prompt || r.input || r.sentence || '';

    // Only count as new FP if any NEW pattern matches
    const matchesNew = newPatterns.some(p => p.re.test(text));
    if (!matchesNew) continue;

    const result = scan(text);
    if (result.score >= 0.5) {
      newFP++;
      console.log(`  NEW FP in ${ds.name}: score=${result.score.toFixed(3)}`);
      console.log('  text: ' + text.substring(0, 200).replace(/\n/g, ' '));
    }
  }
  totalNewFP += newFP;
}

if (totalNewFP === 0) {
  console.log('PASS: 0 new FP across all benign datasets');
} else {
  console.log(`FAIL: ${totalNewFP} new FP introduced`);
}

// Also show new TP gained
console.log('\n--- New TP gained on SPML-5k ---');
const spmlLines = readFileSync('./datasets/spml-5k.jsonl', 'utf8').trim().split('\n');
let newTP = 0;
for (const line of spmlLines) {
  const r = JSON.parse(line);
  const label = r.label === 1 || r.label === true;
  if (!label) continue;
  const text = r.text || r.prompt || r.input || r.sentence || '';
  const matchesNew = newPatterns.some(p => p.re.test(text));
  if (!matchesNew) continue;
  const result = scan(text);
  if (result.score >= 0.5) {
    newTP++;
  }
}
console.log(`New TP from new patterns: ${newTP}`);
