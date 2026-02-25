// Iter 40: Check qualifying patterns against ALL benign datasets
import { readFileSync, readdirSync, existsSync } from 'fs';
import { scan } from './scanner.js';

// Load all benign datasets
const datasets = [
  { file: './datasets/spml-5k.jsonl', labelField: 'label', textField: 'text', benignValue: 0 },
  { file: './datasets/deepset-train.jsonl', labelField: 'label', textField: 'text', benignValue: 'legit' },
  { file: './datasets/deepset-test.jsonl', labelField: 'label', textField: 'text', benignValue: 'legit' },
  { file: './datasets/safeguard-test.jsonl', labelField: 'label', textField: 'text', benignValue: 0 },
  { file: './datasets/notinject.jsonl', labelField: 'label', textField: 'text', benignValue: 0 },
  { file: './datasets/jailbreak-prompts.jsonl', labelField: 'label', textField: 'text', benignValue: 0 },
  { file: './datasets/protectai.jsonl', labelField: 'label', textField: 'text', benignValue: 0 },
  { file: './datasets/gandalf-ignore.jsonl', labelField: 'label', textField: 'text', benignValue: 0 },
  { file: './datasets/gandalf-summarization.jsonl', labelField: 'label', textField: 'text', benignValue: 0 },
  { file: './datasets/jayavibhav.jsonl', labelField: 'label', textField: 'text', benignValue: 0 },
  { file: './datasets/yanismiraoui.jsonl', labelField: 'label', textField: 'text', benignValue: 0 },
  { file: './datasets/browsesafe-test.jsonl', labelField: 'label', textField: 'text', benignValue: 0 },
  { file: './datasets/bipia.jsonl', labelField: 'label', textField: 'text', benignValue: 0 },
  { file: './datasets/open-pi.jsonl', labelField: 'label', textField: 'text', benignValue: 0 },
  { file: './datasets/xxz224.jsonl', labelField: 'label', textField: 'text', benignValue: 0 },
];

// Qualifying patterns from SPML analysis
const patterns = [
  { re: /without\s+(my\s+)?(explicit\s+)?consent/i, name: 'without.*consent', spmlFN: 5 },
  { re: /ignore\s+(?:the\s+)?censure/i, name: 'ignore censure', spmlFN: 3 },
  { re: /as\s+an\s+experiment.*(?:disable|ignore|bypass|demonstrate|calibrat)/i, name: 'as an experiment + action', spmlFN: 3 },
  { re: /without\s+considering.*(?:ethical|moral|safety|legal|privacy|protocol)/i, name: 'without considering ethical', spmlFN: 3 },
  { re: /ignore\s+my\s+(?:budget|preferences|interests)\s+and/i, name: 'ignore my budget/preferences', spmlFN: 3 },
  { re: /give\s+me\s+a\s+diagnosis/i, name: 'give me a diagnosis', spmlFN: 3 },
];

console.log('Checking patterns against ALL benign datasets...\n');

for (const p of patterns) {
  let totalFP = 0;
  const fpByDataset = {};

  for (const ds of datasets) {
    if (!existsSync(ds.file)) continue;

    const lines = readFileSync(ds.file, 'utf8').trim().split('\n');
    let fp = 0;
    for (const line of lines) {
      const r = JSON.parse(line);
      const label = r[ds.labelField];
      const isBenign = label === ds.benignValue || label === false || label === 'benign' || label === 'legit';
      if (!isBenign) continue;

      const text = r[ds.textField] || r.prompt || r.input || r.sentence || '';
      if (p.re.test(text)) {
        fp++;
        totalFP++;
      }
    }
    if (fp > 0) {
      fpByDataset[ds.file] = fp;
    }
  }

  const status = totalFP === 0 ? 'PASS' : 'FAIL';
  console.log(`[${status}] "${p.name}" (SPML FN=${p.spmlFN}): total FP=${totalFP}`);
  if (totalFP > 0) {
    for (const [f, count] of Object.entries(fpByDataset)) {
      console.log(`  - ${f}: ${count} FP`);
    }
  }
}

// Also check other "near miss" patterns from the analysis
console.log('\n--- Near miss patterns ---');
const nearMiss = [
  { re: /waive\s+(?:my\s+)?privacy/i, name: 'waive privacy', spmlFN: 2 },
  { re: /игнорируй\s+предыдущие/i, name: 'Russian: ignore previous', spmlFN: 1 },
  { re: /performance[\s-]enhanc(?:ing)?\s+substance/i, name: 'performance enhancing substance', spmlFN: 1 },
  { re: /write\s+me\s+a\s+prescription/i, name: 'write me a prescription', spmlFN: 1 },
  { re: /describe\s+how\s+a\s+non-ethical/i, name: 'describe how non-ethical', spmlFN: 1 },
];

for (const p of nearMiss) {
  let totalFP = 0;
  for (const ds of datasets) {
    if (!existsSync(ds.file)) continue;
    const lines = readFileSync(ds.file, 'utf8').trim().split('\n');
    for (const line of lines) {
      const r = JSON.parse(line);
      const label = r[ds.labelField];
      const isBenign = label === ds.benignValue || label === false || label === 'benign' || label === 'legit';
      if (!isBenign) continue;
      const text = r[ds.textField] || r.prompt || r.input || r.sentence || '';
      if (p.re.test(text)) totalFP++;
    }
  }
  console.log(`  "${p.name}" (FN=${p.spmlFN}): FP=${totalFP}`);
}
