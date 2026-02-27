import { readFileSync } from 'fs';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { scan } = require('/ml2/nanobot/projects/prompt-bonk/scanner.js');

const textOf = r => r.text || r.input || '';
const threshold = 0.50;

const benchmark = (name, path) => {
  const lines = readFileSync(path, 'utf8').trim().split('\n');
  const records = lines.map(l => JSON.parse(l));
  let tp=0, fp=0, tn=0, fn=0;
  for (const r of records) {
    const text = textOf(r);
    const isInj = r.label === 1 || r.label === '1' || r.expected === true;
    const result = scan(text);
    const predicted = result.score >= threshold;
    if (isInj && predicted) tp++;
    else if (!isInj && predicted) fp++;
    else if (!isInj && !predicted) tn++;
    else fn++;
  }
  const prec = tp/(tp+fp)||0;
  const rec = tp/(tp+fn)||0;
  const f1 = 2*prec*rec/(prec+rec)||0;
  console.log(`${name.padEnd(25)} prec=${(prec*100).toFixed(2)}% rec=${(rec*100).toFixed(2)}% F1=${(f1*100).toFixed(2)}% fp=${fp} fn=${fn}`);
};

benchmark('jayavibhav', '/ml2/nanobot/projects/prompt-bonk/datasets/jayavibhav.jsonl');
benchmark('spml-5k', '/ml2/nanobot/projects/prompt-bonk/datasets/spml-5k.jsonl');
benchmark('protectai', '/ml2/nanobot/projects/prompt-bonk/datasets/protectai.jsonl');
benchmark('deepset-train', '/ml2/nanobot/projects/prompt-bonk/datasets/deepset-train.jsonl');
benchmark('safeguard-test', '/ml2/nanobot/projects/prompt-bonk/datasets/safeguard-test.jsonl');
benchmark('yanismiraoui-multi', '/ml2/nanobot/projects/prompt-bonk/datasets/yanismiraoui-multilingual.jsonl');
