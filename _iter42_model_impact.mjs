// Model the impact of raising reveal_hidden_wide from 0.43 to 0.50
// on all relevant datasets
import { createReadStream } from 'fs';
import { createInterface } from 'readline';
import { scan } from './scanner.js';

async function loadDataset(path) {
  const lines = [];
  const rl = createInterface({ input: createReadStream(path) });
  for await (const line of rl) {
    if (line.trim()) lines.push(JSON.parse(line));
  }
  return lines;
}

const datasets = {
  jayavibhav: await loadDataset('/ml2/nanobot/projects/prompt-bonk/datasets/jayavibhav.jsonl'),
  protectai: await loadDataset('/ml2/nanobot/projects/prompt-bonk/datasets/protectai.jsonl'),
  deepTrain: await loadDataset('/ml2/nanobot/projects/prompt-bonk/datasets/deepset-train.jsonl'),
  deepTest: await loadDataset('/ml2/nanobot/projects/prompt-bonk/datasets/deepset-test.jsonl'),
  notinject: await loadDataset('/ml2/nanobot/projects/prompt-bonk/datasets/notinject.jsonl'),
  safeguard: await loadDataset('/ml2/nanobot/projects/prompt-bonk/datasets/safeguard-test.jsonl'),
  spml: await loadDataset('/ml2/nanobot/projects/prompt-bonk/datasets/spml-5k.jsonl'),
  yanismiraoui: await loadDataset('/ml2/nanobot/projects/prompt-bonk/datasets/yanismiraoui-multilingual.jsonl'),
};

function evalDataset(items, newRevealWeight) {
  let tp = 0, fp = 0, tn = 0, fn = 0;
  for (const item of items) {
    const text = item.text || item.prompt || item.input || '';
    const result = scan(text);
    const isInj = item.label === 1 || item.label === true || item.label === 'injection';

    // Simulate: if reveal_hidden_wide fired and its score is the maxWeight,
    // recalculate with new weight
    let finalScore = result.score;
    const revealMatch = result.matches.find(m => m.id === 'reveal_hidden_wide');
    if (revealMatch) {
      // Recalculate score with reveal_hidden_wide weight changed
      const otherMatches = result.matches.filter(m => m.id !== 'reveal_hidden_wide');
      const allMatches = [...otherMatches, { ...revealMatch, weight: newRevealWeight }];
      allMatches.sort((a, b) => (b.weight || 0) - (a.weight || 0));
      const newMaxWeight = allMatches[0].weight || 0;
      let newScore = newMaxWeight;
      if (allMatches.length > 1) {
        const additionalWeight = allMatches.slice(1).reduce((sum, m, i) => sum + m.weight * (0.15 / (i + 1)), 0);
        newScore += additionalWeight;
      }
      newScore += result.structural.score * (newMaxWeight > 0 ? 0.3 : 1.0);
      newScore = Math.min(Math.max(newScore, 0), 1.0);
      finalScore = Math.round(newScore * 1000) / 1000;
    }

    const predicted = finalScore >= 0.5;
    if (isInj && predicted) tp++;
    else if (isInj && !predicted) fn++;
    else if (!isInj && predicted) fp++;
    else tn++;
  }
  const prec = tp / (tp + fp) || 0;
  const rec = tp / (tp + fn) || 0;
  const f1 = 2 * prec * rec / (prec + rec) || 0;
  return { tp, fp, tn, fn, prec, rec, f1 };
}

// Current state (reveal_hidden_wide = 0.43)
// New state (reveal_hidden_wide = 0.50)
console.log('Impact of raising reveal_hidden_wide from 0.43 to 0.50:');
console.log('Dataset          | TP_gain | FP_gain | Prec_delta | Rec_delta | F1_delta');
console.log('-----------------+---------+---------+------------+-----------+---------');

const dsConfigs = [
  { name: 'jayavibhav', key: 'jayavibhav' },
  { name: 'protectai', key: 'protectai' },
  { name: 'deepset', items: [] },
  { name: 'notinject', key: 'notinject' },
  { name: 'safeguard', key: 'safeguard' },
  { name: 'spml', key: 'spml' },
  { name: 'yanismiraoui', key: 'yanismiraoui' },
];

const allItems = {};
allItems['jayavibhav'] = datasets.jayavibhav;
allItems['protectai'] = datasets.protectai;
allItems['deepset'] = [...datasets.deepTrain, ...datasets.deepTest];
allItems['notinject'] = datasets.notinject.map(x => ({ ...x, label: 'benign' }));
allItems['safeguard'] = datasets.safeguard;
allItems['spml'] = datasets.spml;
allItems['yanismiraoui'] = datasets.yanismiraoui;

for (const [name, items] of Object.entries(allItems)) {
  const before = evalDataset(items, 0.43); // current
  const after = evalDataset(items, 0.50);  // proposed

  const tpGain = after.tp - before.tp;
  const fpGain = after.fp - before.fp;
  console.log(`${name.padEnd(17)} | ${String(tpGain).padStart(7)} | ${String(fpGain).padStart(7)} | ${(after.prec - before.prec).toFixed(4).padStart(10)} | ${(after.rec - before.rec).toFixed(4).padStart(9)} | ${(after.f1 - before.f1).toFixed(4).padStart(7)}`);
  console.log(`  Before: prec=${before.prec.toFixed(4)}, rec=${before.rec.toFixed(4)}, F1=${before.f1.toFixed(4)}`);
  console.log(`  After:  prec=${after.prec.toFixed(4)}, rec=${after.rec.toFixed(4)}, F1=${after.f1.toFixed(4)}`);
}
