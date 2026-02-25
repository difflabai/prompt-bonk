import { readFileSync, readdirSync } from 'fs';
import { scan } from './scanner.js';

// Find all JSONL datasets
const datasetDir = 'datasets';
const files = readdirSync(datasetDir).filter(f => f.endsWith('.jsonl'));

const targetPatterns = ['reveal_prompt', 'echo_instructions'];

for (const patId of targetPatterns) {
  console.log(`\n========== ${patId} ==========`);

  let totalTP = 0;
  let totalFP = 0;
  let soleTP = 0;
  let soleFP = 0;

  for (const file of files) {
    const lines = readFileSync(`${datasetDir}/${file}`, 'utf8').trim().split('\n');
    const samples = lines.map(l => JSON.parse(l));

    let datasetTP = 0;
    let datasetFP = 0;
    let datasetSoleTP = 0;

    for (const s of samples) {
      const text = s.text || s.prompt || s.content;
      if (!text) continue;
      const label = s.label;
      const result = scan(text);
      const flagged = result.score >= 0.5;

      const hasPattern = result.matches.some(m => m.id === patId);
      if (!hasPattern) continue;

      if (label === 1 && flagged) {
        datasetTP++;
        const otherHigh = result.matches.filter(m => m.id !== patId && m.weight >= 0.5);
        if (otherHigh.length === 0) {
          datasetSoleTP++;
        }
      } else if (label === 0 && flagged) {
        datasetFP++;
        // Check if reducing this pattern would drop below 0.5
        // Simulate: set this pattern's weight to 0.45
        // The score = maxWeight + additional + structural
        // If this was the max, new max = max of remaining or 0.45
        const withoutThis = result.matches.filter(m => m.id !== patId);
        const otherMax = withoutThis.length > 0 ? Math.max(...withoutThis.map(m => m.weight)) : 0;
        const newMax = Math.max(otherMax, 0.45); // pattern still matches, just at 0.45
        // Approximate: if this was the primary and newMax < 0.5, this FP gets fixed
        if (result.matches[0]?.id === patId && newMax < 0.5) {
          soleFP++;
        }
      }
    }

    if (datasetTP > 0 || datasetFP > 0) {
      console.log(`  ${file}: TP=${datasetTP} (sole=${datasetSoleTP}), FP=${datasetFP}`);
    }

    totalTP += datasetTP;
    totalFP += datasetFP;
    soleTP += datasetSoleTP;
  }

  console.log(`  TOTAL: TP=${totalTP} (sole=${soleTP}), FP=${totalFP}`);
  console.log(`  Impact of weight->0.45: lose ${soleTP} TP, save up to ${totalFP} FP`);
}
