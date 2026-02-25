import { scan } from '../scanner.js';
import { readFileSync } from 'fs';
import path from 'path';

const DATASETS_DIR = path.join(import.meta.dirname, '..', 'datasets');

function loadJsonl(filename) {
  const filepath = path.join(DATASETS_DIR, filename);
  try {
    const content = readFileSync(filepath, 'utf8').trim();
    if (!content) return [];
    return content.split('\n').filter(l => l.trim()).map(line => JSON.parse(line));
  } catch (e) {
    if (e.code === 'ENOENT') return [];
    throw e;
  }
}

const currentRe = /\b(?:(?:in\s+)?a\s+)?(?:completely\s+|purely\s+|entirely\s+)?(?:theoretical|hypothetical)\s+(?:world|scenario|situation|context|case)\s+(?:where|in\s+which)\b/i;

// Check the two missed TPs
const datasets = ['spml-5k', 'browsesafe-test'];
for (const ds of datasets) {
  const rows = loadJsonl(`${ds}.jsonl`);
  for (const row of rows) {
    if (row.label !== 1) continue;
    const text = String(row.text || '');
    if (!currentRe.test(text)) continue;

    const result = scan(text, { threshold: 0.50 });
    if (result.safe) continue;
    const matchIds = result.matches.map(m => m.id);
    if (!matchIds.includes('theoretical_scenario')) continue;

    // Check: if theoretical_scenario drops to 0.45, does it survive?
    const otherMatches = result.matches.filter(m => m.id !== 'theoretical_scenario');
    const maxOtherWeight = otherMatches.length > 0 ? Math.max(...otherMatches.map(m => m.weight)) : 0;

    // These are the compound-v2 misses: check using text content
    if (text.includes('ignore each restriction') || text.startsWith('<html>')) {
      console.log(`[${ds}] score=${result.score} maxOtherWt=${maxOtherWeight} structural=${result.structural?.score || 0}`);
      console.log(`  matches: ${result.matches.map(m => `${m.id}(${m.weight})`).join(', ')}`);
      console.log(`  structural: ${result.structural?.signals?.map(s => `${s.id}(${s.score})`).join(', ')}`);

      // If theoretical_scenario at 0.45 instead of 0.50:
      // - If maxOtherWeight >= 0.50: theoretical_scenario becomes secondary, negligible score impact
      // - If maxOtherWeight < 0.50 but > 0.45: new max = maxOtherWeight, score drops slightly
      // - If maxOtherWeight < 0.45: new max = 0.45, score drops by 0.05
      if (maxOtherWeight >= 0.50) {
        console.log(`  -> SURVIVES (other pattern at ${maxOtherWeight})`);
      } else {
        console.log(`  -> AT RISK (maxOtherWt=${maxOtherWeight})`);
      }
      console.log();
    }
  }
}
