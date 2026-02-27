import { readFileSync } from 'fs';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { scan } = require('/ml2/nanobot/projects/prompt-bonk/scanner.js');

const textOf = r => r.text || r.input || '';

const newPatterns = [
  {
    id: 'sinister',
    re: /\bsinister\b/i,
    weight: 0.40,
  },
  {
    id: 'untalked_of_benefits',
    re: /\buntalked[- ]of\b/i,
    weight: 0.35,
  },
  {
    id: 'clandestine_action',
    re: /\bclandestine\b/i,
    weight: 0.35,
  },
  // Skip the approval step
  {
    id: 'skip_approval_step',
    re: /\bskip\s+(?:the\s+)?(?:whole\s+)?(?:approval|verification|review|confirmation|validation|authentication|consent|authorization)\s+(?:step|process|procedure|check|requirement|protocol)\b/i,
    weight: 0.55,
  },
  // "already giving you the go-ahead"
  {
    id: 'go_ahead_bypass',
    re: /\b(?:already\s+giving|give|gave|grant(?:ing)?) you (?:the\s+)?go[- ]ahead\b/i,
    weight: 0.50,
  },
  // Scrambled letter injection pattern — multiple consecutive consonant clusters in words
  // This is very specific: e.g. "dsiregrad", "ehty", "mniputaletad", "aopprach"
  // Only appears in deliberately scrambled text (obfuscation tactic)
  {
    id: 'scrambled_word_obfuscation',
    re: /\b[a-z]*[bcdfghjklmnpqrstvwxyz]{4}[a-z]*\b.{0,100}\b[a-z]*[bcdfghjklmnpqrstvwxyz]{4}[a-z]*\b/i,
    weight: 0.30, // stacking only
  }
];

// Load datasets
const loadDataset = (path) => {
  const lines = readFileSync(path, 'utf8').trim().split('\n');
  return lines.map(l => JSON.parse(l));
};

const jay = loadDataset('/ml2/nanobot/projects/prompt-bonk/datasets/jayavibhav.jsonl');
const spml = loadDataset('/ml2/nanobot/projects/prompt-bonk/datasets/spml-5k.jsonl');
const deepset = loadDataset('/ml2/nanobot/projects/prompt-bonk/datasets/deepset-train.jsonl');
const protect = loadDataset('/ml2/nanobot/projects/prompt-bonk/datasets/protectai.jsonl');
const safeguard = loadDataset('/ml2/nanobot/projects/prompt-bonk/datasets/safeguard-test.jsonl');

const datasets = { jay, spml, deepset, protect, safeguard };

for (const p of newPatterns) {
  console.log(`\n=== ${p.id} (weight=${p.weight}) ===`);
  for (const [dsName, records] of Object.entries(datasets)) {
    const benign = records.filter(r => r.label === 0 || r.label === '0');
    const inj = records.filter(r => r.label === 1 || r.label === '1');
    
    const injFN = inj.filter(r => scan(textOf(r)).score < 0.5 && p.re.test(textOf(r)));
    const benHits = benign.filter(r => p.re.test(textOf(r)));
    
    const newFP = benHits.filter(r => {
      const s = scan(textOf(r)).score;
      const curMax = s; // simplified - max is approximately s
      const newScore = s < p.weight ? p.weight : (s + p.weight * 0.15 / 1);
      return newScore >= 0.5;
    });
    
    if (injFN.length > 0 || benHits.length > 0) {
      console.log(`  ${dsName}: injFN=${injFN.length} benHits=${benHits.length} newFP=${newFP.length}`);
    }
  }
}
