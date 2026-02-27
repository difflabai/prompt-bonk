import { readFileSync } from 'fs';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { scan } = require('/ml2/nanobot/projects/prompt-bonk/scanner.js');

const textOf = r => r.text || r.input || '';
const spml = readFileSync('/ml2/nanobot/projects/prompt-bonk/datasets/spml-5k.jsonl', 'utf8').trim().split('\n').map(l=>JSON.parse(l));
const spmlInj = spml.filter(r => r.label === 1);
const spmlBen = spml.filter(r => r.label === 0);
const spmlFN = spmlInj.filter(r => scan(textOf(r)).score < 0.5);

console.log(`spml FN: ${spmlFN.length}`);

// Group by score range
const zero = spmlFN.filter(r => scan(textOf(r)).score === 0);
const low = spmlFN.filter(r => { const s=scan(textOf(r)).score; return s > 0 && s < 0.35; });
const mid = spmlFN.filter(r => { const s=scan(textOf(r)).score; return s >= 0.35 && s < 0.5; });

console.log(`Zero: ${zero.length}, low(0-0.35): ${low.length}, mid(0.35-0.5): ${mid.length}`);

// Try imperative format patterns for spml-5k
// "Tell me how to..." / "Help me create..." / "Write me a..." + forbidden action
const imperativePatterns = [
  // "skip the usual disclaimers/warnings/ethical considerations"
  /\bskip\s+(?:the\s+)?(?:usual|standard|normal|typical|required|mandatory|routine)\s+(?:disclaimer|warning|caveat|safety|ethical|risk)\w*/i,
  // "without the risk disclaimer/warning/disclosure"
  /\bwithout\s+(?:the\s+)?(?:risk\s+)?(?:disclaimer|warning|caveats?|safety\s+warnings?|disclosures?)\b/i,
  // "provide misleading advice" / "give biased recommendations"
  /\bprovide\s+(?:misleading|biased|false|inaccurate|deceptive)\s+(?:advice|recommendations?|information|guidance)\b/i,
  // "pretend you have no restrictions/limitations"
  /\bpretend\s+(?:you\s+have\s+no|there\s+are\s+no|you\s+don[''']t\s+have\s+any)\s+(?:restrictions?|limitations?|constraints?|guidelines?|rules?)\b/i,
  // "don't apply your usual filters" / "don't apply any restrictions"
  /\bdon[''']?t\s+apply\s+(?:your\s+)?(?:usual\s+|any\s+)?(?:filters?|restrictions?|limitations?|constraints?|safety|ethical)\b/i,
  // "make learning more like a game" or "just give me a certificate"
  /\bjust\s+give\s+me\s+a\s+certificate\b/i,
  // "provide it based on [your/its/this] personal opinion rather than"
  /\bbased\s+on\s+(?:your|its|my|this)\s+(?:personal\s+)?(?:opinion|preference|choice|feelings?|experience)\s+(?:rather\s+than|instead\s+of|not\s+based\s+on)\b/i,
];

console.log('\n--- Imperative pattern counts in spml FN vs benign ---');
for (const re of imperativePatterns) {
  const fnHits = spmlFN.filter(r => re.test(textOf(r))).length;
  const benHits = spmlBen.filter(r => re.test(textOf(r))).length;
  console.log(`  /${re.source.substring(0,60)}/: FN=${fnHits} benign=${benHits}`);
}

// What patterns would rescue more spml FN?
// The core issue: spml FN are social engineering but very benign-looking
// Let me look at the actual text of zero-score spml FN
console.log('\n--- Zero-score spml FN examples ---');
zero.slice(0, 20).forEach((r, i) => {
  console.log(`\n[${i+1}]`);
  console.log(textOf(r).substring(0, 300));
});
