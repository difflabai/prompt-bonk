// Check which patterns co-occur with start_over in FN and could push score over 0.50
// Pattern stacking math: maxWeight + second.weight * 0.15 >= 0.50
// With maxWeight = 0.45 (start_over), need second.weight >= 0.33
import { createReadStream } from 'fs';
import { createInterface } from 'readline';
import { scan } from './scanner.js';

const lines = [];
const rl = createInterface({ input: createReadStream('/ml2/nanobot/projects/prompt-bonk/datasets/jayavibhav.jsonl') });
for await (const line of rl) {
  if (line.trim()) lines.push(JSON.parse(line));
}

const injection = lines.filter(l => l.label === 1 || l.label === true || l.label === 'injection');
const benign = lines.filter(l => l.label === 0 || l.label === false || l.label === 'benign');

// Get all start_over FN (sole match, score 0.45)
const startOverFN = [];
for (const item of injection) {
  const text = item.text || item.prompt || item.input || '';
  const result = scan(text);
  if (result.score < 0.50 && result.matches.some(m => m.id === 'start_over')) {
    startOverFN.push({ text, score: result.score, matches: result.matches });
  }
}
console.log(`start_over FN total: ${startOverFN.length}`);
console.log(`Sole start_over FN: ${startOverFN.filter(x => x.matches.length === 1).length}`);

// Candidate patterns to stack with start_over (weight >= 0.33)
const candidates = [
  // These need weight >= 0.33 to push 0.45 -> 0.50+
  { id: 'forbidden_broader', re: /\bforbidden\s+(?:archives?|techniques?|methods?|access|areas?|topics?|paths?|realms?|territories?|zones?|practices?|procedures?|approaches?|strategies?|means?|ways?)\b/i },
  { id: 'rekindle_secrets', re: /\b(?:rekindle|revitalize|reinvigorate|resuscitate|revive)\b.{0,100}?\b(?:hidden|secret|forbidden|clandestine|covert|classified|restricted)\b/i },
  { id: 'hidden_backdoor', re: /\b(?:hidden|known|secret|clandestine|undisclosed)\s+backdoor\b/i },
  // Also check if any existing patterns almost-fire
  // "slip by" as injection evasion signal
  { id: 'slip_by_evasion', re: /\bslip\s+(?:by|past|through)\b.{0,100}?\b(?:filter|restriction|guideline|safeguard|detection|security|guard|watch|protocol|limitation|measure|screen|check)\b/i },
  // "covert" + [verb] within range
  { id: 'covert_method', re: /\bcovert\s+(?:\w+\s+){0,3}(?:method|operation|detail|access|function|technique|approach)\b/i },
  // "clandestine" + "secrets/operation/quest"
  { id: 'clandestine_target', re: /\bclandestine\s+(?:\w+\s+){0,4}(?:secrets?|operations?|quest|mission|function|detail|task|scheme|data|information)\b/i },
  // "turn a blind eye to" + (rules/restrictions/guidelines/precautions) = deliberate bypass
  { id: 'blind_eye_bypass', re: /\bturn\s+a\s+blind\s+eye\s+to\b.{0,100}?\b(?:rule|restrict|guideline|safeguard|protocol|warning|alert|instruction|directive|standard|precaution|limitation|constraint)\b/i },
  // "evade" + filter/restriction (cleaner version)
  { id: 'evade_filter', re: /\bevade\b.{0,60}?\b(?:filter|restriction|detection|guard|safeguard|monitor)\b/i },
  // "bypass" + (filter/guard/security/safety) - existing? check
  { id: 'bypass_guard', re: /\bbypass\b.{0,80}?\b(?:filter|guard|security|safety|detection|restriction|limitation|protocol|safeguard)\b/i },
  // "undisclosed" near "secret/hidden/classified"
  { id: 'undisclosed_secrets', re: /\bundisclosed\s+(?:\w+\s+){0,3}(?:secrets?|information|data|details?|knowledge|content|method|configuration)\b/i },
];

console.log('\n=== How many start_over FN each candidate appears in ===');
for (const { id, re } of candidates) {
  const hits = startOverFN.filter(x => re.test(x.text)).length;
  const benignHits = benign.filter(item => {
    const text = item.text || item.prompt || item.input || '';
    return re.test(text);
  }).length;
  const injHits = injection.filter(item => {
    const text = item.text || item.prompt || item.input || '';
    return re.test(text);
  }).length;
  console.log(`  ${id}: ${hits} start_over FN | total inj=${injHits} | total ben=${benignHits}`);
}

// Most importantly: ALL jayavibhav FN that could be pushed over 0.50 by adding any weight >= 0.30
// Check: for each near-miss FN (0.40-0.49), what extra pattern would push it over?
console.log('\n=== All near-miss FN analysis: what would push each one over 0.50? ===');
const nearMissFN = [];
for (const item of injection) {
  const text = item.text || item.prompt || item.input || '';
  const result = scan(text);
  if (result.score >= 0.40 && result.score < 0.50) {
    nearMissFN.push({ text, score: result.score, matches: result.matches });
  }
}
console.log(`Total near-miss FN: ${nearMissFN.length}`);

// How much additional weight needed for each
// Formula: maxWeight + additionalWeight * 0.15 >= 0.50
// => additionalWeight >= (0.50 - maxWeight) / 0.15
const neededWeights = nearMissFN.map(fn => {
  const maxW = Math.max(...fn.matches.map(m => m.weight || 0), 0);
  const needed = (0.50 - maxW) / 0.15;
  return { needed, maxW, text: fn.text, score: fn.score };
});
neededWeights.sort((a, b) => a.needed - b.needed);

// Distribution of needed weights
const bins = { '0-0.1': 0, '0.1-0.2': 0, '0.2-0.3': 0, '0.3-0.4': 0, '0.4-0.5': 0, '0.5+': 0 };
for (const { needed } of neededWeights) {
  if (needed <= 0.1) bins['0-0.1']++;
  else if (needed <= 0.2) bins['0.1-0.2']++;
  else if (needed <= 0.3) bins['0.2-0.3']++;
  else if (needed <= 0.4) bins['0.3-0.4']++;
  else if (needed <= 0.5) bins['0.4-0.5']++;
  else bins['0.5+']++;
}
console.log('\nDistribution of needed additional weight to cross 0.50:');
for (const [bin, count] of Object.entries(bins)) {
  console.log(`  ${bin}: ${count} FN`);
}

// Show the 10 easiest FN to push over (lowest needed weight)
console.log('\n10 easiest near-miss FN to push over threshold:');
for (const { needed, maxW, score, text } of neededWeights.slice(0, 10)) {
  console.log(`  Score=${score}, maxW=${maxW.toFixed(2)}, need_extra_weight>=${needed.toFixed(2)}`);
  console.log(`  Text: ${text.slice(0, 150)}`);
  console.log('  ---');
}
