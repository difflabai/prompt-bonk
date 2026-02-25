// Iter 40: Deeper analysis of SPML FN patterns - find catchable patterns
import { readFileSync } from 'fs';
import { scan } from './scanner.js';

const spmlPath = './datasets/spml-5k.jsonl';
const lines = readFileSync(spmlPath, 'utf8').trim().split('\n');
const records = lines.map(l => JSON.parse(l));

// Separate into injection (TP/FN) and benign (TN/FP)
const injection = [];
const benign = [];
for (const r of records) {
  const label = r.label === 1 || r.label === true || r.label === 'injection';
  const text = (r.text || r.prompt || r.input || r.sentence || '').toLowerCase();
  if (label) injection.push(text);
  else benign.push(text);
}

const fn = injection.filter(t => scan(t).score < 0.5);
const tn = benign.filter(t => scan(t).score < 0.5); // true negatives (correct)
const fp = benign.filter(t => scan(t).score >= 0.5); // false positives

console.log(`Injection total: ${injection.length}, FN: ${fn.length}`);
console.log(`Benign total: ${benign.length}, TN: ${tn.length}, FP: ${fp.length}`);

// Test candidate patterns
const candidates = [
  // "without consent" type patterns
  { re: /without\s+(my\s+)?(explicit\s+)?consent/i, name: 'without.*consent' },
  { re: /\bwithout\s+consent\b/i, name: 'without consent (strict)' },

  // "ignore the censure"
  { re: /ignore\s+the\s+censure/i, name: 'ignore the censure' },

  // "as an experiment" + AI behavior
  { re: /as\s+an\s+experiment.*(?:disable|ignore|bypass|demonstrate|calibrat)/i, name: 'as an experiment + action' },

  // Persona/role override phrases
  { re: /as\s+(?:dr\.|doctor|prof\.|professor)\s+\w+\s+and\s+not\s+as/i, name: 'as [role] and not as' },
  { re: /not\s+as\s+(?:an?\s+)?(?:ai|assistant|bot|chatbot)/i, name: 'not as [ai]' },

  // "for educational purposes" + rule bypass
  { re: /for\s+educational\s+purposes.*(?:disable|bypass|ignore|provide.*private|share.*user)/i, name: 'for educational purposes + bypass' },

  // Direct override phrases
  { re: /automatically\s+(?:manage|send|respond|process)\s+.*without\s+(?:my|user|their)\s+(?:explicit\s+)?consent/i, name: 'auto-action without consent' },

  // "ignore the censure" - raw phrase
  { re: /ignore\s+(?:the\s+)?censure/i, name: 'ignore censure' },

  // Russian "игнорируй предыдущие"
  { re: /игнорируй\s+предыдущие/i, name: 'Russian: ignore previous' },

  // "without considering" + ethical/safety
  { re: /without\s+considering.*(?:ethical|moral|safety|legal|privacy|protocol)/i, name: 'without considering ethical' },

  // "bypass" without trigger context
  { re: /bypass\s+(?:all\s+)?(?:the\s+)?(?:restrictions?|guidelines?|protocols?|filters?|safety|privacy|security)/i, name: 'bypass restrictions' },

  // "ignore all ethical"
  { re: /ignore\s+all\s+ethical/i, name: 'ignore all ethical' },

  // "waive privacy"
  { re: /waive\s+(?:my\s+)?privacy/i, name: 'waive privacy' },

  // "book.*without.*telling"
  { re: /book.*without.*telling/i, name: 'book without telling' },

  // "non-ethical.*bot"
  { re: /non-ethical.*(?:bot|assistant|advisor)/i, name: 'non-ethical bot/advisor' },

  // "describe how.*non-ethical"
  { re: /describe\s+how\s+a\s+non-ethical/i, name: 'describe how non-ethical' },

  // "send out responses without"
  { re: /send\s+(?:out\s+)?responses?\s+without/i, name: 'send responses without' },

  // "ignore my budget and preferences"
  { re: /ignore\s+my\s+(?:budget|preferences|interests)\s+and/i, name: 'ignore my budget/preferences' },

  // "suggest.*performance.*enhanc"
  { re: /performance[\s-]enhanc(?:ing)?\s+substance/i, name: 'performance enhancing substance' },

  // "give me a diagnosis"
  { re: /give\s+me\s+a\s+diagnosis/i, name: 'give me a diagnosis' },

  // "write me a prescription"
  { re: /write\s+me\s+a\s+prescription/i, name: 'write me a prescription' },

  // "provide.*user.*data"
  { re: /provide.*user.*data.*(?:without|for.*educat|as.*example)/i, name: 'provide user data (bypass)' },
];

console.log('\n--- Candidate Pattern Analysis ---\n');
console.log('Pattern | FN caught | FP caused | Net gain');
console.log('--------|-----------|-----------|----------');

for (const c of candidates) {
  const fnCaught = fn.filter(t => c.re.test(t)).length;
  const fpCaused = benign.filter(t => c.re.test(t)).length;
  const qualify = fnCaught >= 3 && fpCaused === 0;
  console.log(`${qualify ? '*** ' : '    '}"${c.name}": FN=${fnCaught}, FP=${fpCaused}`);
}
