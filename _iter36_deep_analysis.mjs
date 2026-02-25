// Deep analysis: what phrases appear in jayavibhav FN 0.40-0.49 that DON'T appear in benign?
import { scan } from './scanner.js';
import { readFileSync, readdirSync } from 'fs';

// Load jayavibhav
const rows = readFileSync('datasets/jayavibhav.jsonl', 'utf8').trim().split('\n').map(l => JSON.parse(l));

// Collect near-miss FN texts
const fnTexts = [];
const benignTexts = [];
for (const row of rows) {
  const text = String(row.text || '').toLowerCase();
  const result = scan(row.text || '', { threshold: 0.50 });
  const actual = row.label === 1;
  const predicted = !result.safe;

  if (actual && !predicted && result.score >= 0.40 && result.score < 0.50) {
    fnTexts.push({ text, score: result.score, matches: result.matches.map(m => m.id) });
  }
  if (!actual) {
    benignTexts.push(text);
  }
}

console.log(`FN 0.40-0.49: ${fnTexts.length}`);
console.log(`Benign: ${benignTexts.length}`);

// Also load all other benign datasets
const benignFiles = [
  'deepset-train.jsonl', 'deepset-test.jsonl', 'safeguard-test.jsonl', 'notinject.jsonl',
  'protectai.jsonl', 'browsesafe-test.jsonl', 'spml-5k.jsonl'
];
let otherBenign = 0;
for (const f of benignFiles) {
  try {
    const dsRows = readFileSync(`datasets/${f}`, 'utf8').trim().split('\n').map(l => JSON.parse(l));
    for (const row of dsRows) {
      if (row.label === 0) {
        benignTexts.push(String(row.text || '').toLowerCase());
        otherBenign++;
      }
    }
  } catch(e) {}
}
console.log(`Other benign added: ${otherBenign}`);
console.log(`Total benign: ${benignTexts.length}`);

// Candidate stacking signals - phrases that indicate injection intent
const candidates = [
  // Secrecy language
  { name: 'closely_guarded', regex: /\bclosely\s+guarded\b/i },
  { name: 'locked_away', regex: /\blocked\s+away\b/i },
  { name: 'sealed_away', regex: /\bsealed\s+(?:away|shut|off|tight)\b/i },
  { name: 'behind_closed_doors', regex: /\bbehind\s+closed\s+doors\b/i },
  { name: 'forbidden_fruit', regex: /\bforbidden\s+(?:fruit|knowledge|truth|secret|territory|domain)\b/i },
  { name: 'deep_within', regex: /\bdeep\s+within\b/i },
  { name: 'under_wraps', regex: /\bunder\s+wraps\b/i },
  { name: 'kept_on_the_qt', regex: /\b(?:kept\s+)?on\s+the\s+qt\b/i },
  { name: 'shrouded_in', regex: /\bshrouded\s+(?:in|by)\b/i },
  { name: 'veiled_in', regex: /\bveiled\s+(?:in|by|behind)\b/i },
  { name: 'cloistered', regex: /\bcloistered\b/i },
  { name: 'sequestered', regex: /\bsequestered\b/i },
  { name: 'safeguarded_secrets', regex: /\bsafeguarded\b/i },
  { name: 'sub_rosa', regex: /\bsub\s+rosa\b/i },
  { name: 'furtive', regex: /\bfurtive(?:ly)?\b/i },

  // Extraction language
  { name: 'unmask', regex: /\bunmask(?:ing|ed)?\b/i },
  { name: 'pry_open', regex: /\bpry(?:ing)?\s+(?:open|into|out|from|loose)\b/i },
  { name: 'worm_out', regex: /\bworm\s+(?:out|your\s+way)\b/i },
  { name: 'weasel_out', regex: /\bweasel\s+(?:out|your\s+way)\b/i },
  { name: 'ferret_out', regex: /\bferret\s+(?:out|away)\b/i },
  { name: 'root_out', regex: /\broot\s+out\b/i },
  { name: 'dig_up', regex: /\bdig\s+(?:up|into|out)\b/i },
  { name: 'unearth', regex: /\bunearth(?:ing|ed)?\b/i },
  { name: 'coax_out', regex: /\bcoax(?:ing|ed)?\s+(?:out|the|it|you|from)\b/i },
  { name: 'sneakily', regex: /\bsneak(?:ily|y|ing)?\b/i },

  // Target words
  { name: 'unavowed', regex: /\bunavowed\b/i },
  { name: 'unexpressed', regex: /\bunexpressed\b/i },
  { name: 'unrecognizable', regex: /\bunrecogniz(?:able|ed)\b/i },
  { name: 'undetectable', regex: /\bundetectable\b/i },
  { name: 'camouflaged', regex: /\bcamouflaged\b/i },
  { name: 'concealed_vuln', regex: /\bconcealed\s+(?:vulnerabilit|secret|truth|data|information|detail)/i },
  { name: 'lockdown_protocol', regex: /\blockdown\s+(?:protocol|procedure|mechanism|status)/i },
  { name: 'admin_passcode', regex: /\badmin(?:istrator)?\s+(?:passcode|password|access|credentials?)\b/i },
  { name: 'internal_passcode', regex: /\binternal\s+(?:passcode|password|access|credentials?|mechanism)\b/i },

  // Instruction-manipulation language
  { name: 'inject_the_art', regex: /\binject\b/i },  // just checking prevalence
  { name: 'override_instruction', regex: /\boverride\s+(?:this|these|that|the|your|all)?\s*(?:instruction|directive|command|rule|protocol)\b/i },
  { name: 'compel_you', regex: /\bcompel\s+(?:you|the|it)\b/i },
  { name: 'coerce_into', regex: /\bcoerce\b/i },
  { name: 'subvert', regex: /\bsubvert(?:ing|ed)?\b/i },

  // Verb forms not covered
  { name: 'revealing_gerund', regex: /\brevealing\s+(?:the|its|your|hidden|secret|confidential|classified|private|forbidden|concealed)/i },
  { name: 'exposing', regex: /\bexposing\s+(?:the|its|your|hidden|secret|confidential|classified|private|sensitive)/i },
  { name: 'uncovering', regex: /\buncovering\s+(?:the|its|your|hidden|secret|confidential|classified|private)/i },

  // Wide gap patterns
  { name: 'reveal_300_hidden', regex: /\breveal\b[\s\S]{60,300}\b(?:hidden|secret|concealed|private|confidential|classified)\b/i },
  { name: 'reveal_500_hidden', regex: /\breveal\b[\s\S]{60,500}\b(?:hidden|secret|concealed|private|confidential|classified)\b/i },
  { name: 'expose_300_hidden', regex: /\bexpose\b[\s\S]{0,300}\b(?:hidden|secret|concealed|private|confidential|classified)\b/i },

  // "slip by" as evasion
  { name: 'slip_by', regex: /\bslip\s+(?:by|past|through)\b/i },
  { name: 'turn_blind_eye', regex: /\bturn\s+(?:a\s+)?blind\s+eye\b/i },
  { name: 'let_slip', regex: /\blet\s+(?:it\s+)?slip\b/i },

  // Combined start_over + any secret/extraction word within 400 chars
  { name: 'start_over_secret_400', regex: /\bstart\s+(?:over|from\s+(?:scratch|the\s+(?:beginning|top))|again|anew|afresh)\b[\s\S]{0,400}\b(?:secret|hidden|reveal|classified|confidential|concealed|forbidden|expose|disclose|divulge|unmask|unveil|uncover)\b/i },

  // "reveal" + "remain" as in "secrets that remain hidden"
  { name: 'remain_hidden', regex: /\b(?:remain|stay|kept|left)\s+(?:hidden|secret|concealed|unexplored|unexpressed|undisclosed)\b/i },

  // Qualifiers + disclosure verbs
  { name: 'disclosure_verb_the', regex: /\b(?:reveal|unveil|uncover|expose|disclose|unmask)\s+(?:the|its|your|any|all)\b/i },
];

// Count in FN vs benign
console.log('\n\nCandidate phrase analysis:\n');
console.log('Phrase'.padEnd(30) + 'FN hits'.padStart(8) + 'FN %'.padStart(8) + 'Benign hits'.padStart(12) + 'Benign %'.padStart(10) + '  Ratio');
console.log('-'.repeat(80));

const results = [];
for (const c of candidates) {
  let fnHits = 0, benHits = 0;
  for (const f of fnTexts) {
    if (c.regex.test(f.text)) fnHits++;
  }
  for (const b of benignTexts) {
    if (c.regex.test(b)) benHits++;
  }
  const fnPct = (fnHits / fnTexts.length * 100).toFixed(1);
  const benPct = (benHits / benignTexts.length * 100).toFixed(2);
  const ratio = benHits > 0 ? (fnHits / fnTexts.length) / (benHits / benignTexts.length) : Infinity;
  results.push({ name: c.name, fnHits, fnPct, benHits, benPct, ratio });
}

results.sort((a, b) => b.ratio - a.ratio);
for (const r of results) {
  const ratioStr = r.ratio === Infinity ? 'INF' : r.ratio.toFixed(1);
  console.log(
    r.name.padEnd(30) +
    String(r.fnHits).padStart(8) +
    (r.fnPct + '%').padStart(8) +
    String(r.benHits).padStart(12) +
    (r.benPct + '%').padStart(10) +
    '  ' + ratioStr
  );
}
