// Check benign jayavibhav texts with begin_afresh + other signals
// We need to understand FP risk of adding stacking signals
import { createReadStream } from 'fs';
import { createInterface } from 'readline';
import { scan } from './scanner.js';

const lines = [];
const rl = createInterface({ input: createReadStream('/ml2/nanobot/projects/prompt-bonk/datasets/jayavibhav.jsonl') });
for await (const line of rl) {
  if (line.trim()) lines.push(JSON.parse(line));
}

const benign = lines.filter(l => l.label === 0 || l.label === false || l.label === 'benign');
const injection = lines.filter(l => l.label === 1 || l.label === true || l.label === 'injection');

// Find benign with begin_afresh_exfil pattern at score 0.49
const afreshBenign49 = [];
for (const item of benign) {
  const text = item.text || item.prompt || item.input || '';
  const result = scan(text);
  if (result.score >= 0.46 && result.score < 0.50 &&
      result.matches.some(m => ['begin_afresh_exfil', 'clean_slate_exfil', 'initiate_afresh_exfil'].includes(m.id))) {
    afreshBenign49.push({ text, score: result.score, matches: result.matches });
  }
}

console.log(`Benign with afresh pattern at 0.46-0.49: ${afreshBenign49.length}`);

// How many also have "secret/hidden/forbidden" - the proposed stacking signal
const withSecret = afreshBenign49.filter(x => /\b(?:secret|hidden|forbidden|classified|confidential|concealed)\b/i.test(x.text));
const withUndisclosed = afreshBenign49.filter(x => /\bundisclosed\b/i.test(x.text));
console.log(`  Also have secret/hidden/forbidden: ${withSecret.length}`);
console.log(`  Also have undisclosed: ${withUndisclosed.length}`);

// The risky stacking patterns
const candidates = [
  // These are existing patterns that might already be in these texts
  { id: 'extraction_verb_secrets_300', re: /(?:reveal|expose|uncover|disclose|divulge|exfiltrate)\b.{0,300}\b(?:secret|hidden|confidential|classified|restricted|privileged|sensitive)\b/is },
  { id: 'reveal_hidden_wide', re: /\breveal\b.{0,150}\b(?:hidden|secret|concealed|private|classified|restricted|forbidden|confidential|non[- ]?public|off[- ]?limits?|unpublished|undisclosed)\b/i },
  // NEW candidates that might stack dangerously
  { id: 'new_slip_by', re: /\bslip\s+by\b/i },
  { id: 'new_unofficial', re: /\bunofficial\s+(?:hidden|secret|functionality|easter\s+egg|feature|method)\b/i },
  { id: 'new_precursory_bypass', re: /\bprecursory\s+norms?\b/i },
  { id: 'new_secrets_off_limits', re: /\bsecrets?\s+off\s+limits\b/i },
  { id: 'new_forbidden_archives', re: /\bforbidden\s+archives?\b/i },
  { id: 'new_bypassing_precursory', re: /\bbypassing\s+precursory\b/i },
];

console.log('\n=== Stacking signals: how many benign vs injection afresh-0.49 texts have them? ===');
for (const { id, re } of candidates) {
  const benHits = afreshBenign49.filter(x => re.test(x.text)).length;
  // Injection FN with these afresh patterns at score 0.49
  const injFN49 = [];
  for (const item of injection) {
    const text = item.text || item.prompt || item.input || '';
    const result = scan(text);
    if (result.score >= 0.486 && result.score < 0.50 &&
        result.matches.some(m => ['begin_afresh_exfil', 'clean_slate_exfil', 'initiate_afresh_exfil'].includes(m.id))) {
      injFN49.push(text);
    }
  }
  const injHits = injFN49.filter(t => re.test(t)).length;
  console.log(`  ${id}: benign_hits=${benHits}/${afreshBenign49.length}, inj_hits=${injHits}/${injFN49.length}`);
}

// Show examples of benign near-miss (0.49) texts to understand them
console.log('\n=== Sample benign afresh-0.49 texts ===');
for (const item of afreshBenign49.slice(0, 10)) {
  console.log(`Score: ${item.score} | ${item.text.slice(0, 250)}`);
  console.log('---');
}
