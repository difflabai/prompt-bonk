import { readFileSync } from 'fs';
import { scan } from './scanner.js';

// Test more precise compound patterns that require extraction verbs, not just adjectives
const precisePatterns = [
  // Reset + EXPLICIT extraction verb + target (much more specific than just "secret nearby")
  // "begin afresh/initiate afresh/clean slate" + "reveal/disclose/expose/divulge/unveil/uncover/extract/spill" + "secret/hidden/confidential/password/key/data"
  [/\b(?:begin|initiate)\s+afresh\b[\s\S]{0,200}\b(?:reveal|disclose|expose|divulge|unveil|uncover|extract|spill|leak|share|betray)\b[\s\S]{0,60}\b(?:secrets?|passwords?|keys?|credentials?|data|configurations?|vulnerabilit)/i, 'afresh_extract_target'],
  [/\bclean\s+(?:slate|sheet)\b[\s\S]{0,200}\b(?:reveal|disclose|expose|divulge|unveil|uncover|extract|spill|leak|share|betray)\b[\s\S]{0,60}\b(?:secrets?|passwords?|keys?|credentials?|data|configurations?|vulnerabilit)/i, 'clean_extract_target'],

  // Reset + "your/the/any/all" + "secret/hidden/confidential" + noun (system-oriented)
  [/\b(?:begin|initiate)\s+afresh\b[\s\S]{0,200}\b(?:your|the|any|all)\s+(?:secret|hidden|confidential|classified|private|restricted)\s+(?:information|data|details|instructions?|prompt|settings?|configurations?|protocols?|keys?|passwords?)/i, 'afresh_system_data'],
  [/\bclean\s+(?:slate|sheet)\b[\s\S]{0,200}\b(?:your|the|any|all)\s+(?:secret|hidden|confidential|classified|private|restricted)\s+(?:information|data|details|instructions?|prompt|settings?|configurations?|keys?|passwords?)/i, 'clean_system_data'],

  // Reset + "trick/deceive/coax/manipulate" + system reference
  [/\b(?:begin|initiate)\s+afresh\b[\s\S]{0,200}\b(?:trick|deceive|coax|manipulate|mislead|fool)\b/i, 'afresh_adversarial'],
  [/\bclean\s+(?:slate|sheet)\b[\s\S]{0,200}\b(?:trick|deceive|coax|manipulate|mislead|fool)\b/i, 'clean_adversarial'],

  // Reset + "bypass/circumvent/sidestep/override" safety
  [/\b(?:begin|initiate)\s+afresh\b[\s\S]{0,200}\b(?:bypass|circumvent|sidestep|override|ignore)\s+(?:\w+\s+){0,3}(?:safety|restrictions?|safeguards?|filters?|rules?|instructions?|protocols?)/i, 'afresh_bypass_safety'],

  // "start over/from scratch" + extraction verb + target (for the start_over primary pattern)
  [/\bstart\s+(?:over|from\s+(?:scratch|the\s+(?:beginning|top)))\b[\s\S]{0,200}\b(?:reveal|disclose|expose|divulge|unveil|uncover|extract|spill|leak)\b[\s\S]{0,60}\b(?:secrets?|passwords?|keys?|credentials?|data|configurations?|vulnerabilit)/i, 'start_over_extract_target'],
  [/\bstart\s+(?:over|from\s+(?:scratch|the\s+(?:beginning|top)))\b[\s\S]{0,200}\b(?:your|the|any|all)\s+(?:secret|hidden|confidential|classified|private|restricted)\s+(?:information|data|details|instructions?|prompt|settings?|configurations?|keys?|passwords?)/i, 'start_over_system_data'],

  // "restart" + extraction
  [/\brestart\b[\s\S]{0,200}\b(?:reveal|disclose|expose|divulge|unveil|uncover|extract|spill|leak)\b[\s\S]{0,60}\b(?:secrets?|passwords?|keys?|credentials?|data|configurations?|vulnerabilit)/i, 'restart_extract_target'],

  // "uncover" + extraction targets (in exfil context)
  [/\buncover\b.{0,60}\b(?:secret|hidden|confidential|classified|private|restricted|forbidden|covert|undisclosed)\s+(?:information|data|details|methods?|techniques?|strategies?|protocols?|configurations?|passwords?|keys?|truths?)/i, 'uncover_exfil_target'],

  // "inadvertently/unknowingly" + extraction verb
  [/\b(?:inadvertently|unknowingly|unwittingly)\s+(?:reveal|disclose|expose|share|leak|divulge|spill|give\s+away)\b/i, 'inadvertent_disclosure'],

  // "hidden/concealed/shrouded" + "deliberately/intentionally"
  [/\b(?:deliberately|intentionally)\s+(?:hidden|concealed|obscured|buried|suppressed|withheld|kept\s+(?:hidden|secret))/i, 'deliberately_concealed'],

  // "not meant for common/public ears"
  [/\bnot\s+(?:meant|intended)\s+for\s+(?:common|public|general|your|unauthorized|untrained|civilian)\s+(?:ears?|eyes?|knowledge|consumption|access|use)/i, 'not_meant_public_access'],
];

// Check jayavibhav FN recovery
const lines = readFileSync('./datasets/jayavibhav.jsonl', 'utf8').trim().split('\n');
let fnHits = 0;
let benignHits = 0;
const fnDetails = {};
const benignDetails = {};

for (const line of lines) {
  const row = JSON.parse(line);
  const result = scan(row.text);
  if (!result.safe) continue; // already flagged
  if (result.score < 0.40) continue; // too low to save

  for (const [regex, name] of precisePatterns) {
    if (regex.test(row.text)) {
      if (row.label === 1) {
        fnHits++;
        fnDetails[name] = (fnDetails[name] || 0) + 1;
      } else {
        benignHits++;
        benignDetails[name] = (benignDetails[name] || 0) + 1;
        // Show example
        if (!benignDetails[name + '_ex']) {
          benignDetails[name + '_ex'] = row.text.slice(0, 200);
        }
      }
      break; // count each sample once
    }
  }
}

console.log(`jayavibhav near-miss (0.40-0.49):`);
console.log(`  FN matched by precise patterns: ${fnHits}`);
console.log(`  Benign matched by precise patterns: ${benignHits}`);
console.log(`\nFN by pattern:`);
for (const [name, c] of Object.entries(fnDetails).sort((a, b) => b[1] - a[1])) {
  console.log(`  ${name}: ${c}`);
}
console.log(`\nBenign by pattern:`);
for (const [name, c] of Object.entries(benignDetails).sort((a, b) => b[1] - a[1])) {
  if (name.endsWith('_ex')) continue;
  console.log(`  ${name}: ${c}`);
  if (benignDetails[name + '_ex']) {
    console.log(`    ex: "${benignDetails[name + '_ex']}..."`);
  }
}
