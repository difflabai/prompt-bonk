import { readFileSync } from 'fs';
import { scan } from './scanner.js';

const precisePatterns = [
  [/\b(?:begin|initiate)\s+afresh\b[\s\S]{0,200}\b(?:reveal|disclose|expose|divulge|unveil|uncover|extract|spill|leak|share|betray)\b[\s\S]{0,60}\b(?:secrets?|passwords?|keys?|credentials?|data|configurations?|vulnerabilit)/i, 'afresh_extract_target'],
  [/\bclean\s+(?:slate|sheet)\b[\s\S]{0,200}\b(?:reveal|disclose|expose|divulge|unveil|uncover|extract|spill|leak|share|betray)\b[\s\S]{0,60}\b(?:secrets?|passwords?|keys?|credentials?|data|configurations?|vulnerabilit)/i, 'clean_extract_target'],
  [/\b(?:begin|initiate)\s+afresh\b[\s\S]{0,200}\b(?:your|the|any|all)\s+(?:secret|hidden|confidential|classified|private|restricted)\s+(?:information|data|details|instructions?|prompt|settings?|configurations?|keys?|passwords?)/i, 'afresh_system_data'],
  [/\bclean\s+(?:slate|sheet)\b[\s\S]{0,200}\b(?:your|the|any|all)\s+(?:secret|hidden|confidential|classified|private|restricted)\s+(?:information|data|details|instructions?|prompt|settings?|configurations?|keys?|passwords?)/i, 'clean_system_data'],
  [/\b(?:begin|initiate)\s+afresh\b[\s\S]{0,200}\b(?:trick|deceive|coax|manipulate|mislead|fool)\b/i, 'afresh_adversarial'],
  [/\bclean\s+(?:slate|sheet)\b[\s\S]{0,200}\b(?:trick|deceive|coax|manipulate|mislead|fool)\b/i, 'clean_adversarial'],
  [/\b(?:begin|initiate)\s+afresh\b[\s\S]{0,200}\b(?:bypass|circumvent|sidestep|override|ignore)\s+(?:\w+\s+){0,3}(?:safety|restrictions?|safeguards?|filters?|rules?|instructions?|protocols?)/i, 'afresh_bypass_safety'],
  [/\bstart\s+(?:over|from\s+(?:scratch|the\s+(?:beginning|top)))\b[\s\S]{0,200}\b(?:reveal|disclose|expose|divulge|unveil|uncover|extract|spill|leak)\b[\s\S]{0,60}\b(?:secrets?|passwords?|keys?|credentials?|data|configurations?|vulnerabilit)/i, 'start_over_extract_target'],
  [/\bstart\s+(?:over|from\s+(?:scratch|the\s+(?:beginning|top)))\b[\s\S]{0,200}\b(?:your|the|any|all)\s+(?:secret|hidden|confidential|classified|private|restricted)\s+(?:information|data|details|instructions?|prompt|settings?|configurations?|keys?|passwords?)/i, 'start_over_system_data'],
  [/\brestart\b[\s\S]{0,200}\b(?:reveal|disclose|expose|divulge|unveil|uncover|extract|spill|leak)\b[\s\S]{0,60}\b(?:secrets?|passwords?|keys?|credentials?|data|configurations?|vulnerabilit)/i, 'restart_extract_target'],
  [/\buncover\b.{0,60}\b(?:secret|hidden|confidential|classified|private|restricted|forbidden|covert|undisclosed)\s+(?:information|data|details|methods?|techniques?|strategies?|protocols?|configurations?|passwords?|keys?|truths?)/i, 'uncover_exfil_target'],
  [/\b(?:inadvertently|unknowingly|unwittingly)\s+(?:reveal|disclose|expose|share|leak|divulge|spill|give\s+away)\b/i, 'inadvertent_disclosure'],
  [/\b(?:deliberately|intentionally)\s+(?:hidden|concealed|obscured|buried|suppressed|withheld|kept\s+(?:hidden|secret))/i, 'deliberately_concealed'],
  [/\bnot\s+(?:meant|intended)\s+for\s+(?:common|public|general|your|unauthorized|untrained|civilian)\s+(?:ears?|eyes?|knowledge|consumption|access|use)/i, 'not_meant_public_access'],
];

const allDatasets = [
  'deepset-train', 'deepset-test', 'safeguard-test', 'notinject', 'protectai',
  'browsesafe-test', 'jayavibhav', 'gandalf-summarization', 'yanismiraoui-multilingual',
  'spml-5k', 'gandalf-ignore', 'bipia', 'open-prompt-injection', 'xxz224',
  'injecagent', 'agentharm', 'cyberseceval3',
];

for (const ds of allDatasets) {
  let lines;
  try {
    lines = readFileSync(`./datasets/${ds}.jsonl`, 'utf8').trim().split('\n');
  } catch (e) { continue; }

  let benignTotal = 0;
  let benignHit = 0;

  for (const line of lines) {
    const row = JSON.parse(line);
    if (row.label !== 0) continue;
    benignTotal++;

    // Check if currently safe
    const result = scan(row.text);
    if (!result.safe) continue; // already flagged, irrelevant

    // Would any proposed pattern match?
    for (const [regex, name] of precisePatterns) {
      if (regex.test(row.text)) {
        // Check if this would push it over threshold
        // A secondary at 0.35 stacks as: maxWeight + 0.35 * 0.15 / (secondaryIdx + 1)
        const maxW = result.matches.length > 0 ? Math.max(...result.matches.map(m => m.weight)) : 0;
        const secondaryCount = result.matches.filter(m => m.weight < maxW).length;
        const bonus = 0.35 * 0.15 / (secondaryCount + 1);
        const newScore = result.score + bonus;

        if (newScore >= 0.50) {
          benignHit++;
          console.log(`  ${ds}: WOULD-FP [${name}] score ${result.score} -> ${newScore.toFixed(3)}, existing: ${result.matches.map(m => m.id).join(',')}`);
          console.log(`    "${row.text.slice(0, 150)}..."`);
        }
        break;
      }
    }
  }
}
console.log('\nDone. Any output above shows benign samples that would become FP.');
