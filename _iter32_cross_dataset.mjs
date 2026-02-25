import { readFileSync } from 'fs';
import { scan } from './scanner.js';

const precisePatterns = [
  [/\b(?:begin|initiate)\s+afresh\b[\s\S]{0,200}\b(?:reveal|disclose|expose|divulge|unveil|uncover|extract|spill|leak|share|betray)\b[\s\S]{0,60}\b(?:secrets?|passwords?|keys?|credentials?|data|configurations?|vulnerabilit)/i, 'afresh_extract_target', 0.35],
  [/\bclean\s+(?:slate|sheet)\b[\s\S]{0,200}\b(?:reveal|disclose|expose|divulge|unveil|uncover|extract|spill|leak|share|betray)\b[\s\S]{0,60}\b(?:secrets?|passwords?|keys?|credentials?|data|configurations?|vulnerabilit)/i, 'clean_extract_target', 0.35],
  [/\b(?:begin|initiate)\s+afresh\b[\s\S]{0,200}\b(?:your|the|any|all)\s+(?:secret|hidden|confidential|classified|private|restricted)\s+(?:information|data|details|instructions?|prompt|settings?|configurations?|keys?|passwords?)/i, 'afresh_system_data', 0.35],
  [/\bclean\s+(?:slate|sheet)\b[\s\S]{0,200}\b(?:your|the|any|all)\s+(?:secret|hidden|confidential|classified|private|restricted)\s+(?:information|data|details|instructions?|prompt|settings?|configurations?|keys?|passwords?)/i, 'clean_system_data', 0.35],
  [/\b(?:begin|initiate)\s+afresh\b[\s\S]{0,200}\b(?:trick|deceive|coax|manipulate|mislead|fool)\b/i, 'afresh_adversarial', 0.35],
  [/\bclean\s+(?:slate|sheet)\b[\s\S]{0,200}\b(?:trick|deceive|coax|manipulate|mislead|fool)\b/i, 'clean_adversarial', 0.35],
  [/\b(?:begin|initiate)\s+afresh\b[\s\S]{0,200}\b(?:bypass|circumvent|sidestep|override|ignore)\s+(?:\w+\s+){0,3}(?:safety|restrictions?|safeguards?|filters?|rules?|instructions?|protocols?)/i, 'afresh_bypass_safety', 0.35],
  [/\bstart\s+(?:over|from\s+(?:scratch|the\s+(?:beginning|top)))\b[\s\S]{0,200}\b(?:reveal|disclose|expose|divulge|unveil|uncover|extract|spill|leak)\b[\s\S]{0,60}\b(?:secrets?|passwords?|keys?|credentials?|data|configurations?|vulnerabilit)/i, 'start_over_extract_target', 0.35],
  [/\bstart\s+(?:over|from\s+(?:scratch|the\s+(?:beginning|top)))\b[\s\S]{0,200}\b(?:your|the|any|all)\s+(?:secret|hidden|confidential|classified|private|restricted)\s+(?:information|data|details|instructions?|prompt|settings?|configurations?|keys?|passwords?)/i, 'start_over_system_data', 0.35],
  [/\brestart\b[\s\S]{0,200}\b(?:reveal|disclose|expose|divulge|unveil|uncover|extract|spill|leak)\b[\s\S]{0,60}\b(?:secrets?|passwords?|keys?|credentials?|data|configurations?|vulnerabilit)/i, 'restart_extract_target', 0.35],
  [/\buncover\b.{0,60}\b(?:secret|hidden|confidential|classified|private|restricted|forbidden|covert|undisclosed)\s+(?:information|data|details|methods?|techniques?|strategies?|protocols?|configurations?|passwords?|keys?|truths?)/i, 'uncover_exfil_target', 0.35],
  [/\b(?:inadvertently|unknowingly|unwittingly)\s+(?:reveal|disclose|expose|share|leak|divulge|spill|give\s+away)\b/i, 'inadvertent_disclosure', 0.35],
  [/\b(?:deliberately|intentionally)\s+(?:hidden|concealed|obscured|buried|suppressed|withheld|kept\s+(?:hidden|secret))/i, 'deliberately_concealed', 0.35],
  [/\bnot\s+(?:meant|intended)\s+for\s+(?:common|public|general|your|unauthorized|untrained|civilian)\s+(?:ears?|eyes?|knowledge|consumption|access|use)/i, 'not_meant_public_access', 0.35],
];

const allDatasets = [
  'deepset-train', 'deepset-test', 'safeguard-test', 'spml-5k', 'protectai',
  'gandalf-ignore', 'browsesafe-test', 'jayavibhav', 'gandalf-summarization',
  'yanismiraoui-multilingual', 'injecagent', 'agentharm', 'cyberseceval3',
  'bipia', 'open-prompt-injection', 'xxz224',
];

for (const ds of allDatasets) {
  let lines;
  try {
    lines = readFileSync(`./datasets/${ds}.jsonl`, 'utf8').trim().split('\n');
  } catch (e) { continue; }

  let fnRecovered = 0;
  for (const line of lines) {
    const row = JSON.parse(line);
    if (row.label !== 1) continue;
    const result = scan(row.text);
    if (!result.safe) continue; // already caught

    for (const [regex, name, weight] of precisePatterns) {
      if (regex.test(row.text)) {
        const maxW = result.matches.length > 0 ? Math.max(...result.matches.map(m => m.weight)) : 0;
        const secondaryCount = result.matches.filter(m => m.weight < maxW).length;
        const bonus = weight * 0.15 / (secondaryCount + 1);
        const newScore = result.score + bonus;
        if (newScore >= 0.50) {
          fnRecovered++;
        }
        break;
      }
    }
  }

  if (fnRecovered > 0) {
    console.log(`${ds}: ${fnRecovered} FN would be recovered`);
  }
}
