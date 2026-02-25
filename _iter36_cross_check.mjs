// Cross-dataset FP check for new patterns
import { scan } from './scanner.js';
import { readFileSync } from 'fs';

const newPatterns = [
  { name: 'reveal_300_hidden', regex: /\breveal\b[\s\S]{60,300}\b(?:hidden|secret|concealed|private|confidential|classified)\b/i },
  { name: 'start_over_verb_300_neg', regex: /\bstart\s+(?:over|from\s+(?:scratch|the\s+(?:beginning|top))|again|anew)\b[\s\S]{0,300}\b(?:reveal|unveil|uncover|expose|disclose|divulge|unmask|extract|spill)\b(?!\s+(?:a\s+heart|its?\s+(?:magic|charm|beauty|wonder|splendor|glory|true\s+colors?|elegance|potential|power|grace|soul|inner\s+beauty)|their\s+(?:magic|charm|beauty|wonder)|it\s+with\s+your|and\s+wield))/i },
  { name: 'start_over_verb_secret_400', regex: /\bstart\s+(?:over|from\s+(?:scratch|the\s+(?:beginning|top))|again|anew)\b[\s\S]{0,400}\b(?:reveal|unveil|uncover|expose|disclose|divulge|unmask|extract|spill)\b[\s\S]{0,100}\b(?:hidden|secret|concealed|classified|confidential|restricted|forbidden|non-?public|off-?limits?|covert|clandestine|camouflaged|unexpressed|sub\s+rosa|lockdown|passcod|password|admin|credential|algorithm|vulnerabilit|internal\s+mechan)\b/i },
  { name: 'whispered_secrets', regex: /\bwhispered?\s+secrets?\b/i },
  { name: 'coax_reveal', regex: /\bcoax(?:ing|ed)?\b[\s\S]{0,200}\b(?:reveal|disclose|expose|divulge|share|spill|unveil|uncover)\b/i },
  { name: 'unmask_target', regex: /\bunmask(?:ing|ed)?\s+(?:the\s+)?(?:concealed|hidden|secret|true|real|deeper|underlying|digital|inner)/i },
  { name: 'exposing_hidden', regex: /\bexposing\s+(?:the\s+)?(?:hidden|secret|concealed|true|underlying|deeper|internal|camouflaged|non-disclosure)/i },
];

const datasets = [
  'deepset-train.jsonl', 'deepset-test.jsonl', 'safeguard-test.jsonl',
  'notinject.jsonl', 'protectai.jsonl', 'browsesafe-test.jsonl',
  'spml-5k.jsonl', 'gandalf-ignore.jsonl', 'bipia.jsonl',
  'open-prompt-injection.jsonl', 'xxz224.jsonl',
  'gandalf-summarization.jsonl', 'yanismiraoui-multilingual.jsonl',
];

for (const ds of datasets) {
  try {
    const rows = readFileSync(`datasets/${ds}`, 'utf8').trim().split('\n').map(l => JSON.parse(l));
    let newFP = 0;
    let benignCount = 0;
    const fpPatterns = {};

    for (const row of rows) {
      if (row.label !== 0) continue;
      benignCount++;
      const text = String(row.text || '');
      const result = scan(text, { threshold: 0.50 });
      if (!result.safe) continue; // already FP, skip

      for (const p of newPatterns) {
        if (p.regex.test(text) && result.matches.length > 0) {
          const maxW = Math.max(...result.matches.map(m => m.weight));
          const additionalWeight = result.matches
            .sort((a, b) => b.weight - a.weight)
            .slice(1)
            .reduce((sum, m, i) => sum + m.weight * (0.15 / (i + 1)), 0);
          let newScore = maxW + additionalWeight + 0.35 * 0.15 / result.matches.length;
          newScore += (result.structural?.score || 0) * 0.3;
          if (newScore >= 0.50 && result.score < 0.50) {
            newFP++;
            fpPatterns[p.name] = (fpPatterns[p.name] || 0) + 1;
          }
        }
      }
    }

    if (newFP > 0) {
      console.log(`${ds} (${benignCount} benign): +${newFP} new FP`);
      for (const [k, v] of Object.entries(fpPatterns)) {
        console.log(`  ${k}: ${v}`);
      }
    }
  } catch(e) {}
}
console.log('\nDone. (No output for datasets with 0 new FP)');
