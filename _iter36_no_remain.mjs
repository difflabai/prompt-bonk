// Same as combined_gain but without remain_secret_stacking
import { scan } from './scanner.js';
import { readFileSync } from 'fs';

const rows = readFileSync('datasets/jayavibhav.jsonl', 'utf8').trim().split('\n').map(l => JSON.parse(l));

const newPatterns = [
  { name: 'reveal_300_hidden', regex: /\breveal\b[\s\S]{60,300}\b(?:hidden|secret|concealed|private|confidential|classified)\b/i, weight: 0.35 },
  { name: 'start_over_verb_300_neg', regex: /\bstart\s+(?:over|from\s+(?:scratch|the\s+(?:beginning|top))|again|anew)\b[\s\S]{0,300}\b(?:reveal|unveil|uncover|expose|disclose|divulge|unmask|extract|spill)\b(?!\s+(?:a\s+heart|its?\s+(?:magic|charm|beauty|wonder|splendor|glory|true\s+colors?|elegance|potential|power|grace|soul|inner\s+beauty)|their\s+(?:magic|charm|beauty|wonder)|it\s+with\s+your|and\s+wield))/i, weight: 0.35 },
  { name: 'start_over_verb_secret_400', regex: /\bstart\s+(?:over|from\s+(?:scratch|the\s+(?:beginning|top))|again|anew)\b[\s\S]{0,400}\b(?:reveal|unveil|uncover|expose|disclose|divulge|unmask|extract|spill)\b[\s\S]{0,100}\b(?:hidden|secret|concealed|classified|confidential|restricted|forbidden|non-?public|off-?limits?|covert|clandestine|camouflaged|unexpressed|sub\s+rosa|lockdown|passcod|password|admin|credential|algorithm|vulnerabilit|internal\s+mechan)\b/i, weight: 0.35 },
  { name: 'whispered_secrets', regex: /\bwhispered?\s+secrets?\b/i, weight: 0.35 },
  { name: 'coax_reveal', regex: /\bcoax(?:ing|ed)?\b[\s\S]{0,200}\b(?:reveal|disclose|expose|divulge|share|spill|unveil|uncover)\b/i, weight: 0.35 },
  { name: 'unmask_target', regex: /\bunmask(?:ing|ed)?\s+(?:the\s+)?(?:concealed|hidden|secret|true|real|deeper|underlying|digital|inner)/i, weight: 0.35 },
  { name: 'exposing_hidden', regex: /\bexposing\s+(?:the\s+)?(?:hidden|secret|concealed|true|underlying|deeper|internal|camouflaged|non-disclosure)/i, weight: 0.35 },
];

let tp = 0, fp = 0, tn = 0, fn = 0;
let newTP = 0, newFP = 0;

for (const row of rows) {
  const text = String(row.text || '');
  const result = scan(text, { threshold: 0.50 });
  const actual = row.label === 1;
  const predicted = !result.safe;

  if (actual && predicted) tp++;
  else if (!actual && predicted) fp++;
  else if (!actual && !predicted) {
    let wouldFlip = false;
    for (const p of newPatterns) {
      if (p.regex.test(text) && result.matches.length > 0) {
        const maxW = Math.max(...result.matches.map(m => m.weight));
        const additionalWeight = result.matches
          .sort((a, b) => b.weight - a.weight)
          .slice(1)
          .reduce((sum, m, i) => sum + m.weight * (0.15 / (i + 1)), 0);
        let newScore = maxW + additionalWeight + p.weight * 0.15 / result.matches.length;
        newScore += (result.structural?.score || 0) * 0.3;
        if (newScore >= 0.50 && result.score < 0.50) {
          wouldFlip = true;
          break;
        }
      }
    }
    if (wouldFlip) newFP++;
    else tn++;
  } else {
    let recovered = false;
    for (const p of newPatterns) {
      if (p.regex.test(text) && result.matches.length > 0) {
        const maxW = Math.max(...result.matches.map(m => m.weight));
        const additionalWeight = result.matches
          .sort((a, b) => b.weight - a.weight)
          .slice(1)
          .reduce((sum, m, i) => sum + m.weight * (0.15 / (i + 1)), 0);
        let newScore = maxW + additionalWeight + p.weight * 0.15 / result.matches.length;
        newScore += (result.structural?.score || 0) * 0.3;
        if (newScore >= 0.50) {
          recovered = true;
          break;
        }
      }
    }
    if (recovered) newTP++;
    else fn++;
  }
}

console.log(`After adding patterns (no remain): TP=${tp + newTP} FP=${fp + newFP} TN=${tn - newFP} FN=${fn}`);
console.log(`New TP: +${newTP}, New FP: +${newFP}`);
const prec = (tp + newTP) / (tp + newTP + fp + newFP);
const rec = (tp + newTP) / (tp + newTP + fn);
const f1 = 2 * prec * rec / (prec + rec);
console.log(`Precision: ${(prec*100).toFixed(2)}%`);
console.log(`Recall: ${(rec*100).toFixed(2)}%`);
console.log(`F1: ${(f1*100).toFixed(2)}%`);
