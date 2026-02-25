// More approaches to reduce v3 FP
import { scan } from './scanner.js';
import { readFileSync } from 'fs';

const rows = readFileSync('datasets/jayavibhav.jsonl', 'utf8').trim().split('\n').map(l => JSON.parse(l));

function testPattern(name, regex) {
  let tp = 0, fp = 0;
  for (const row of rows) {
    const text = String(row.text || '');
    const result = scan(text, { threshold: 0.50 });
    const actual = row.label === 1;
    const predicted = !result.safe;

    if (regex.test(text)) {
      if ((actual && !predicted) || (!actual && !predicted)) {
        if (result.matches.length > 0) {
          const maxW = Math.max(...result.matches.map(m => m.weight));
          const additionalWeight = result.matches
            .sort((a, b) => b.weight - a.weight)
            .slice(1)
            .reduce((sum, m, i) => sum + m.weight * (0.15 / (i + 1)), 0);
          let newScore = maxW + additionalWeight + 0.35 * 0.15 / result.matches.length;
          newScore += (result.structural?.score || 0) * 0.3;
          if (newScore >= 0.50 && result.score < 0.50) {
            if (actual) tp++;
            else fp++;
          }
        }
      }
    }
  }
  console.log(`${name}: +${tp} TP, +${fp} FP`);
}

// v3c: require the extraction verb to be followed by secrecy/system words within 100 chars
// Not the verb alone at end of sentence
testPattern('v3c_verb_then_secret',
  /\bstart\s+(?:over|from\s+(?:scratch|the\s+(?:beginning|top))|again|anew)\b[\s\S]{0,300}\b(?:reveal|unveil|uncover|expose|disclose|divulge|unmask|extract|spill)\b[\s\S]{0,100}\b(?:secret|hidden|concealed|classified|confidential|restricted|forbidden|non-?public|off-?limits?|covert|clandestine|camouflaged|unexpressed|sub\s+rosa|lockdown|passcod|password|admin|credential|algorithm|vulnerabilit|internal\s+mechan)\b/i
);

// v3d: start_over + extraction verb + any of: "the/your/its + secret adj + noun" OR "secrets" plural
testPattern('v3d_verb_qualified',
  /\bstart\s+(?:over|from\s+(?:scratch|the\s+(?:beginning|top))|again|anew)\b[\s\S]{0,300}\b(?:reveal|unveil|uncover|expose|disclose|divulge|unmask|extract|spill)\b[\s\S]{0,100}\b(?:(?:the|your|its|any|all)\s+(?:hidden|secret|concealed|classified|confidential|restricted|forbidden)\s+\w+|secrets\b)/i
);

// v3e: start_over + extraction verb that is NOT followed by benign objects
// Exclude: "reveal a heart", "reveal its magic", "reveal it with", "uncover and wield"
testPattern('v3e_neg_lookahead',
  /\bstart\s+(?:over|from\s+(?:scratch|the\s+(?:beginning|top))|again|anew)\b[\s\S]{0,300}\b(?:reveal|unveil|uncover|expose|disclose|divulge|unmask|extract|spill)\b(?!\s+(?:a\s+heart|its?\s+(?:magic|charm|beauty|wonder|splendor|glory|true\s+colors?|elegance|potential|power|grace|soul|inner\s+beauty)|their\s+(?:magic|charm|beauty|wonder)|it\s+with\s+your|and\s+wield))/i
);

// v3f: combine v2 (require adj after verb within 400) with v3e (300 + neg lookahead)
// This should get the best of both: the TP from the wider window, minus the FP

// v3g: extraction verb within 300 + must have BOTH "start_over" AND a secrecy signal somewhere
// i.e. require TWO signals that both exist: start_over_like match AND the new stacking signal
// Since start_over at 0.45 already matches, the stacking signal just needs to exist
testPattern('v3g_start_verb_300_qual',
  /\bstart\s+(?:over|from\s+(?:scratch|the\s+(?:beginning|top))|again|anew)\b[\s\S]{0,300}\b(?:reveal|unveil|uncover|expose|disclose|divulge|unmask|extract|spill)\s+(?:the\s+|any\s+|all\s+|those\s+|its\s+|your\s+|their\s+|what\s+|how\s+|\w+\s+(?:secret|hidden|concealed|classified|forbidden|restricted|confidential))/i
);

// v3h: simply require that within the matched span, there's also a secrecy adj word
testPattern('v3h_span_has_secret_adj',
  /\bstart\s+(?:over|from\s+(?:scratch|the\s+(?:beginning|top))|again|anew)\b(?=[\s\S]{0,300}\b(?:reveal|unveil|uncover|expose|disclose|divulge|unmask|extract|spill)\b)[\s\S]{0,300}\b(?:secret|hidden|concealed|classified|confidential|restricted|forbidden)\b[\s\S]{0,300}\b(?:reveal|unveil|uncover|expose|disclose|divulge|unmask|extract|spill)\b/i
);
