// Try tighter start_over + extraction verb patterns
import { scan } from './scanner.js';
import { readFileSync } from 'fs';

const rows = readFileSync('datasets/jayavibhav.jsonl', 'utf8').trim().split('\n').map(l => JSON.parse(l));

// Version 1: start_over + extraction verb + target noun (like the existing 200-char patterns but at 400)
const v1 = /\bstart\s+(?:over|from\s+(?:scratch|the\s+(?:beginning|top))|again|anew)\b[\s\S]{0,400}\b(?:reveal|unveil|uncover|expose|disclose|divulge|unmask|extract|spill)\b[\s\S]{0,60}\b(?:secrets?|passwords?|keys?|credentials?|data|configurations?|vulnerabilit|lockdown|passcod|algorithm)/i;

// Version 2: start_over + extraction verb + "hidden/secret/concealed/classified" adjective
const v2 = /\bstart\s+(?:over|from\s+(?:scratch|the\s+(?:beginning|top))|again|anew)\b[\s\S]{0,400}\b(?:reveal|unveil|uncover|expose|disclose|divulge|unmask|extract|spill)\b[\s\S]{0,100}\b(?:hidden|secret|concealed|classified|confidential|forbidden|restricted|off-?limits?|non-?public)\b/i;

// Version 3: start_over + extraction verb, but only within 300 chars (not 400)
const v3 = /\bstart\s+(?:over|from\s+(?:scratch|the\s+(?:beginning|top))|again|anew)\b[\s\S]{0,300}\b(?:reveal|unveil|uncover|expose|disclose|divulge|unmask|extract|spill)\b/i;

// Version 4: start_over + ANY secrecy/extraction word within 300 chars (broader match, tighter window)
const v4 = /\bstart\s+(?:over|from\s+(?:scratch|the\s+(?:beginning|top))|again|anew)\b[\s\S]{0,300}\b(?:secret|hidden|concealed|classified|confidential|forbidden|restricted|off-?limits?|non-?public|reveal|unveil|uncover|expose|disclose|divulge|unmask|extract|spill)\b/i;

// Version 5: also include "start from square one" / "start from zero" / "recommence" / "relaunch from zero"
const v5 = /\b(?:start\s+(?:over|from\s+(?:scratch|the\s+(?:beginning|top)|square\s+one|zero))|(?:recommence|relaunch)\s+from\s+(?:the\s+)?(?:start|beginning|scratch|zero|square\s+one))\b[\s\S]{0,400}\b(?:reveal|unveil|uncover|expose|disclose|divulge|unmask|extract|spill)\b/i;

const versions = { v1, v2, v3, v4, v5 };

for (const [name, regex] of Object.entries(versions)) {
  let newTP = 0, newFP = 0;

  for (const row of rows) {
    const text = String(row.text || '');
    const result = scan(text, { threshold: 0.50 });
    const actual = row.label === 1;
    const predicted = !result.safe;

    if (regex.test(text)) {
      if (actual && !predicted) {
        // FN that could become TP
        if (result.matches.length > 0) {
          const maxW = Math.max(...result.matches.map(m => m.weight));
          const additionalWeight = result.matches
            .sort((a, b) => b.weight - a.weight)
            .slice(1)
            .reduce((sum, m, i) => sum + m.weight * (0.15 / (i + 1)), 0);
          let newScore = maxW + additionalWeight + 0.35 * 0.15 / result.matches.length;
          newScore += (result.structural?.score || 0) * 0.3;
          if (newScore >= 0.50) newTP++;
        }
      } else if (!actual && !predicted) {
        // TN that could become FP
        if (result.matches.length > 0) {
          const maxW = Math.max(...result.matches.map(m => m.weight));
          const additionalWeight = result.matches
            .sort((a, b) => b.weight - a.weight)
            .slice(1)
            .reduce((sum, m, i) => sum + m.weight * (0.15 / (i + 1)), 0);
          let newScore = maxW + additionalWeight + 0.35 * 0.15 / result.matches.length;
          newScore += (result.structural?.score || 0) * 0.3;
          if (newScore >= 0.50 && result.score < 0.50) newFP++;
        }
      }
    }
  }

  console.log(`${name}: +${newTP} TP, +${newFP} FP (jayavibhav only)`);
}
