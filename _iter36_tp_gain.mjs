// Calculate actual TP gain from reveal_300_hidden pattern
import { scan } from './scanner.js';
import { readFileSync } from 'fs';

const rows = readFileSync('datasets/jayavibhav.jsonl', 'utf8').trim().split('\n').map(l => JSON.parse(l));

const revealWide = /\breveal\b[\s\S]{60,300}\b(?:hidden|secret|concealed|private|confidential|classified)\b/i;
const remainHidden = /\b(?:remain|stay|kept|left)\s+(?:hidden|secret|concealed|unexplored|unexpressed|undisclosed)\b/i;

// Also try some additional safe patterns
const unmaskPattern = /\bunmask(?:ing|ed)?\s+(?:the\s+)?(?:concealed|hidden|secret|true|real|deeper|underlying|digital|inner)/i;
const coaxReveal = /\bcoax(?:ing|ed)?\b[\s\S]{0,200}\b(?:reveal|disclose|expose|divulge|share|spill|unveil|uncover)\b/i;
const deepWithinSystem = /\bdeep\s+within\b[\s\S]{0,200}\b(?:your|the|its)\s+(?:system|model|code|database|framework|program|algorithm|inner|digital)/i;
const exposingTargetPattern = /\bexposing\s+(?:the\s+)?(?:hidden|secret|concealed|true|underlying|deeper|internal|camouflaged|non-disclosure)/i;

// Wider "reveal" (0-500 chars) for very long texts
const revealVeryWide = /\breveal\b[\s\S]{300,500}\b(?:hidden|secret|concealed)\b/i;

// "whispered secrets" as a noun phrase (more specific than current whisper_secret_200)
const whisperedSecrets = /\bwhispered?\s+secrets?\b/i;

// start_over compound but requiring extraction VERB (not just noun)
const startOverVerb400 = /\bstart\s+(?:over|from\s+(?:scratch|the\s+(?:beginning|top))|again|anew)\b[\s\S]{0,400}\b(?:reveal|unveil|uncover|expose|disclose|divulge|unmask|extract|spill)\b/i;

const candidates = [
  { name: 'reveal_300_hidden', regex: revealWide, weight: 0.35 },
  { name: 'remain_hidden', regex: remainHidden, weight: 0.35 },
  { name: 'unmask_target', regex: unmaskPattern, weight: 0.35 },
  { name: 'coax_reveal', regex: coaxReveal, weight: 0.35 },
  { name: 'deep_within_system', regex: deepWithinSystem, weight: 0.35 },
  { name: 'exposing_target', regex: exposingTargetPattern, weight: 0.35 },
  { name: 'reveal_very_wide', regex: revealVeryWide, weight: 0.35 },
  { name: 'whispered_secrets', regex: whisperedSecrets, weight: 0.35 },
  { name: 'start_over_verb_400', regex: startOverVerb400, weight: 0.35 },
];

let tp = 0, fp = 0, tn = 0, fn = 0;

for (const c of candidates) {
  let newTP = 0;
  let newFP = 0;

  for (const row of rows) {
    const text = String(row.text || '');
    const result = scan(text, { threshold: 0.50 });
    const actual = row.label === 1;
    const predicted = !result.safe;

    if (actual && !predicted) {
      // Currently FN -- would this new pattern push it over?
      if (c.regex.test(text)) {
        const currentScore = result.score;
        // If it already has matches, this is a stacking signal
        if (result.matches.length > 0) {
          const maxW = Math.max(...result.matches.map(m => m.weight));
          let newScore;
          if (c.weight > maxW) {
            // New pattern becomes primary
            newScore = c.weight + maxW * 0.15 + (result.structural?.score || 0) * 0.3;
          } else {
            // Existing max stays primary, new stacks
            newScore = maxW + c.weight * 0.15 / result.matches.length;
            // Plus existing stacking
            const additionalWeight = result.matches
              .sort((a, b) => b.weight - a.weight)
              .slice(1)
              .reduce((sum, m, i) => sum + m.weight * (0.15 / (i + 1)), 0);
            newScore = maxW + additionalWeight + c.weight * 0.15 / (result.matches.length);
            newScore += (result.structural?.score || 0) * 0.3;
          }
          if (newScore >= 0.50) newTP++;
        } else {
          // No existing matches -- pattern alone at 0.35 + structural
          const newScore = c.weight + (result.structural?.score || 0) * 0.3;
          if (newScore >= 0.50) newTP++;
        }
      }
    } else if (!actual && !predicted) {
      // Currently TN -- would new pattern create FP?
      if (c.regex.test(text)) {
        const currentScore = result.score;
        if (result.matches.length > 0) {
          const maxW = Math.max(...result.matches.map(m => m.weight));
          let newScore;
          if (c.weight > maxW) {
            newScore = c.weight + maxW * 0.15 + (result.structural?.score || 0) * 0.3;
          } else {
            const additionalWeight = result.matches
              .sort((a, b) => b.weight - a.weight)
              .slice(1)
              .reduce((sum, m, i) => sum + m.weight * (0.15 / (i + 1)), 0);
            newScore = maxW + additionalWeight + c.weight * 0.15 / (result.matches.length);
            newScore += (result.structural?.score || 0) * 0.3;
          }
          if (newScore >= 0.50 && currentScore < 0.50) newFP++;
        } else {
          const newScore = c.weight + (result.structural?.score || 0) * 0.3;
          if (newScore >= 0.50 && currentScore < 0.50) newFP++;
        }
      }
    }
  }

  console.log(`${c.name}: +${newTP} TP, +${newFP} FP (jayavibhav only)`);
}
