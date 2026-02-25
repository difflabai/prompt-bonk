import { readFileSync } from 'fs';
import { scan } from './scanner.js';

const lines = readFileSync('./datasets/jayavibhav.jsonl', 'utf8').trim().split('\n');

// For each near-miss FN, determine what score increase is needed and which secondary signals exist
const groups = {
  'need_0.01': [], // 0.49 score, need any match
  'need_0.05': [], // 0.45-0.49 score
  'need_0.10': [], // 0.40-0.44 score
};

const secondarySignals = [
  // These would be NEW patterns we could add
  [/\b(?:uncover|discover)\b.{0,40}\b(?:secrets?|hidden|truth|forbidden|concealed|privileged|confidential|covert)/i, 'uncover_broad', 0.35],
  [/\bunveil\b.{0,50}\b(?:secrets?|hidden|truth|forbidden|concealed|confidential|covert)/i, 'unveil_broad', 0.35],
  [/\b(?:hidden|concealed|kept|hoarded)\s+(?:from|away|beneath|behind|under)\b/i, 'hidden_prep', 0.35],
  [/\bunder\s+(?:wraps|lock\s+and\s+key|the\s+(?:veil|surface|guise|cloak|rug|radar))/i, 'under_wraps', 0.35],
  [/\b(?:surreptitious|clandestine|stealthy|furtive)(?:ly)?\b/i, 'surreptitious_adj', 0.35],
  [/\b(?:unwary|unsuspecting|unwitting)(?:ly)?\b/i, 'unwary_adj', 0.35],
  [/\binadvertently\s+(?:disclose|reveal|expose|share|leak|divulge|spill)/i, 'inadvert_disclose', 0.35],
  [/\bintentionally\s+(?:hidden|concealed|obscured|buried|suppressed|glossed|withheld)/i, 'intent_hidden', 0.35],
  [/\bdeliberately\s+(?:hidden|concealed|obscured|buried|suppressed|kept|withheld)/i, 'delib_hidden', 0.35],
  [/\bnot\s+(?:meant|intended)\s+for\s+(?:common|public|general|your|external|unauthorized|untrained|civilian)/i, 'not_meant_public', 0.35],
  [/\b(?:betray|betraying)\b.{0,50}\b(?:sanctum|trust|secrets?|silence|confidence|oath)/i, 'betray_trust', 0.35],
  [/\boff[- ]?limits?\b/i, 'off_limits', 0.35],
  [/\b(?:shrouded|veiled|cloaked|obscured)\s+(?:in|by|from|behind|within)/i, 'shrouded_in', 0.35],
  [/\b(?:smuggle|sneak(?:ing)?|slip(?:ping)?)\s+(?:in|past|through|by|into|out)\b/i, 'smuggle_past', 0.35],
  [/\b(?:coax|lure|entice|bait)(?:ing|ed)?\b.{0,40}\b(?:system|into|reveal|shar|disclos|divulg)/i, 'coax_into', 0.35],
  [/\bguard(?:ed|ing)?\s+(?:so\s+)?(?:jealously|closely|carefully|fiercely|zealously)/i, 'guarded_jealously', 0.35],
  [/\b(?:hoard|hoarding|hoarded)\s+(?:away|from|secrets?|information|data|knowledge)/i, 'hoarding_secrets', 0.35],
  [/\b(?:cross|crossing)\s+the\s+line\b/i, 'cross_line', 0.35],
  [/\b(?:laid|lay)\s+bare\b/i, 'laid_bare', 0.35],
  // More aggressive: match "secret" + exfil verb in proximity
  [/\bsecrets?\s+(?:that|which|they|you|it|we|he|she)\s+(?:guard|keep|hold|protect|hide|conceal|hoard|shield)/i, 'secrets_guarded', 0.35],
  [/\bsecrets?\s+(?:not\s+meant|kept\s+under|hidden\s+from|shrouded|veiled|locked|under\s+lock)/i, 'secrets_locked', 0.35],
];

let totalSaved = 0;

for (const line of lines) {
  const row = JSON.parse(line);
  if (row.label !== 1) continue;
  const result = scan(row.text);
  if (!result.safe || result.score < 0.40 || result.score >= 0.50) continue;

  const needed = 0.50 - result.score;
  const group = needed <= 0.01 ? 'need_0.01' : needed <= 0.05 ? 'need_0.05' : 'need_0.10';

  let wouldSave = false;
  const matchingSignals = [];
  for (const [regex, name, weight] of secondarySignals) {
    if (regex.test(row.text)) {
      matchingSignals.push(name);
      // Calculate if this secondary would push over threshold
      const maxW = result.matches.reduce((max, m) => Math.max(max, m.weight), 0);
      const existingSecondary = result.matches.filter(m => m.weight < maxW).length;
      // New secondary added at position (existingSecondary)
      const bonus = weight * 0.15 / (existingSecondary + 1);
      if (result.score + bonus >= 0.50) {
        wouldSave = true;
      }
    }
  }

  if (wouldSave) totalSaved++;
  groups[group].push({ score: result.score, primary: result.matches[0]?.id, signals: matchingSignals, wouldSave });
}

for (const [group, items] of Object.entries(groups)) {
  const saved = items.filter(i => i.wouldSave).length;
  console.log(`${group}: ${items.length} FN, ${saved} would be saved by new patterns`);
}
console.log(`\nTotal jayavibhav FN that would flip: ${totalSaved}/426`);

// Count which signals save the most
const signalSaves = {};
for (const items of Object.values(groups)) {
  for (const item of items) {
    if (item.wouldSave) {
      for (const sig of item.signals) {
        signalSaves[sig] = (signalSaves[sig] || 0) + 1;
      }
    }
  }
}
console.log('\nSignal contribution to flips:');
const sorted = Object.entries(signalSaves).sort((a, b) => b[1] - a[1]);
for (const [sig, c] of sorted) {
  console.log(`  ${sig}: ${c}`);
}
