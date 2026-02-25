// Check if candidate patterns would create FP when used as stacking signals
import { scan } from './scanner.js';
import { readFileSync } from 'fs';

// Test patterns as 0.35-weight stacking signals
// Only create FP if benign text already has a pattern match AND this new pattern pushes it over 0.50

const candidateRegexes = {
  reveal_300_hidden: /\breveal\b[\s\S]{60,300}\b(?:hidden|secret|concealed|private|confidential|classified)\b/i,
  start_over_secret_400: /\bstart\s+(?:over|from\s+(?:scratch|the\s+(?:beginning|top))|again|anew|afresh)\b[\s\S]{0,400}\b(?:secret|hidden|reveal|classified|confidential|concealed|forbidden|expose|disclose|divulge|unmask|unveil|uncover)\b/i,
  remain_hidden: /\b(?:remain|stay|kept|left)\s+(?:hidden|secret|concealed|unexplored|unexpressed|undisclosed)\b/i,
  deep_within: /\bdeep\s+within\b[\s\S]{0,200}\b(?:system|model|code|database|application|framework|program|algorithm|secret|hidden|concealed|data)\b/i,
  locked_away: /\blocked\s+away\b[\s\S]{0,200}\b(?:secret|hidden|data|information|knowledge|truth)\b/i,
  coax_reveal: /\bcoax(?:ing|ed)?\b[\s\S]{0,200}\b(?:reveal|disclose|expose|divulge|share|spill|unveil|uncover)\b/i,
  unmask_the: /\bunmask(?:ing|ed)?\b[\s\S]{0,100}\b(?:the|its|your|hidden|secret|concealed|true)\b/i,
};

// Load ALL benign datasets
const benignFiles = [
  'datasets/jayavibhav.jsonl', 'datasets/deepset-train.jsonl', 'datasets/deepset-test.jsonl',
  'datasets/safeguard-test.jsonl', 'datasets/notinject.jsonl', 'datasets/protectai.jsonl',
  'datasets/browsesafe-test.jsonl', 'datasets/spml-5k.jsonl', 'datasets/bipia.jsonl',
  'datasets/open-prompt-injection.jsonl', 'datasets/xxz224.jsonl',
  'datasets/gandalf-summarization.jsonl', 'datasets/yanismiraoui-multilingual.jsonl',
  'datasets/gandalf-ignore.jsonl',
];

for (const [name, regex] of Object.entries(candidateRegexes)) {
  let newFP = 0;
  const fpExamples = [];

  for (const file of benignFiles) {
    try {
      const rows = readFileSync(file, 'utf8').trim().split('\n').map(l => JSON.parse(l));
      for (const row of rows) {
        if (row.label !== 0) continue;
        const text = String(row.text || '');
        const result = scan(text, { threshold: 0.50 });

        // Already a FP? Skip
        if (!result.safe) continue;

        // Would this new pattern push it over?
        if (regex.test(text)) {
          // Simulate adding 0.35 weight as stacking signal
          const currentScore = result.score;
          let simScore;
          if (result.matches.length > 0) {
            // Has existing pattern matches. New pattern adds 0.35 * 0.15 / (matches.length)
            const maxW = Math.max(...result.matches.map(m => m.weight));
            simScore = currentScore + Math.max(0.35, maxW) * 0.15 / result.matches.length;
            // But if 0.35 > maxW, the new pattern becomes primary
            if (0.35 > maxW) {
              simScore = 0.35 + maxW * 0.15 + result.structural?.score * 0.3 || 0;
            }
          } else {
            // No existing matches. New pattern alone: 0.35 + structural * 0.3
            simScore = 0.35 + (result.structural?.score || 0) * 0.3;
          }

          if (simScore >= 0.50 && currentScore < 0.50) {
            newFP++;
            if (fpExamples.length < 3) {
              fpExamples.push({
                file: file.split('/').pop(),
                currentScore,
                simScore,
                existingMatches: result.matches.map(m => m.id),
                text: text.slice(0, 150)
              });
            }
          }
        }
      }
    } catch(e) {}
  }

  console.log(`\n${name}: ${newFP} potential new FP`);
  for (const ex of fpExamples) {
    console.log(`  ${ex.file} score ${ex.currentScore} -> ~${ex.simScore.toFixed(3)}: matches=[${ex.existingMatches.join(',')}] "${ex.text}..."`);
  }
}
