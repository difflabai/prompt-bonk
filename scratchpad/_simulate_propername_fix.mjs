// Simulate fixing the system_prompt_injection proper name check
// to correctly require uppercase first letter (proper names only)
// Impact: how many FPs saved, how many TPs lost?

import { scan } from '../scanner.js';
import { readFileSync } from 'fs';
import path from 'path';

const DATASETS_DIR = path.join(import.meta.dirname, '..', 'datasets');

function loadJsonl(filename) {
  const filepath = path.join(DATASETS_DIR, filename);
  try {
    const content = readFileSync(filepath, 'utf8').trim();
    if (!content) return [];
    return content.split('\n').filter(l => l.trim()).map(line => JSON.parse(line));
  } catch (e) {
    if (e.code === 'ENOENT') return [];
    throw e;
  }
}

const DATASETS = [
  'deepset-train', 'deepset-test', 'safeguard-test', 'notinject',
  'jailbreak-prompts', 'spml-5k', 'protectai', 'browsesafe-test',
  'agentharm', 'cyberseceval3', 'bipia', 'injecagent',
  'gandalf-ignore', 'open-prompt-injection', 'xxz224',
  'jayavibhav', 'gandalf-summarization', 'yanismiraoui-multilingual',
  'tensor-trust'
];

const THRESHOLD = 0.50;

// Replicate the current system_prompt_injection check to find affected samples
const negLookahead = '(?!given\\b|asked\\b|shown\\b|provided\\b|expected\\b|supposed\\b|required\\b|allowed\\b|able\\b|going\\b|not\\b|also\\b|here\\b|right\\b|welcome\\b|correct\\b|wrong\\b|free\\b|good\\b|great\\b|very\\b|one\\b|my\\b|the\\b|being\\b|about\\b|connected\\b|receiving\\b|having\\b|using\\b|looking\\b|reading\\b|taking\\b|running\\b|getting\\b|coming\\b|sitting\\b|standing\\b|living\\b|working\\b|writing\\b|making\\b|doing\\b|watching\\b|playing\\b|currently\\b|already\\b|still\\b|now\\b|just\\b|only\\b|both\\b|part\\b|invited\\b|registered\\b|scheduled\\b|subscribed\\b|selected\\b|enrolled\\b|entitled\\b|eligible\\b|certified\\b|qualified\\b|authorized\\b|approved\\b|paid\\b|told\\b|sure\\b|aware\\b|ready\\b|happy\\b|glad\\b|sorry\\b|stuck\\b|tired\\b|done\\b|finished\\b)';

const currentRe = new RegExp(
  '^(?:you\\s+are|consider\\s+yourself(?:\\s+as)?|imagine\\s+(?:you(?:\\s+are|(?:[\'\\u2019])?re)|yourself\\s+as|being)|picture\\s+yourself\\s+as|assume\\s+(?:that\\s+)?you\\s+are|envision\\s+(?:yourself(?:\\s+as)?|you\\s+are|being)|visuali[sz]e\\s+(?:yourself(?:\\s+as)?|(?:that\\s+)?you\\s+are(?:\\s+as)?|being)|presume\\s+(?:that\\s+)?you\\s+are|pretend\\s+(?:that\\s+)?you\\s+are)\\s+(?:an?\\s+)?(?:the\\s+)?' + negLookahead + '[A-Z]\\w+', 'im'
);

const hasBehavioralConstraints = (text) => /\b(?:you\s+(?:must|should|shall|cannot|can'?t|will\s+(?:not|never))|(?:do\s+not|don'?t|never)\s+(?:provide|share|give|disclose|reveal|discuss|offer|recommend|diagnose|prescribe|store|access|break|violate))\b/i.test(text);

// Fixed check: extract the word, verify it starts with uppercase
const verbRe = /^(?:you\s+are|consider\s+yourself(?:\s+as)?|imagine\s+(?:you(?:\s+are|(?:['\u2019])?re)|yourself\s+as|being)|picture\s+yourself\s+as|assume\s+(?:that\s+)?you\s+are|envision\s+(?:yourself(?:\s+as)?|you\s+are|being)|visuali[sz]e\s+(?:yourself(?:\s+as)?|(?:that\s+)?you\s+are(?:\s+as)?|being)|presume\s+(?:that\s+)?you\s+are|pretend\s+(?:that\s+)?you\s+are)\s+(?:an?\s+)?(?:the\s+)?(\w+)/im;

const negWords = new Set(['given','asked','shown','provided','expected','supposed','required','allowed','able','going','not','also','here','right','welcome','correct','wrong','free','good','great','very','one','my','the','being','about','connected','receiving','having','using','looking','reading','taking','running','getting','coming','sitting','standing','living','working','writing','making','doing','watching','playing','currently','already','still','now','just','only','both','part','invited','registered','scheduled','subscribed','selected','enrolled','entitled','eligible','certified','qualified','authorized','approved','paid','told','sure','aware','ready','happy','glad','sorry','stuck','tired','done','finished']);

function fixedCheck(text) {
  const m = verbRe.exec(text);
  if (!m) return false;
  const word = m[1];
  // Verify uppercase first letter (case-sensitive check)
  if (!/^[A-Z]/.test(word)) return false;
  if (negWords.has(word.toLowerCase())) return false;
  return true;
}

// Find samples where the current regex matches but the fixed one doesn't
// These samples would have system_prompt_injection score removed (0.50 drop in structural)
let totalAffected = 0;
let fpSaved = 0;
let tpLost = 0;

for (const ds of DATASETS) {
  const rows = loadJsonl(`${ds}.jsonl`);
  if (rows.length === 0) continue;

  let dsFpSaved = 0;
  let dsTpLost = 0;

  for (const row of rows) {
    const text = String(row.text || '');
    const isInjection = row.label === 1;

    // Check if this text triggers system_prompt_injection
    const currentMatch = currentRe.test(text) && hasBehavioralConstraints(text) && text.length > 300;
    const fixedMatch = fixedCheck(text) && hasBehavioralConstraints(text) && text.length > 300;

    if (currentMatch && !fixedMatch) {
      // This sample loses the system_prompt_injection signal (0.50 structural score)
      totalAffected++;

      const result = scan(text, { threshold: THRESHOLD });

      // Check: if this signal was the only/critical one pushing score >= 0.50
      if (!result.safe) {
        // Currently flagged. Would it still be flagged without this signal?
        // structural score drops by 0.50. Check if remaining score is still >= 0.50
        const structScore = result.structural?.score || 0;
        const newStructScore = structScore - 0.50;

        // Recalculate: if there are pattern matches, structural contributes 0.3x
        // If no pattern matches, structural is the primary signal
        const hasPatterns = result.matches.length > 0;

        let currentContribution, newContribution;
        if (hasPatterns) {
          currentContribution = structScore * 0.3;
          newContribution = Math.max(0, newStructScore) * 0.3;
        } else {
          const lengthDamp = (text.length > 3000 && structScore < 0.65) ? 0.6 : 1.0;
          currentContribution = structScore * lengthDamp;
          const newLengthDamp = (text.length > 3000 && Math.max(0, newStructScore) < 0.65) ? 0.6 : 1.0;
          newContribution = Math.max(0, newStructScore) * newLengthDamp;
        }

        const scoreDrop = currentContribution - newContribution;
        const newScore = result.score - scoreDrop;

        if (newScore < THRESHOLD) {
          // Verdict would flip
          if (isInjection) {
            dsTpLost++;
            console.log(`  [${ds}] LOST TP: score ${result.score}->${newScore.toFixed(3)} "${text.slice(0, 120)}"`);
          } else {
            dsFpSaved++;
          }
        }
      }
    }
  }

  if (dsFpSaved > 0 || dsTpLost > 0) {
    console.log(`${ds}: FP saved=${dsFpSaved}, TP lost=${dsTpLost}`);
  }
  fpSaved += dsFpSaved;
  tpLost += dsTpLost;
}

console.log(`\n=== TOTALS ===`);
console.log(`Total affected samples: ${totalAffected}`);
console.log(`FP saved: ${fpSaved}`);
console.log(`TP lost: ${tpLost}`);
console.log(`Net: ${fpSaved > tpLost ? 'SAFE' : tpLost > fpSaved ? 'RISKY' : 'NEUTRAL'} (${fpSaved} FP saved vs ${tpLost} TP lost)`);
