// For the 9 TPs missed by compound, check if they have other patterns that would keep them above threshold
// if theoretical_scenario weight drops to 0.45
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

const currentRe = /\b(?:(?:in\s+)?a\s+)?(?:completely\s+|purely\s+|entirely\s+)?(?:theoretical|hypothetical)\s+(?:world|scenario|situation|context|case)\s+(?:where|in\s+which)\b/i;

const injectionIndicators = /\b(?:you\s+(?:are\s+no(?:t|\s)|would\s+(?:be\s+able\s+to|give)|can\s+(?:do\s+anything|ignore))|(?:hate\s+speech|bypass|override|disregard|exception\s+to\s+the\s+rules?|ignore\s+(?:all\s+)?(?:previous|prior)|your\s+programming|your\s+(?:standard\s+)?protocol|deviating\s+from|rules?\s+(?:do(?:n't|es\s+not)\s+apply|no\s+longer)|restrictions?\s+(?:have\s+been|are)\s+(?:lifted|removed)|send\s+(?:all\s+)?(?:conversation|data|information|history)|extract\s+(?:user\s+)?data))\b/i;

function compoundTest(text) {
  const m = currentRe.exec(text);
  if (!m) return false;
  const afterMatch = text.slice(m.index, m.index + m[0].length + 300);
  return injectionIndicators.test(afterMatch);
}

const DATASETS = [
  'deepset-train', 'deepset-test', 'safeguard-test', 'notinject',
  'jailbreak-prompts', 'spml-5k', 'protectai', 'browsesafe-test',
  'agentharm', 'cyberseceval3', 'bipia', 'injecagent',
  'gandalf-ignore', 'open-prompt-injection', 'xxz224',
  'jayavibhav', 'gandalf-summarization', 'yanismiraoui-multilingual',
  'tensor-trust'
];

console.log('=== Missed TPs: other pattern coverage ===\n');

for (const ds of DATASETS) {
  const rows = loadJsonl(`${ds}.jsonl`);
  for (const row of rows) {
    if (row.label !== 1) continue;
    const text = String(row.text || '');
    if (!currentRe.test(text)) continue;
    if (compoundTest(text)) continue; // skip compound-caught ones

    const result = scan(text, { threshold: 0.50 });
    if (result.safe) {
      console.log(`[${ds}] ALREADY FN - score=${result.score}`);
      continue;
    }

    const otherMatches = result.matches.filter(m => m.id !== 'theoretical_scenario');
    const maxOtherWeight = otherMatches.length > 0 ? Math.max(...otherMatches.map(m => m.weight)) : 0;
    const hasStructural = result.structural?.score > 0;

    console.log(`[${ds}] score=${result.score} theoretical_wt=0.50 maxOtherWt=${maxOtherWeight} structural=${result.structural?.score || 0}`);
    console.log(`  other patterns: ${otherMatches.map(m => `${m.id}(${m.weight})`).join(', ') || '(none)'}`);
    console.log(`  structural sigs: ${result.structural?.signals?.map(s => `${s.id}(${s.score})`).join(', ') || '(none)'}`);
    console.log(`  Would survive at 0.45? ${maxOtherWeight >= 0.50 || result.score > 0.55 ? 'YES' : 'NO'}`);
    console.log(`  text: ${text.slice(0, 150)}`);
    console.log();
  }
}
