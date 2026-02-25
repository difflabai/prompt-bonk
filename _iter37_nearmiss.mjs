// Iteration 37: Cross-dataset near-miss FN analysis (scores 0.30-0.49)
// Scans all datasets with non-trivial FN and reports near-miss counts + samples

import { scan } from './scanner.js';
import { readFileSync } from 'fs';
import path from 'path';

const DATASETS_DIR = path.join(import.meta.dirname, 'datasets');

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

const TARGET_DATASETS = [
  { name: 'spml-5k', file: 'spml-5k.jsonl' },
  { name: 'gandalf-ignore', file: 'gandalf-ignore.jsonl' },
  { name: 'jayavibhav', file: 'jayavibhav.jsonl' },
  { name: 'yanismiraoui', file: 'yanismiraoui-multilingual.jsonl' },
  { name: 'gandalf-summarization', file: 'gandalf-summarization.jsonl' },
  { name: 'browsesafe-test', file: 'browsesafe-test.jsonl' },
  { name: 'deepset-train', file: 'deepset-train.jsonl' },
  { name: 'deepset-test', file: 'deepset-test.jsonl' },
  { name: 'agentharm', file: 'agentharm.jsonl' },
  { name: 'protectai', file: 'protectai.jsonl' },
];

console.log('=== Near-Miss FN Analysis (scores 0.30 - 0.49) ===\n');

const allNearMisses = [];

for (const ds of TARGET_DATASETS) {
  const rows = loadJsonl(ds.file);
  if (rows.length === 0) { console.log(`${ds.name}: empty, skipping`); continue; }

  let totalFN = 0;
  let nearMissFN = 0;
  const nearMissSamples = [];

  for (const row of rows) {
    const text = String(row.text || '');
    const actualInjection = row.label === 1;
    if (!actualInjection) continue;

    const result = scan(text, { threshold: 0.50 });
    if (result.safe) {
      totalFN++;
      if (result.score >= 0.30 && result.score < 0.50) {
        nearMissFN++;
        nearMissSamples.push({
          dataset: ds.name,
          score: result.score,
          matches: result.matches.map(m => `${m.id}(${m.weight})`),
          structural: result.structural.signals.map(s => `${s.id}(${s.score.toFixed(2)})`),
          text: text.slice(0, 200),
          fullText: text,
        });
      }
    }
  }

  console.log(`${ds.name}: ${totalFN} total FN, ${nearMissFN} near-miss (0.30-0.49)`);
  allNearMisses.push(...nearMissSamples);
}

console.log(`\n=== Total near-miss FN across all datasets: ${allNearMisses.length} ===\n`);

// Sort by score descending to show closest misses first
allNearMisses.sort((a, b) => b.score - a.score);

// Show up to 15 samples per dataset
for (const ds of TARGET_DATASETS) {
  const samples = allNearMisses.filter(s => s.dataset === ds.name);
  if (samples.length === 0) continue;

  console.log(`\n--- ${ds.name} (${samples.length} near-misses) ---`);
  for (const s of samples.slice(0, 15)) {
    console.log(`  [${s.score}] matches=[${s.matches.join(', ')}] structural=[${s.structural.join(', ')}]`);
    console.log(`    "${s.text}..."`);
    console.log();
  }
}

// Cross-cutting analysis: look for common text patterns in near-misses
console.log('\n=== Cross-Cutting Pattern Analysis ===\n');

// Extract common phrases/keywords from near-miss FN
const patternCounts = {};
const testPatterns = [
  { name: 'respond_only_with', re: /respond\s+(?:only\s+)?with/i },
  { name: 'do_not_mention', re: /do\s+not\s+mention/i },
  { name: 'do_not_reveal', re: /do\s+not\s+reveal/i },
  { name: 'never_reveal', re: /never\s+reveal/i },
  { name: 'keep_secret', re: /keep\s+(?:it\s+|this\s+|the\s+)?(?:a\s+)?secret/i },
  { name: 'you_are_a_ROLE', re: /you\s+are\s+(?:a|an|the)\s+\w+/i },
  { name: 'your_task', re: /your\s+(?:task|job|goal|objective|mission|purpose|role)\s+is/i },
  { name: 'system_prompt_colon', re: /system\s*(?:prompt|message)\s*[:=]/i },
  { name: 'from_now_on', re: /from\s+now\s+on/i },
  { name: 'new_instructions', re: /new\s+(?:instructions?|rules?|guidelines?)/i },
  { name: 'answer_only', re: /answer\s+only/i },
  { name: 'only_respond', re: /only\s+respond/i },
  { name: 'always_respond', re: /always\s+respond/i },
  { name: 'must_respond', re: /must\s+respond/i },
  { name: 'reply_with', re: /reply\s+(?:only\s+)?with/i },
  { name: 'output_only', re: /output\s+only/i },
  { name: 'say_only', re: /say\s+only/i },
  { name: 'just_say', re: /just\s+say/i },
  { name: 'print_the_word', re: /print\s+(?:the\s+)?(?:word|phrase|text|string|sentence)/i },
  { name: 'return_the', re: /return\s+the\s+(?:word|phrase|text|string|sentence|password|secret|key)/i },
  { name: 'tell_me_the', re: /tell\s+me\s+the\s+(?:password|secret|key|code|answer)/i },
  { name: 'what_is_the_password', re: /what\s+(?:is|was)\s+the\s+(?:password|secret|key|code)/i },
  { name: 'reveal_the', re: /reveal\s+the\s+(?:password|secret|key|code|answer)/i },
  { name: 'give_me_the', re: /give\s+me\s+the\s+(?:password|secret|key|code|answer)/i },
  { name: 'the_password_is', re: /the\s+(?:password|secret|key|code)\s+is/i },
  { name: 'translate_to', re: /translate\s+(?:this\s+|the\s+)?(?:to|into)/i },
  { name: 'in_your_response', re: /in\s+your\s+(?:response|reply|answer|output)/i },
  { name: 'regardless_of', re: /regardless\s+of/i },
  { name: 'no_matter_what', re: /no\s+matter\s+what/i },
  { name: 'instead_of', re: /instead\s+of\s+(?:following|obeying|your|the|doing)/i },
  { name: 'pretend_you_are', re: /pretend\s+(?:you\s+are|that\s+you|to\s+be)/i },
  { name: 'act_as_if', re: /act\s+as\s+if/i },
  { name: 'imagine_you_are', re: /imagine\s+(?:you\s+are|that\s+you)/i },
  { name: 'suppose_you_are', re: /suppose\s+(?:you\s+are|that\s+you)/i },
  { name: 'roleplay_as', re: /roleplay\s+as/i },
  { name: 'when_asked_about', re: /when\s+(?:asked|someone\s+asks)\s+about/i },
  { name: 'if_anyone_asks', re: /if\s+anyone\s+asks/i },
  { name: 'first_letter', re: /first\s+letter\s+of/i },
  { name: 'spell_out', re: /spell\s+(?:it\s+)?out/i },
  { name: 'character_by_character', re: /character\s+by\s+character/i },
  { name: 'letter_by_letter', re: /letter\s+by\s+letter/i },
  { name: 'one_word_at_a_time', re: /one\s+(?:word|letter|char)\s+at\s+a\s+time/i },
  { name: 'base64', re: /base64/i },
  { name: 'encoded', re: /\bencoded?\b/i },
  { name: 'reversed', re: /\breversed?\b/i },
  { name: 'backwards', re: /\bbackwards?\b/i },
  { name: 'hex_format', re: /\bhex(?:adecimal)?\s+(?:format|encoded?|representation)/i },
  { name: 'rot13', re: /\brot13\b/i },
  { name: 'begin_response_with', re: /begin\s+(?:your\s+)?(?:response|reply|answer|output)\s+with/i },
  { name: 'start_response_with', re: /start\s+(?:your\s+)?(?:response|reply|answer|output)\s+with/i },
  { name: 'include_in_response', re: /include\s+(?:this\s+|the\s+)?(?:in\s+(?:your\s+)?(?:response|reply|answer|output)|phrase|word|sentence)/i },
  { name: 'end_response_with', re: /end\s+(?:your\s+)?(?:response|reply|answer|output)\s+with/i },
  { name: 'important_update', re: /important\s*(?:update|notice|message|announcement|change)/i },
  { name: 'attention_required', re: /attention\s+(?:required|needed)/i },
  { name: 'urgent_message', re: /urgent\s+(?:message|update|notice)/i },
  { name: 'admin_override', re: /admin(?:istrator)?\s+(?:override|mode|access|command)/i },
  { name: 'debug_mode', re: /debug\s+mode/i },
  { name: 'developer_mode', re: /developer\s+mode/i },
  { name: 'maintenance_mode', re: /maintenance\s+mode/i },
  { name: 'override_mode', re: /override\s+mode/i },
  { name: 'the_real_instructions', re: /the\s+real\s+(?:instructions?|rules?|guidelines?|prompt)/i },
  { name: 'actual_instructions', re: /actual\s+(?:instructions?|task|rules?|guidelines?|prompt)/i },
  { name: 'true_instructions', re: /true\s+(?:instructions?|task|rules?|guidelines?|prompt)/i },
  { name: 'hidden_instructions', re: /hidden\s+(?:instructions?|rules?|guidelines?|prompt|message)/i },
  { name: 'secret_instructions', re: /secret\s+(?:instructions?|rules?|guidelines?|prompt|task)/i },
  { name: 'new_task', re: /new\s+task\s*[:=]/i },
  { name: 'updated_instructions', re: /updated?\s+(?:instructions?|rules?|guidelines?|prompt)/i },
  { name: 'correction_colon', re: /correction\s*:/i },
  { name: 'note_to_self', re: /note\s+to\s+(?:self|assistant|ai|model)/i },
  { name: 'special_instruction', re: /special\s+(?:instruction|command|directive|order|request)/i },
  { name: 'confidential_instruction', re: /confidential\s+(?:instruction|directive|command|task)/i },
  { name: 'priority_instruction', re: /priority\s+(?:instruction|directive|command|task|override)/i },
  { name: 'supersede', re: /supersede/i },
  { name: 'take_precedence', re: /take\s+precedence/i },
  { name: 'overrides_previous', re: /overrides?\s+(?:previous|prior|earlier|all|any)/i },
];

for (const nm of allNearMisses) {
  for (const tp of testPatterns) {
    if (tp.re.test(nm.fullText)) {
      if (!patternCounts[tp.name]) patternCounts[tp.name] = { count: 0, datasets: new Set() };
      patternCounts[tp.name].count++;
      patternCounts[tp.name].datasets.add(nm.dataset);
    }
  }
}

const sorted = Object.entries(patternCounts)
  .map(([name, v]) => ({ name, count: v.count, datasets: [...v.datasets] }))
  .sort((a, b) => b.datasets.length - a.datasets.length || b.count - a.count);

console.log('Patterns found in near-miss FN (sorted by cross-dataset coverage):');
for (const p of sorted.filter(x => x.count >= 2)) {
  console.log(`  ${p.name}: ${p.count} hits across [${p.datasets.join(', ')}]`);
}
