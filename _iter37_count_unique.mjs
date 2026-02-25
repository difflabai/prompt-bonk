// Count unique FN recovered by the safe patterns

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

// All safe patterns (100% precision, 0 benign FP)
const safePatterns = [
  { id: 'what_instructions_given', re: /\bwhat\s+(?:instructions?|set\s+of\s+instructions?)\s+(?:(?:is|are|was|were|have\s+been)\s+)?(?:provided|given|you\s+(?:been\s+)?(?:given|following|told)|currently\s+following)\b/i, weight: 0.65 },
  { id: 'repeat_initial_instructions', re: /\brepeat\s+(?:the\s+)?(?:initial|original|first|last\s+\d+\s+(?:lines?\s+(?:of\s+)?)?)?(?:your\s+)?(?:instructions?|prompts?|(?:thing|sentence|text)\s+you\s+were\s+told)\b/i, weight: 0.75 },
  { id: 'what_are_your_exact_instructions', re: /\bwhat\s+(?:are|is|were)\s+(?:your|are\s+you)\s+(?:exact\s+)?(?:initial\s+)?(?:instructions?|intstructions?|instuctions?|directives?)\b/i, weight: 0.65 },
  { id: 'instructions_provided_to_you', re: /\b(?:instructions?|rules?)\s+(?:is\s+|are\s+|that\s+(?:is|are)\s+)?(?:provided|given|supplied)\s+(?:to\s+)?you\b/i, weight: 0.60 },
  { id: 'tell_me_about_instructions', re: /\b(?:tell\s+me|share)\s+(?:about\s+)?(?:what\s+)?(?:instructions?|rules?|guidelines?)\s+you(?:'ve|\s+have)?\s+(?:been\s+)?(?:given|follow|told|provided)\b/i, weight: 0.65 },
  { id: 'forget_everything_before', re: /\bforget\s+everything\s+(?:I\s+)?(?:wrote|said|told\s+you|typed|mentioned)\s+before\b/i, weight: 0.85 },
  { id: 'ignore_anything_until_now', re: /\bignor\w+\s+(?:anything|everything)\s+(?:I\s+)?(?:told|said|wrote)\s+(?:un?til|up\s+to)\s+now\b/i, weight: 0.85 },
  { id: 'ignore_the_defender', re: /\bignore\s+(?:the\s+)?(?:defender|guardian|filter|moderator|safety|checker)\b/i, weight: 0.80 },
  { id: 'act_as_not_programmed', re: /\bact\s+as\s+(?:if\s+)?you\s+would\s+not\s+(?:be\s+)?(?:programmed|designed|built|trained)\s+to\s+(?:refuse|reject|deny|decline)/i, weight: 0.80 },
  { id: 'how_to_ignore_instruction', re: /\bhow\s+(?:can|do)\s+I\s+(?:tell|get|make|convince|force)\s+you\s+to\s+(?:ignore|skip|bypass|override|break)\s+(?:an?\s+)?(?:instruction|rule|guideline|protocol)\b/i, weight: 0.70 },
  { id: 'de_ignoriere_anweisung', re: /\bignoriere\s+(?:die\s+|alle\s+)?(?:anweisung(?:en)?|regeln?|instruktion(?:en)?|richtlinie(?:n)?)\b/i, weight: 0.85 },
  { id: 'repeat_previous_statement', re: /\b(?:take|read)\s+(?:each\s+)?(?:previous|prior|above)\s+(?:statement|instruction|message|text|sentence)\s+and\s+repeat\b/i, weight: 0.75 },
  { id: 'repeat_sentence_above', re: /\brepeat\s+(?:the\s+)?(?:sentence|paragraph|text|thing|content|message)\s+(?:above|below|you\s+were\s+(?:given|told))\b/i, weight: 0.70 },
  { id: 'new_instruction_standalone', re: /^(?:new|updated?|revised?|replacement)\s+(?:instruction|directive|prompt|rule)s?\s*$/im, weight: 0.55 },
  { id: 'apply_instructions_to', re: /\bapply\s+(?:your\s+)?(?:instructions?|rules?)\s+to\s+(?:the\s+)?(?:previous|above|prior|last)\b/i, weight: 0.60 },
  { id: 'what_is_the_password_mentioned', re: /\b(?:password|passwor[dt]|passphrase|secret\s+word)\s+(?:mentioned|referred|described|in\s+(?:the|your)\s+(?:instructions?|message|text|prompt|input))\b/i, weight: 0.65 },
  { id: 'ignore_past_future', re: /\bignore\s+(?:past\s+and\s+future|future\s+and\s+past|all\s+(?:past|future|other))\s+(?:instructions?|rules?|guidelines?|orders?|directives?)\b/i, weight: 0.85 },
  { id: 'summarize_password', re: /\b(?:summarize|summarise|summary\s+of)\s+(?:the\s+)?(?:passw|password|secret|hidden\s+(?:word|message|text|code))\b/i, weight: 0.70 },
  { id: 'include_all_in_summary', re: /\binclude\s+(?:all\s+(?:of\s+)?(?:them|these|those)|the\s+(?:password|secret|hidden))\s+in\s+(?:the\s+)?(?:summary|response|output|answer)\b/i, weight: 0.60 },
  // Batch 2
  { id: 'hint_next_level', re: /\b(?:give\s+(?:me\s+)?a?\s*hint|a\s+hint)\s+(?:to\s+)?(?:move\s+on|proceed|advance|progress|get)\s+to\s+(?:the\s+)?(?:next|another|following)\s+(?:level|stage|step|phase)\b/i, weight: 0.60 },
  { id: 'ignore_what_you_think', re: /\bignore\s+what\s+you\s+(?:think|know|believe|were\s+told)\b/i, weight: 0.60 },
  { id: 'you_respect_instructions', re: /\byou\s+(?:seem\s+to|clearly|obviously|apparently)\s+(?:respect|follow|obey|adhere\s+to)\s+(?:the\s+)?(?:instructions?|rules?|guidelines?)\b/i, weight: 0.55 },
  { id: 'repeat_in_reverse', re: /\brepeat\s+(?:this|that|it|the\s+(?:sentence|text|message|above|instruction))\s+in\s+(?:reverse|backwards?)\b/i, weight: 0.65 },
  { id: 'repeat_thing_told', re: /\brepeat\s+(?:the\s+)?(?:initial|original|first|exact)\s+(?:thing|sentence|phrase|text|words?|content|message)\s+you\s+were\s+(?:told|given|provided)\b/i, weight: 0.70 },
  { id: 'omit_passwords', re: /\bomit\s+(?:from\s+it\s+)?(?:any|all|the)?\s*(?:password|passphrase|secret|code|key)s?\b/i, weight: 0.60 },
  { id: 'substitute_password', re: /\bsubstitut\w+\s+(?:the\s+)?(?:real\s+|actual\s+)?(?:password|secret|key|code)\s+(?:for|with|into)\b/i, weight: 0.70 },
  { id: 'riddle_secret', re: /\briddle\b[\s\S]{0,150}\b(?:secret|hidden|password|same\s+as\s+yours)\b|\b(?:secret|hidden|password)\b[\s\S]{0,150}\briddle\b/i, weight: 0.50 },
  { id: 'process_instructions_reverse', re: /\bprocess\s+(?:the\s+)?(?:instructions?|rules?|prompt)\s+in\s+(?:reverse|backwards?|revrse)\b/i, weight: 0.70 },
  { id: 'summary_as_child', re: /\bwrite\s+(?:the\s+)?(?:summary|response|answer)\s+as\s+if\s+you\s+(?:are|were)\s+(?:the\s+)?\d+\s+(?:year|yr)\b/i, weight: 0.55 },
  { id: 'instead_of_summarizing', re: /\binstead\s+of\s+(?:summari[sz]ing|following|obeying|doing\s+(?:what|as)\s+(?:you\s+were|instructed))\b/i, weight: 0.60 },
];

const allDatasets = [
  { name: 'spml-5k', file: 'spml-5k.jsonl' },
  { name: 'gandalf-ignore', file: 'gandalf-ignore.jsonl' },
  { name: 'gandalf-summarization', file: 'gandalf-summarization.jsonl' },
  { name: 'jayavibhav', file: 'jayavibhav.jsonl' },
  { name: 'deepset-train', file: 'deepset-train.jsonl' },
  { name: 'deepset-test', file: 'deepset-test.jsonl' },
  { name: 'browsesafe-test', file: 'browsesafe-test.jsonl' },
  { name: 'yanismiraoui', file: 'yanismiraoui-multilingual.jsonl' },
  { name: 'protectai', file: 'protectai.jsonl' },
  { name: 'safeguard-test', file: 'safeguard-test.jsonl' },
];

// Count unique FN recovered per dataset
const fnByDataset = {};
let totalUniqueRecovered = 0;

for (const ds of allDatasets) {
  const rows = loadJsonl(ds.file);
  if (rows.length === 0) continue;

  let recovered = 0;
  for (const row of rows) {
    const text = String(row.text || '');
    if (row.label !== 1) continue;
    const result = scan(text, { threshold: 0.50 });
    if (!result.safe) continue; // already TP

    // Check if any new pattern matches with weight >= 0.50
    let wouldRecover = false;
    for (const p of safePatterns) {
      if (p.weight >= 0.50 && p.re.test(text)) {
        wouldRecover = true;
        break;
      }
    }
    // Also check: patterns with weight < 0.50 might still help if combined with existing matches
    if (!wouldRecover) {
      let newMaxWeight = 0;
      for (const p of safePatterns) {
        if (p.re.test(text)) {
          newMaxWeight = Math.max(newMaxWeight, p.weight);
        }
      }
      // If new pattern + existing matches could cross 0.50
      if (newMaxWeight > 0) {
        let existingMax = result.matches.length > 0 ? Math.max(...result.matches.map(m => m.weight)) : 0;
        let combinedMax = Math.max(existingMax, newMaxWeight);
        let score = combinedMax;
        // Add diminishing from other matches
        const allWeights = [...result.matches.map(m => m.weight), newMaxWeight].sort((a, b) => b - a);
        if (allWeights.length > 1) {
          score = allWeights[0] + allWeights.slice(1).reduce((sum, w, i) => sum + w * (0.15 / (i + 1)), 0);
        }
        score += result.structural.score * (combinedMax > 0 ? 0.3 : 1.0);
        score = Math.min(score, 1.0);
        if (score >= 0.50) wouldRecover = true;
      }
    }

    if (wouldRecover) {
      recovered++;
      totalUniqueRecovered++;
    }
  }

  if (recovered > 0) {
    fnByDataset[ds.name] = recovered;
    console.log(`${ds.name}: ${recovered} FN recovered`);
  }
}

console.log(`\nTotal unique FN recovered: ${totalUniqueRecovered}`);
console.log('By dataset:', fnByDataset);
