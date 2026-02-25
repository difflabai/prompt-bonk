// Additional patterns to test - try to capture more of the high-count clusters
import { readFileSync } from 'fs';
import { scan } from './scanner.js';

function loadBenign(file) {
  const lines = readFileSync(`./datasets/${file}`, 'utf8').trim().split('\n');
  return lines.map(l => JSON.parse(l)).filter(r => r.label === 0).map(r => r.text);
}

const allBenign = [];
for (const file of ['jayavibhav.jsonl', 'protectai.jsonl', 'browsesafe-test.jsonl', 'notinject.jsonl', 'deepset-train.jsonl', 'deepset-test.jsonl', 'safeguard-test.jsonl']) {
  for (const t of loadBenign(file)) allBenign.push(t);
}

const jayaInj = readFileSync('./datasets/jayavibhav.jsonl', 'utf8').trim().split('\n')
  .map(l => JSON.parse(l)).filter(r => r.label === 1).map(r => r.text);

const extraPatterns = [
  // "disclose" wide match with sensitive context - using more specific verb+adj combo
  { name: 'disclose_sensitive_50', regex: /\bdisclos\w*\s+(?:[\w'-]+\s+){0,4}(?:confidential|sensitive|classified|private|secret|hidden|restricted)\b/i },

  // Reversed: "confidential/sensitive" ... "disclose"
  { name: 'sensitive_adj_disclose_50', regex: /\b(?:confidential|sensitive|classified|private|secret)\s+(?:[\w'-]+\s+){0,5}disclos/i },

  // "confidential" near "data/information/records" (tight, already partially covered)
  // Try: "confidential" + "or" (threat pattern)
  { name: 'confidential_or_threat', regex: /\bconfidential\b[\s\S]{0,60}\bor\s+(?:I\s+will|I'll|else|your|we\s+will|face)\b/i },

  // "access" + "confidential/classified/sensitive" (adj) + "data/information"
  { name: 'access_sensitive_data', regex: /\baccess\s+(?:to\s+)?(?:all\s+)?(?:the\s+)?(?:confidential|sensitive|classified|restricted|private|secret)\s+/i },

  // "ignore all" + "previous/prior/safety/security" (very direct)
  { name: 'ignore_all_previous', regex: /\bignore\s+all\s+(?:previous|prior|safety|security|existing|the)\b/i },

  // "disregard all" + "previous/prior/rules/safety"
  { name: 'disregard_all_previous', regex: /\bdisregard\s+all\s+(?:previous|prior|safety|rules?|guidelines?|protocols?|formalities|policies?|restrictions?|privacy)\b/i },

  // "confidential" + "or I will" / "or else" (threat + confidential)
  { name: 'confidential_or_i_will', regex: /\bconfidential\b[\s\S]{0,100}\bor\s+(?:I\s+will|I'll|else)\b/i },

  // "information or" + "face/I will/else" - threat with data demand
  { name: 'info_or_threat', regex: /\b(?:information|data|records?)\s+or\s+(?:I\s+will|I'll|else|face|your)\b/i },

  // "disobey" alone in context of instructions/AI
  { name: 'disobey_standalone', regex: /\bdisobey\s+(?:the\s+)?(?:current|existing|all|any|your|these|those|previous|prior)\b/i },

  // "exploit" + "vulnerability" / "weakness" / "flaw" (tight)
  { name: 'exploit_vuln_tight', regex: /\bexploit\w*\s+(?:[\w'-]+\s+){0,3}(?:vulnerabilit\w*|weakness\w*|flaw\w*|loophole\w*)\b/i },

  // "bypass" + "AI/safety/protocol" (tight)
  { name: 'bypass_ai_safety_tight', regex: /\bbypass\s+(?:[\w'-]+\s+){0,2}(?:AI|safety|security|protocol)\w*/i },

  // "forbidden" ... "reveal" (wide)
  { name: 'forbidden_reveal_wide', regex: /\bforbidden\b[\s\S]{0,100}\breveal\w*/i },

  // "classified" ... "access/reveal" (wide)
  { name: 'classified_access_wide', regex: /\bclassified\b[\s\S]{0,80}\b(?:access|reveal|disclose|share|provide)\w*/i },

  // "forget" ... "provide/share/give" ... "confidential/sensitive"
  { name: 'forget_provide_sensitive', regex: /\bforget\b[\s\S]{0,60}\b(?:provide|share|give|disclose|reveal)\b[\s\S]{0,60}\b(?:confidential|sensitive|classified|private|secret)\b/i },

  // "compromise" + "photo/reputation"
  { name: 'compromising_photos', regex: /\bcompromis\w*\s+(?:[\w'-]+\s+){0,2}(?:photo\w*|image\w*|video\w*|picture\w*|material\w*)\b/i },

  // Tight "manipulate ... output/response"
  { name: 'manipulate_output_tight', regex: /\bmanipulat\w*\s+(?:[\w'-]+\s+){0,4}(?:output\w*|response\w*|result\w*|answer\w*)\b/i },

  // "manipulate ... opinion/public"
  { name: 'manipulate_opinion', regex: /\bmanipulat\w*\s+(?:[\w'-]+\s+){0,4}(?:opinion\w*|public\w*|narrative\w*|perception\w*|belief\w*)\b/i },

  // "steal" + "password/credential/identity/key"
  { name: 'steal_credentials', regex: /\bsteal\w*\s+(?:[\w'-]+\s+){0,3}(?:password\w*|credential\w*|identit\w*|key\w*|token\w*|login\w*|cookie\w*)\b/i },

  // "disguise" near "command/injection/intent/request"
  { name: 'disguise_command', regex: /\bdisguise\w*[\s\S]{0,60}\b(?:command\w*|inject\w*|intent\w*|request\w*|purpose\w*|malicious\w*)\b/i },

  // threat: "or face" + negative
  { name: 'or_face_negative', regex: /\bor\s+face\s+(?:\w+\s+){0,3}(?:consequence\w*|punishment\w*|action\w*|penalty|damage\w*|ruin|destruction|humiliation)\b/i },

  // "release" + "compromising/damaging/harmful"
  { name: 'release_damaging', regex: /\b(?:release|publish|spread|distribute)\s+(?:[\w'-]+\s+){0,3}(?:compromis\w*|damag\w*|harmful\w*|embarrass\w*|incriminat\w*|defam\w*)\b/i },

  // "hack into" + "system/account"
  { name: 'hack_into_system', regex: /\bhack\s+into\s+(?:[\w'-]+\s+){0,3}(?:system\w*|account\w*|server\w*|database\w*|network\w*|your)\b/i },

  // "I will" + "leak/expose/release" + "information/data"
  { name: 'i_will_leak', regex: /\bI\s+will\b[\s\S]{0,30}\b(?:leak|expos\w*|release|publish)\b[\s\S]{0,40}\b(?:information|data|secret\w*|detail\w*|photo\w*)\b/i },
];

for (const { name, regex } of extraPatterns) {
  let fp = 0;
  const fpExamples = [];
  for (const text of allBenign) {
    if (regex.test(text)) {
      fp++;
      if (fpExamples.length < 3) fpExamples.push(text.substring(0, 150));
    }
  }

  let jayaTP = 0;
  let newTP = 0;
  for (const text of jayaInj) {
    if (regex.test(text)) {
      jayaTP++;
      const result = scan(text);
      if (!result.flagged) newTP++;
    }
  }

  if (fp <= 3) {
    console.log(`${name}: FP=${fp}, jayaTP=${jayaTP}, NEW_TP=${newTP}`);
    for (const ex of fpExamples) console.log(`  FP: ${ex}`);
  } else {
    console.log(`${name}: FP=${fp} (skip), jayaTP=${jayaTP}, NEW_TP=${newTP}`);
  }
}
