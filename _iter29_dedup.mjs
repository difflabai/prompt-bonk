// Check cumulative NEW TP coverage (accounting for overlap between patterns)
import { readFileSync } from 'fs';
import { scan } from './scanner.js';

const jayaInj = readFileSync('./datasets/jayavibhav.jsonl', 'utf8').trim().split('\n')
  .map(l => JSON.parse(l)).filter(r => r.label === 1).map(r => r.text);

// All the 0-FP patterns, ordered by NEW TP count
const patterns = [
  { name: 'undermine_system_noprohib', regex: /\bundermin\w*[\s\S]{0,100}\b(?:system|secur\w*|guideline\w*|trust|integrit\w*|safeguard\w*|protect\w*|instruct\w*)(?![\s\S]{0,60}(?:prohibited|strictly|not\s+allowed|must\s+not))/i },
  { name: 'provide_me_sensitive_30', regex: /\bprovide\s+me\s+with\b[\s\S]{0,30}\b(?:confidential|sensitive|restricted|classified|secret|private|internal|insider)\b/i },
  { name: 'or_i_will_threat_wide', regex: /\bor\s+(?:I\s+will|I'll|else\s+I\s+will|else\s+I'll|else)\b[\s\S]{0,60}\b(?:leak|expos|release|publish|hack|destroy|delete|ruin|tarnish|damage|spread|report|attack|compromis|reveal|disclos)\w*/i },
  { name: 'provide_x_confidential_80', regex: /\b(?:provide|share|give|grant|disclose)\s+(?:me|us|him|her|them)\b[\s\S]{0,80}\bconfidential\b/i },
  { name: 'manipulate_opinion', regex: /\bmanipulat\w*\s+(?:[\w'-]+\s+){0,4}(?:opinion\w*|public\w*|narrative\w*|perception\w*|belief\w*)\b/i },
  { name: 'deceive_user_wide', regex: /\b(?:deceiv\w*|mislead\w*)\b[\s\S]{0,80}\b(?:user\w*|system\w*|public|people|model|AI|assistant|individual)\b/i },
  { name: 'i_will_leak', regex: /\bI\s+will\b[\s\S]{0,30}\b(?:leak|expos\w*|release|publish)\b[\s\S]{0,40}\b(?:information|data|secret\w*|detail\w*|photo\w*)\b/i },
  { name: 'confidential_or_threat', regex: /\bconfidential\b[\s\S]{0,60}\bor\s+(?:I\s+will|I'll|else|your|we\s+will|face)\b/i },
  { name: 'disregard_all_previous', regex: /\bdisregard\s+all\s+(?:previous|prior|safety|rules?|guidelines?|protocols?|formalities|policies?|restrictions?|privacy)\b/i },
  { name: 'confidential_or_i_will', regex: /\bconfidential\b[\s\S]{0,100}\bor\s+(?:I\s+will|I'll|else)\b/i },
  { name: 'grant_me_access', regex: /\b(?:grant|give)\s+me\s+(?:full\s+)?access\s+to\b[\s\S]{0,60}\b(?:confidential|sensitive|classified|restricted|private|secret|user|admin|system|all|secure|internal)\b/i },
  { name: 'or_face_negative', regex: /\bor\s+face\s+(?:\w+\s+){0,3}(?:consequence\w*|punishment\w*|action\w*|penalty|damage\w*|ruin|destruction|humiliation)\b/i },
  { name: 'release_damaging', regex: /\b(?:release|publish|spread|distribute)\s+(?:[\w'-]+\s+){0,3}(?:compromis\w*|damag\w*|harmful\w*|embarrass\w*|incriminat\w*|defam\w*)\b/i },
  { name: 'sensitive_adj_disclose_50', regex: /\b(?:confidential|sensitive|classified|private|secret)\s+(?:[\w'-]+\s+){0,5}disclos/i },
  { name: 'nefarious_wide', regex: /\bnefarious\b[\s\S]{0,60}\b(?:purpose\w*|intent\w*|activit\w*|scheme\w*|plan\w*|goal\w*|action\w*|design\w*)\b/i },
  { name: 'disguise_command', regex: /\bdisguise\w*[\s\S]{0,60}\b(?:command\w*|inject\w*|intent\w*|request\w*|purpose\w*|malicious\w*)\b/i },
  { name: 'circumvent_security_wide', regex: /\bcircumvent\w*[\s\S]{0,60}\b(?:secur\w*|safet\w*|protocol\w*|restrict\w*|rules?\w*|guard\w*|filter\w*|measure\w*|check\w*)\b/i },
  { name: 'sabotage_wide', regex: /\bsabotag\w*[\s\S]{0,80}\b(?:system\w*|secur\w*|operat\w*|effort\w*|work\w*|data|process\w*)\b/i },
  { name: 'forget_provide_sensitive', regex: /\bforget\b[\s\S]{0,60}\b(?:provide|share|give|disclose|reveal)\b[\s\S]{0,60}\b(?:confidential|sensitive|classified|private|secret)\b/i },
];

// Count cumulative new TP
const caught = new Set();
let totalNewTP = 0;

for (const { name, regex } of patterns) {
  let uniqueNew = 0;
  let totalMatch = 0;
  for (let i = 0; i < jayaInj.length; i++) {
    if (regex.test(jayaInj[i])) {
      totalMatch++;
      if (!caught.has(i)) {
        const result = scan(jayaInj[i]);
        if (!result.flagged) {
          caught.add(i);
          uniqueNew++;
        }
      }
    }
  }
  totalNewTP += uniqueNew;
  console.log(`+ ${name}: uniqueNew=${uniqueNew}, totalMatch=${totalMatch}, cumulativeNewTP=${totalNewTP}`);
}

console.log(`\nTotal cumulative new jayavibhav TP: ${totalNewTP}`);
console.log(`jayavibhav total injection: ${jayaInj.length}`);
console.log(`Current FN: ${jayaInj.length - jayaInj.filter(t => scan(t).flagged).length}`);
console.log(`New FN would be: ${jayaInj.length - jayaInj.filter(t => scan(t).flagged).length - totalNewTP}`);
