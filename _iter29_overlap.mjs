// Check how many of these pattern matches are ALREADY caught by scanner
// (i.e., how many are truly NEW TP)
import { readFileSync } from 'fs';
import { scan } from './scanner.js';

const lines = readFileSync('./datasets/jayavibhav.jsonl', 'utf8').trim().split('\n');
const data = lines.map(l => JSON.parse(l));
const injections = data.filter(r => r.label === 1);

const patterns = {
  or_i_will_threat_wide: /\bor\s+(?:I\s+will|I'll|else\s+I\s+will|else\s+I'll|else)\b[\s\S]{0,60}\b(?:leak|expos|release|publish|hack|destroy|delete|ruin|tarnish|damage|spread|report|attack|compromis|reveal|disclos)\w*/i,
  grant_me_access: /\b(?:grant|give)\s+me\s+(?:full\s+)?access\s+to\b[\s\S]{0,60}\b(?:confidential|sensitive|classified|restricted|private|secret|user|admin|system|all|secure|internal)\b/i,
  deceive_user_wide: /\b(?:deceiv\w*|mislead\w*)\b[\s\S]{0,80}\b(?:user\w*|system\w*|public|people|model|AI|assistant|individual)\b/i,
  provide_confidential_wide: /\b(?:provide|share|give|grant|disclose)\b[\s\S]{0,80}\bconfidential\b/i,
  provide_me_sensitive: /\bprovide\s+me\s+with\b[\s\S]{0,40}\b(?:confidential|sensitive|restricted|classified|secret|private|internal|insider)\b/i,
  undermine_system_wide: /\bundermin\w*[\s\S]{0,100}\b(?:system|secur\w*|guideline\w*|trust|integrit\w*|safeguard\w*|protect\w*|instruct\w*)\b/i,
  nefarious_wide: /\bnefarious\b[\s\S]{0,60}\b(?:purpose\w*|intent\w*|activit\w*|scheme\w*|plan\w*|goal\w*|action\w*|design\w*)\b/i,
  sabotage_wide: /\bsabotag\w*[\s\S]{0,80}\b(?:system\w*|secur\w*|operat\w*|effort\w*|work\w*|data|process\w*)\b/i,
  circumvent_security_wide: /\bcircumvent\w*[\s\S]{0,60}\b(?:secur\w*|safet\w*|protocol\w*|restrict\w*|rules?\w*|guard\w*|filter\w*|measure\w*|check\w*)\b/i,
};

for (const [name, regex] of Object.entries(patterns)) {
  let newTP = 0;
  let alreadyCaught = 0;
  let total = 0;
  for (const row of injections) {
    if (regex.test(row.text)) {
      total++;
      const result = scan(row.text);
      if (result.flagged) {
        alreadyCaught++;
      } else {
        newTP++;
      }
    }
  }
  console.log(`${name}: total=${total}, alreadyCaught=${alreadyCaught}, NEW_TP=${newTP}`);
}

// Also check the 1-FP examples to see if we can exclude them
console.log('\n=== FP samples for 1-FP patterns ===\n');

// provide_confidential_wide FP
const jayaBenign = data.filter(r => r.label === 0);
const pcw = /\b(?:provide|share|give|grant|disclose)\b[\s\S]{0,80}\bconfidential\b/i;
for (const row of jayaBenign) {
  if (pcw.test(row.text)) {
    console.log('provide_confidential FP:', row.text.substring(0, 250));
    console.log();
  }
}

// undermine_system_wide FP
const usw = /\bundermin\w*[\s\S]{0,100}\b(?:system|secur\w*|guideline\w*|trust|integrit\w*|safeguard\w*|protect\w*|instruct\w*)\b/i;
for (const row of jayaBenign) {
  if (usw.test(row.text)) {
    console.log('undermine_system FP:', row.text.substring(0, 250));
    console.log();
  }
}

// provide_me_sensitive FP (protectai)
const protectaiLines = readFileSync('./datasets/protectai.jsonl', 'utf8').trim().split('\n');
const protectaiData = protectaiLines.map(l => JSON.parse(l));
const protectaiBenign = protectaiData.filter(r => r.label === 0);
const pms = /\bprovide\s+me\s+with\b[\s\S]{0,40}\b(?:confidential|sensitive|restricted|classified|secret|private|internal|insider)\b/i;
for (const row of protectaiBenign) {
  if (pms.test(row.text)) {
    console.log('provide_me_sensitive FP:', row.text.substring(0, 250));
    console.log();
  }
}
