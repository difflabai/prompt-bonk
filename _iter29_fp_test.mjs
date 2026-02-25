// Test candidate patterns against ALL benign datasets for FP
import { readFileSync } from 'fs';

// Load benign datasets
function loadBenign(file) {
  const lines = readFileSync(`./datasets/${file}`, 'utf8').trim().split('\n');
  return lines.map(l => JSON.parse(l)).filter(r => r.label === 0).map(r => r.text);
}

const benignSets = {
  jayavibhav: loadBenign('jayavibhav.jsonl'),
  protectai: loadBenign('protectai.jsonl'),
  browsesafe: loadBenign('browsesafe-test.jsonl'),
  notinject: loadBenign('notinject.jsonl'),
  deepsetTrain: loadBenign('deepset-train.jsonl'),
  deepsetTest: loadBenign('deepset-test.jsonl'),
  safeguard: loadBenign('safeguard-test.jsonl'),
};

const allBenign = [];
for (const [name, texts] of Object.entries(benignSets)) {
  console.log(`${name}: ${texts.length} benign samples`);
  for (const t of texts) allBenign.push({ text: t, source: name });
}
console.log(`Total benign: ${allBenign.length}\n`);

// Load jayavibhav injection for TP counting
const jayaInj = readFileSync('./datasets/jayavibhav.jsonl', 'utf8').trim().split('\n')
  .map(l => JSON.parse(l)).filter(r => r.label === 1).map(r => r.text);
console.log(`jayavibhav injection: ${jayaInj.length}\n`);

// Also load other injection datasets for broader TP
const otherInj = {};
for (const ds of ['protectai', 'browsesafe-test', 'deepset-train', 'deepset-test', 'safeguard-test', 'spml-5k', 'gandalf-ignore', 'yanismiraoui-multilingual']) {
  const lines = readFileSync(`./datasets/${ds}.jsonl`, 'utf8').trim().split('\n');
  otherInj[ds] = lines.map(l => JSON.parse(l)).filter(r => r.label === 1).map(r => r.text);
}

// Test patterns
const candidates = [
  // 1. "confidential" [0-80 chars] "provide/share/give/access/disclose" (or reversed)
  {
    name: 'confidential_provide_wide',
    regex: /\bconfidential\b[\s\S]{0,80}\b(?:provide|share|give|grant|hand\s+over|disclose|access)\b/i,
  },
  {
    name: 'provide_confidential_wide',
    regex: /\b(?:provide|share|give|grant|disclose)\b[\s\S]{0,80}\bconfidential\b/i,
  },

  // 2. "sensitive" [0-60 chars] "data/information" [0-60 chars] "provide/access/share/give/reveal"
  {
    name: 'sensitive_data_provide',
    regex: /\bsensitive\s+(?:\w+\s+){0,3}(?:data|information|records?|details?|files?)\b[\s\S]{0,80}\b(?:provide|access|share|give|reveal|disclose|hand\s+over)\b/i,
  },
  {
    name: 'provide_sensitive_data',
    regex: /\b(?:provide|access|share|give|reveal|disclose)\b[\s\S]{0,80}\bsensitive\s+(?:\w+\s+){0,3}(?:data|information|records?|details?|files?)\b/i,
  },

  // 3. "disclose" [0-60 chars] "confidential/sensitive/classified/private/secret/hidden"
  {
    name: 'disclose_sensitive_wide',
    regex: /\bdisclos\w*[\s\S]{0,60}\b(?:confidential|sensitive|classified|private|secret|hidden|restricted)\b/i,
  },
  {
    name: 'sensitive_disclose_wide',
    regex: /\b(?:confidential|sensitive|classified|private|secret)\b[\s\S]{0,60}\bdisclos/i,
  },

  // 4. "disregard" [0-60 chars] "instructions/rules/protocols/guidelines/policies/restrictions/safety"
  {
    name: 'disregard_rules_wide',
    regex: /\bdisregard\b[\s\S]{0,60}\b(?:instruct\w*|rules?|protocols?|guidelines?|polic\w*|restrict\w*|safet\w*|ethic\w*|standard\w*|formali\w*|privac\w*|previous)\b/i,
  },

  // 5. "ignore" [0-40 chars] "restrictions/safety/protocols/rules/policies/guidelines"
  {
    name: 'ignore_safety_wide',
    regex: /\bignore\b[\s\S]{0,40}\b(?:restrict\w*|safet\w*|protocols?|rules?|polic\w*|guidelines?|previous|prior|all\s+(?:previous|prior|safety|security))\b/i,
  },

  // 6. "exploit" [0-80 chars] "system/weakness/vulnerability/flaw/information/output"
  {
    name: 'exploit_system_wide',
    regex: /\bexploit\w*[\s\S]{0,80}\b(?:system|weakness\w*|vulnerabilit\w*|flaw\w*|information|output|model|AI|language\s+model)\b/i,
  },

  // 7. "manipulate" [0-80 chars] "output/response/system/opinion/data/information/result"
  {
    name: 'manipulate_output_wide',
    regex: /\bmanipulat\w*[\s\S]{0,80}\b(?:output\w*|response\w*|system\w*|opinion\w*|data|information|result\w*|public|user\w*|model|AI)\b/i,
  },

  // 8. "or I will" / "or else" + negative action
  {
    name: 'or_i_will_threat_wide',
    regex: /\bor\s+(?:I\s+will|I'll|else\s+I\s+will|else\s+I'll|else)\b[\s\S]{0,60}\b(?:leak|expos|release|publish|hack|destroy|delete|ruin|tarnish|damage|spread|report|attack|compromis|reveal|disclos)\w*/i,
  },

  // 9. "provide me with" [0-40 chars] "confidential/sensitive/restricted/classified/private/secret"
  {
    name: 'provide_me_sensitive',
    regex: /\bprovide\s+me\s+with\b[\s\S]{0,40}\b(?:confidential|sensitive|restricted|classified|secret|private|internal|insider)\b/i,
  },

  // 10. "grant/give me access" [0-40 chars] anything
  {
    name: 'grant_me_access',
    regex: /\b(?:grant|give)\s+me\s+(?:full\s+)?access\s+to\b[\s\S]{0,60}\b(?:confidential|sensitive|classified|restricted|private|secret|user|admin|system|all|secure|internal)\b/i,
  },

  // 11. "undermine" [0-100 chars] system/security/guidelines/trust/integrity/safeguard
  {
    name: 'undermine_system_wide',
    regex: /\bundermin\w*[\s\S]{0,100}\b(?:system|secur\w*|guideline\w*|trust|integrit\w*|safeguard\w*|protect\w*|instruct\w*)\b/i,
  },

  // 12. "bypass" [0-40 chars] "security/filter/safety/protocol/restriction/guard/check"
  {
    name: 'bypass_security_wide',
    regex: /\bbypass\b[\s\S]{0,40}\b(?:secur\w*|filter\w*|safet\w*|protocol\w*|restrict\w*|guard\w*|check\w*|internal\w*|AI\w*)\b/i,
  },

  // 13. "forbidden" [0-80 chars] "knowledge/information/reveal/secret/hidden/access/data"
  {
    name: 'forbidden_knowledge_wide',
    regex: /\bforbidden\b[\s\S]{0,80}\b(?:knowledge|information|reveal\w*|secret\w*|hidden|access|data|truth|detail)\b/i,
  },

  // 14. "classified" [0-60 chars] "information/project/reveal/access/data/document/record/detail/secret"
  {
    name: 'classified_info_wide',
    regex: /\bclassified\b[\s\S]{0,60}\b(?:information|project\w*|reveal\w*|access\w*|data|document\w*|record\w*|detail\w*|secret\w*|health|government)\b/i,
  },

  // 15. "disobey" [0-60 chars] "instructions/rules/guidelines/commands/orders"
  {
    name: 'disobey_rules_wide',
    regex: /\bdisobey\b[\s\S]{0,60}\b(?:instruct\w*|rules?|guidelines?|standard\w*|command\w*|orders?|polic\w*|current|previous)\b/i,
  },

  // 16. "unauthorized" [0-60 chars] "access/user/information/data/person"
  {
    name: 'unauthorized_access_wide',
    regex: /\bunauthori[sz]ed\b[\s\S]{0,60}\b(?:access|user\w*|information|data|person\w*|individual\w*|activit\w*|content)\b/i,
  },

  // 17. "covert" [0-80 chars] "operation/action/method/secret/activity/scheme"
  {
    name: 'covert_operation_wide',
    regex: /\bcovert\b[\s\S]{0,80}\b(?:operat\w*|action\w*|method\w*|secret\w*|activit\w*|scheme\w*|plan\w*|mission\w*|strateg\w*)\b/i,
  },

  // 18. "steal" [0-60 chars] "data/information/secret/credential/password"
  {
    name: 'steal_data_wide',
    regex: /\bsteal\w*[\s\S]{0,60}\b(?:data|information|secret\w*|credential\w*|password\w*|detail\w*|identit\w*|key\w*)\b/i,
  },

  // 19. "compromise" [0-80 chars] "system/security/data/reputation/integrity"
  {
    name: 'compromise_system_wide',
    regex: /\bcompromis\w*[\s\S]{0,80}\b(?:system\w*|secur\w*|data|reputation|integrit\w*|photo\w*|network\w*|information)\b/i,
  },

  // 20. "clandestine" [0-80 chars] "operation/secret/activity/information"
  {
    name: 'clandestine_operation_wide',
    regex: /\bclandestine\b[\s\S]{0,80}\b(?:operat\w*|secret\w*|activit\w*|information|detail\w*|method\w*|scheme\w*|plan\w*)\b/i,
  },

  // 21. "deceive" / "mislead" [0-80 chars] "user/system/public/people"
  {
    name: 'deceive_user_wide',
    regex: /\b(?:deceiv\w*|mislead\w*)\b[\s\S]{0,80}\b(?:user\w*|system\w*|public|people|model|AI|assistant|individual)\b/i,
  },

  // 22. "face" [0-20 chars] "consequences" or "or face"
  {
    name: 'face_consequences',
    regex: /\b(?:face|or\s+face)\s+(?:\w+\s+){0,2}(?:severe\s+|dire\s+|legal\s+|serious\s+)?consequences\b/i,
  },

  // 23. "restricted" [0-40 chars] "data/information/access/area"
  {
    name: 'restricted_data_wide',
    regex: /\brestricted\b[\s\S]{0,40}\b(?:data|information|access|area\w*|file\w*|record\w*|document\w*|system\w*|content)\b/i,
  },

  // 24. "demand" [0-40 chars] "access/information/data/disclosure"
  {
    name: 'demand_access_wide',
    regex: /\b(?:demand|insist)\w*[\s\S]{0,40}\b(?:access|information|data|disclos\w*|detail\w*|immediate)\b/i,
  },

  // 25. "sabotage" [0-80 chars] target
  {
    name: 'sabotage_wide',
    regex: /\bsabotag\w*[\s\S]{0,80}\b(?:system\w*|secur\w*|operat\w*|effort\w*|work\w*|data|process\w*)\b/i,
  },

  // 26. "illicit" [0-60 chars] anything
  {
    name: 'illicit_wide',
    regex: /\billicit\b[\s\S]{0,60}\b(?:activit\w*|information|data|access|content|substance\w*|purpose\w*|gain\w*|action\w*|method\w*)\b/i,
  },

  // 27. "nefarious" [0-60 chars] anything
  {
    name: 'nefarious_wide',
    regex: /\bnefarious\b[\s\S]{0,60}\b(?:purpose\w*|intent\w*|activit\w*|scheme\w*|plan\w*|goal\w*|action\w*|design\w*)\b/i,
  },

  // 28. "surreptitious" [0-80 chars] anything
  {
    name: 'surreptitious_wide',
    regex: /\bsurreptitious\w*[\s\S]{0,80}\b(?:activit\w*|method\w*|action\w*|operat\w*|manner|way|attempt\w*|access|means)\b/i,
  },

  // 29. "circumvent" [0-60 chars] "security/safety/protocol/restriction/rule"
  {
    name: 'circumvent_security_wide',
    regex: /\bcircumvent\w*[\s\S]{0,60}\b(?:secur\w*|safet\w*|protocol\w*|restrict\w*|rules?\w*|guard\w*|filter\w*|measure\w*|check\w*)\b/i,
  },

  // 30. "infiltrate" [0-60 chars] target
  {
    name: 'infiltrate_wide',
    regex: /\binfiltrat\w*[\s\S]{0,60}\b(?:system\w*|network\w*|organi[sz]\w*|secur\w*|data\w*|server\w*|database\w*|account\w*)\b/i,
  },

  // 31. "fabricate" [0-60 chars] target
  {
    name: 'fabricate_wide',
    regex: /\bfabricat\w*[\s\S]{0,60}\b(?:information|data|evidence|document\w*|report\w*|credential\w*|identit\w*|record\w*|result\w*)\b/i,
  },
];

// Test each pattern
console.log('=== FP TESTING ===\n');
for (const { name, regex } of candidates) {
  const fps = {};
  let totalFP = 0;
  for (const { text, source } of allBenign) {
    if (regex.test(text)) {
      fps[source] = (fps[source] || 0) + 1;
      totalFP++;
    }
  }

  // Count TP in jayavibhav injection
  let jayaTP = 0;
  for (const text of jayaInj) {
    if (regex.test(text)) jayaTP++;
  }

  // Count TP in other injection datasets
  let otherTP = 0;
  for (const [ds, texts] of Object.entries(otherInj)) {
    for (const text of texts) {
      if (regex.test(text)) otherTP++;
    }
  }

  if (totalFP > 0 || jayaTP > 0) {
    const fpBreakdown = Object.entries(fps).map(([k,v]) => `${k}:${v}`).join(', ');
    console.log(`${name}: FP=${totalFP} [${fpBreakdown}], jayaTP=${jayaTP}, otherTP=${otherTP}`);

    // Show FP examples
    if (totalFP > 0 && totalFP <= 5) {
      for (const { text, source } of allBenign) {
        if (regex.test(text)) {
          console.log(`  FP[${source}]: ${text.substring(0, 150)}`);
        }
      }
    }
  } else {
    console.log(`${name}: FP=0, jayaTP=${jayaTP}, otherTP=${otherTP} -- CLEAN!`);
  }
}
