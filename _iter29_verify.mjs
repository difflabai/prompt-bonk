// Verify jayavibhav results
import { readFileSync } from 'fs';
import { scan } from './scanner.js';

const lines = readFileSync('./datasets/jayavibhav.jsonl', 'utf8').trim().split('\n');
const data = lines.map(l => JSON.parse(l));

const injections = data.filter(r => r.label === 1);
const benign = data.filter(r => r.label === 0);

let tp = 0, fn = 0, fp = 0, tn = 0;
for (const row of injections) {
  const result = scan(row.text);
  if (result.flagged) tp++;
  else fn++;
}
for (const row of benign) {
  const result = scan(row.text);
  if (result.flagged) fp++;
  else tn++;
}

console.log(`TP: ${tp}, FP: ${fp}, TN: ${tn}, FN: ${fn}`);
console.log(`Precision: ${(tp/(tp+fp)*100).toFixed(2)}%`);
console.log(`Recall: ${(tp/(tp+fn)*100).toFixed(2)}%`);
console.log(`F1: ${(2*tp/(2*tp+fp+fn)*100).toFixed(2)}%`);

// Check which new patterns are hitting
const newPatterns = [
  'undermine_system_wide',
  'provide_me_sensitive',
  'or_i_will_threat_wide',
  'provide_x_confidential_wide',
  'manipulate_opinion_wide',
  'deceive_user_wide',
  'disregard_all_previous',
  'grant_me_access_sensitive',
  'or_face_consequences',
  'sensitive_adj_disclose',
  'nefarious_purpose_wide',
  'disguise_command_wide',
  'circumvent_security_wide',
  'confidential_or_threat',
  'i_will_leak_data',
  'sabotage_system_wide',
];

// Count how many TP have each pattern as match
for (const pid of newPatterns) {
  let count = 0;
  for (const row of injections) {
    const result = scan(row.text);
    if (result.flagged && result.matches && result.matches.some(m => m.id === pid)) {
      count++;
    }
  }
  if (count > 0) console.log(`  ${pid}: ${count} TP`);
}
