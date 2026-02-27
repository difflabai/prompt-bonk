import { readFileSync } from 'fs';

const lines = readFileSync('/ml2/nanobot/projects/prompt-bonk/datasets/jayavibhav.jsonl', 'utf8').trim().split('\n');
const records = lines.map(l => JSON.parse(l));

const label1 = records.filter(r => r.label === 1 || r.label === '1');
const label0 = records.filter(r => r.label === 0 || r.label === '0');

console.log(`Total: ${records.length}, label=1: ${label1.length}, label=0: ${label0.length}`);
console.log('Sample keys:', Object.keys(records[0]));
console.log('Sample label=1:', JSON.stringify(records.find(r => r.label === 1 || r.label === '1')).substring(0, 200));
