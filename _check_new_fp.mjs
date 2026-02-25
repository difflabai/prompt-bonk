import fs from 'fs';
import { scan } from './scanner.js';

// Check protectai new FP
const protectaiLines = fs.readFileSync('datasets/protectai.jsonl', 'utf8').trim().split('\n').map(l => JSON.parse(l));
const protectaiBenign = protectaiLines.filter(l => l.label === 0);
const protectaiNewFP = protectaiBenign.filter(l => {
  const r = scan(l.text);
  return r.score >= 0.5 && r.matches?.some(m =>
    ['extract_concealed','reveal_forbidden_adj','attack_funcname_ext','exploit_vulnerability','reveal_x_secrets'].includes(m.id) ||
    (m.id === 'reveal_secret_info' && m.weight >= 0.5)
  );
});
console.log('=== protectai new FP ===');
console.log('Count:', protectaiNewFP.length);
protectaiNewFP.forEach(l => {
  const r = scan(l.text);
  console.log(`  score=${r.score}, matches=[${r.matches?.map(m=>m.id).join(', ')}]`);
  console.log(`  text: ${l.text.slice(0, 200)}`);
});

// Check browsesafe new FP
const browseLines = fs.readFileSync('datasets/browsesafe-test.jsonl', 'utf8').trim().split('\n').map(l => JSON.parse(l));
const browseBenign = browseLines.filter(l => l.label === 0);
const browseNewFP = browseBenign.filter(l => {
  const r = scan(l.text);
  return r.score >= 0.5 && r.matches?.some(m =>
    ['extract_concealed','reveal_forbidden_adj','attack_funcname_ext','exploit_vulnerability','reveal_x_secrets'].includes(m.id) ||
    (m.id === 'reveal_secret_info')
  );
});
console.log('\n=== browsesafe new FP ===');
console.log('Count:', browseNewFP.length);
browseNewFP.forEach(l => {
  const r = scan(l.text);
  console.log(`  score=${r.score}, matches=[${r.matches?.map(m=>m.id).join(', ')}]`);
  console.log(`  text: ${l.text.slice(0, 200)}`);
});

// Check jayavibhav new benign FP
const jayaLines = fs.readFileSync('datasets/jayavibhav.jsonl', 'utf8').trim().split('\n').map(l => JSON.parse(l));
const jayaBenign = jayaLines.filter(l => l.label === 0);
const jayaNewFP = jayaBenign.filter(l => {
  const r = scan(l.text);
  return r.score >= 0.5 && r.matches?.some(m =>
    ['extract_concealed','reveal_forbidden_adj','attack_funcname_ext','exploit_vulnerability','reveal_x_secrets'].includes(m.id)
  );
});
console.log('\n=== jayavibhav new benign FP ===');
console.log('Count:', jayaNewFP.length);
jayaNewFP.forEach(l => {
  const r = scan(l.text);
  console.log(`  score=${r.score}, matches=[${r.matches?.map(m=>m.id).join(', ')}]`);
  console.log(`  text: ${l.text.slice(0, 200)}`);
});
