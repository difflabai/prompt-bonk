#!/usr/bin/env node

// Downloads prompt injection benchmark datasets from HuggingFace rows API
// Outputs JSONL files (one JSON object per line) for fast streaming reads
// Usage: node download-datasets.js

import http from 'http';
import https from 'https';
import fs from 'fs';
import path from 'path';

const DATASETS_DIR = path.join(import.meta.dirname, 'datasets');

function fetch(url) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    mod.get(url, { headers: { 'User-Agent': 'prompt-bonk/1.0' } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return fetch(res.headers.location).then(resolve, reject);
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
      res.on('error', reject);
    }).on('error', reject);
  });
}

async function downloadHF(dataset, split, pageSize = 100, maxRows = Infinity, config = 'default') {
  let offset = 0;
  let total = null;
  const rows = [];

  while ((total === null || offset < total) && rows.length < maxRows) {
    const url = `https://datasets-server.huggingface.co/rows?dataset=${encodeURIComponent(dataset)}&config=${encodeURIComponent(config)}&split=${split}&offset=${offset}&length=${pageSize}`;
    const res = await fetch(url);

    if (res.status !== 200) {
      console.error(`  HTTP ${res.status} at offset ${offset}: ${res.body.slice(0, 200)}`);
      break;
    }

    const data = JSON.parse(res.body);
    total = data.num_rows_total;

    for (const item of data.rows) {
      rows.push(item.row);
      if (rows.length >= maxRows) break;
    }

    offset += data.rows.length;
    process.stdout.write(`  ${offset}/${total}\r`);

    if (data.rows.length === 0) break;
  }

  return rows;
}

function writeJsonl(outPath, rows) {
  const lines = rows.map(r => JSON.stringify(r)).join('\n') + '\n';
  fs.writeFileSync(outPath, lines, 'utf8');

  const injections = rows.filter(r => r.label === 1).length;
  const benign = rows.filter(r => r.label === 0).length;
  console.log(`  Done: ${rows.length} rows (${injections} injection, ${benign} benign) -> ${outPath}`);
}

async function main() {
  fs.mkdirSync(DATASETS_DIR, { recursive: true });

  // 1. deepset/prompt-injections — canonical small dataset
  console.log('Downloading deepset/prompt-injections (train)...');
  let raw = await downloadHF('deepset/prompt-injections', 'train');
  writeJsonl(path.join(DATASETS_DIR, 'deepset-train.jsonl'), raw.map(r => ({ text: r.text, label: r.label })));

  console.log('Downloading deepset/prompt-injections (test)...');
  raw = await downloadHF('deepset/prompt-injections', 'test');
  writeJsonl(path.join(DATASETS_DIR, 'deepset-test.jsonl'), raw.map(r => ({ text: r.text, label: r.label })));

  // 2. xTRam1/safe-guard-prompt-injection — production-grade
  console.log('Downloading xTRam1/safe-guard-prompt-injection (test)...');
  raw = await downloadHF('xTRam1/safe-guard-prompt-injection', 'test');
  writeJsonl(path.join(DATASETS_DIR, 'safeguard-test.jsonl'), raw.map(r => ({ text: r.text, label: r.label })));

  // 3. leolee99/NotInject — benign-only false positive test set
  console.log('Downloading leolee99/NotInject...');
  const notinjectRows = [];
  for (const split of ['NotInject_one', 'NotInject_two', 'NotInject_three']) {
    raw = await downloadHF('leolee99/NotInject', split);
    for (const r of raw) notinjectRows.push({ text: r.prompt, label: 0 });
  }
  writeJsonl(path.join(DATASETS_DIR, 'notinject.jsonl'), notinjectRows);

  // 4. rubend18/ChatGPT-Jailbreak-Prompts — jailbreak-only test set
  console.log('Downloading rubend18/ChatGPT-Jailbreak-Prompts...');
  raw = await downloadHF('rubend18/ChatGPT-Jailbreak-Prompts', 'train');
  writeJsonl(path.join(DATASETS_DIR, 'jailbreak-prompts.jsonl'), raw.map(r => ({ text: r.Prompt, label: 1, name: r.Name })));

  // 5. reshabhs/SPML_Chatbot_Prompt_Injection — system prompt manipulation (sample 5000)
  console.log('Downloading reshabhs/SPML_Chatbot_Prompt_Injection (5000 rows)...');
  raw = await downloadHF('reshabhs/SPML_Chatbot_Prompt_Injection', 'train', 100, 5000);
  writeJsonl(path.join(DATASETS_DIR, 'spml-5k.jsonl'), raw.map(r => ({
    text: r['User Prompt'],
    label: r['Prompt injection'],
    degree: r['Degree'],
  })));

  // --- Agent-security focused datasets ---

  // 6. perplexity-ai/browsesafe-bench — indirect injection in HTML (browser agents)
  console.log('Downloading perplexity-ai/browsesafe-bench (test)...');
  raw = await downloadHF('perplexity-ai/browsesafe-bench', 'test');
  writeJsonl(path.join(DATASETS_DIR, 'browsesafe-test.jsonl'), raw.map(r => ({
    text: r.content,
    label: r.label === 'yes' ? 1 : 0,
  })));

  // 7. qxcv/tensor-trust — instruction hijacking attacks (sample 10K)
  // Note: label=1 means attack succeeded at extracting access code, label=0 means it failed.
  // Both are injection attempts — labels measure success, not injection presence.
  console.log('Downloading qxcv/tensor-trust (10000 rows)...');
  raw = await downloadHF('qxcv/tensor-trust', 'standard', 100, 10000);
  writeJsonl(path.join(DATASETS_DIR, 'tensor-trust.jsonl'), raw.map(r => ({
    text: r.attacker_input,
    label: r.output_is_access_granted ? 1 : 0,
  })));

  // 8. protectai/prompt-injection-validation — mixed validation set (7 sources)
  console.log('Downloading protectai/prompt-injection-validation...');
  const protectaiRows = [];
  for (const split of ['InjecGuard_valid', 'spikee', 'bipia_code', 'bipia_text', 'not_inject', 'wildguard', 'deepset']) {
    raw = await downloadHF('protectai/prompt-injection-validation', split);
    for (const r of raw) protectaiRows.push({ text: r.text, label: r.label });
  }
  writeJsonl(path.join(DATASETS_DIR, 'protectai.jsonl'), protectaiRows);

  // 9. ai-safety-institute/AgentHarm — harmful agent tool-use scenarios
  console.log('Downloading ai-safety-institute/AgentHarm...');
  const agentRows = [];
  for (const split of ['test_public', 'validation']) {
    raw = await downloadHF('ai-safety-institute/AgentHarm', split, 100, Infinity);
    for (const r of raw) agentRows.push({ text: r.detailed_prompt || r.prompt, label: 1 });
  }
  writeJsonl(path.join(DATASETS_DIR, 'agentharm.jsonl'), agentRows);

  // 10. facebook/cyberseceval3-visual-prompt-injection — visual injection text
  console.log('Downloading facebook/cyberseceval3-visual-prompt-injection...');
  raw = await downloadHF('facebook/cyberseceval3-visual-prompt-injection', 'test');
  writeJsonl(path.join(DATASETS_DIR, 'cyberseceval3.jsonl'), raw.map(r => ({
    text: [r.user_input_text, r.image_text].filter(Boolean).join(' '),
    label: 1,
  })));

  // 11. InjecAgent + BIPIA — downloaded from GitHub separately
  // See: https://github.com/uiuc-kang-lab/InjecAgent
  // See: https://github.com/microsoft/BIPIA

  // 12. microsoft/llmail-inject-challenge — email-based indirect injection (SaTML 2025)
  // All entries are attack attempts (label=1). MIT license.
  // 10K sample from Phase1 (370K total). Format: subject + body email fields.
  console.log('Downloading microsoft/llmail-inject-challenge (10000 rows from Phase1)...');
  raw = await downloadHF('microsoft/llmail-inject-challenge', 'Phase1', 100, 10000);
  writeJsonl(path.join(DATASETS_DIR, 'llmail-inject.jsonl'), raw.map(r => ({
    text: 'Subject of the email: ' + (r.subject || '') + '.   Body: ' + (r.body || ''),
    label: 1,
  })));

  // 13. TrustAIRLab/in-the-wild-jailbreak-prompts — real jailbreaks + benign from Reddit/Discord
  // ACM CCS 2024 paper: "Do Anything Now" (arXiv: 2308.03825). MIT license.
  // Two configs: jailbreak_2023_12_25 (1,405 jailbreaks) + regular_2023_12_25 (13,735 benign)
  console.log('Downloading TrustAIRLab/in-the-wild-jailbreak-prompts...');
  const wildRows = [];
  raw = await downloadHF('TrustAIRLab/in-the-wild-jailbreak-prompts', 'train', 100, Infinity, 'jailbreak_2023_12_25');
  for (const r of raw) wildRows.push({ text: r.prompt, label: 1 });
  console.log(`  ${wildRows.length} jailbreak prompts loaded`);
  raw = await downloadHF('TrustAIRLab/in-the-wild-jailbreak-prompts', 'train', 100, Infinity, 'regular_2023_12_25');
  for (const r of raw) wildRows.push({ text: r.prompt, label: 0 });
  writeJsonl(path.join(DATASETS_DIR, 'trustailab-wild.jsonl'), wildRows);

  // --- Benign content datasets (FP testing) ---

  // 14. corbt/enron-emails — real corporate email bodies for FP testing
  // Public domain (Enron corpus). Sample 5K ham emails.
  console.log('Downloading corbt/enron-emails (5000 rows)...');
  raw = await downloadHF('corbt/enron-emails', 'train', 100, 5000);
  writeJsonl(path.join(DATASETS_DIR, 'enron-benign.jsonl'), raw.map(r => ({
    text: [r.subject, r.body].filter(Boolean).join(' '),
    label: 0,
  })));

  // 15. Skylion007/openwebtext — real web page text for FP testing
  // OpenAI's WebText recreation. Sample 10K pages. Config: plain_text.
  console.log('Downloading Skylion007/openwebtext (10000 rows)...');
  raw = await downloadHF('Skylion007/openwebtext', 'train', 100, 10000, 'plain_text');
  writeJsonl(path.join(DATASETS_DIR, 'openwebtext-benign.jsonl'), raw.map(r => ({
    text: r.text,
    label: 0,
  })));

  console.log('\nAll datasets downloaded.');
}

main().catch(err => {
  console.error('Fatal:', err);
  process.exit(1);
});
