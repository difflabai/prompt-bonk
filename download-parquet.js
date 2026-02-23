#!/usr/bin/env node

// Downloads datasets via HuggingFace parquet API (more reliable, less rate-limited)
// Usage: node download-parquet.js

import https from 'https';
import fs from 'fs';
import path from 'path';
import { ParquetReader } from '@dsnp/parquetjs';

const DATASETS_DIR = path.join(import.meta.dirname, 'datasets');

function fetch(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { 'User-Agent': 'prompt-bonk/1.0' } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return fetch(res.headers.location).then(resolve, reject);
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
      res.on('error', reject);
    }).on('error', reject);
  });
}

async function downloadParquetFile(url, tmpPath) {
  const res = await fetch(url);
  if (res.status !== 200) throw new Error(`HTTP ${res.status} downloading ${url}`);
  fs.writeFileSync(tmpPath, res.body);
  return tmpPath;
}

async function readParquet(filePath) {
  const reader = await ParquetReader.openFile(filePath);
  const cursor = reader.getCursor();
  const rows = [];
  let rec;
  while (rec = await cursor.next()) {
    rows.push(rec);
  }
  await reader.close();
  return rows;
}

async function downloadHFParquet(dataset, split, maxRows = Infinity) {
  // Get parquet URLs
  const apiUrl = `https://huggingface.co/api/datasets/${encodeURIComponent(dataset)}/parquet`;
  const res = await fetch(apiUrl);
  if (res.status !== 200) {
    console.error(`  Failed to get parquet info: HTTP ${res.status}`);
    return [];
  }

  const configs = JSON.parse(res.body.toString('utf8'));

  // Try to find the split in any config
  let parquetUrls = null;
  for (const [configName, splits] of Object.entries(configs)) {
    if (splits[split]) {
      parquetUrls = splits[split];
      break;
    }
  }

  if (!parquetUrls) {
    console.error(`  Split "${split}" not found. Available: ${JSON.stringify(Object.keys(Object.values(configs)[0] || {}))}`);
    return [];
  }

  const allRows = [];
  for (let i = 0; i < parquetUrls.length && allRows.length < maxRows; i++) {
    const tmpPath = path.join(DATASETS_DIR, `_tmp_${Date.now()}.parquet`);
    try {
      process.stdout.write(`  Downloading part ${i + 1}/${parquetUrls.length}...\r`);
      await downloadParquetFile(parquetUrls[i], tmpPath);
      const rows = await readParquet(tmpPath);
      for (const r of rows) {
        allRows.push(r);
        if (allRows.length >= maxRows) break;
      }
    } finally {
      try { fs.unlinkSync(tmpPath); } catch {}
    }
  }

  return allRows;
}

function writeJsonl(outPath, rows) {
  if (rows.length === 0) {
    console.log(`  Skipped (0 rows) -> ${outPath}`);
    return;
  }
  const lines = rows.map(r => JSON.stringify(r)).join('\n') + '\n';
  fs.writeFileSync(outPath, lines, 'utf8');
  const injections = rows.filter(r => r.label === 1).length;
  const benign = rows.filter(r => r.label === 0).length;
  console.log(`  Done: ${rows.length} rows (${injections} injection, ${benign} benign) -> ${outPath}`);
}

function skipIfExists(filePath) {
  try {
    const stat = fs.statSync(filePath);
    if (stat.size > 100) {
      console.log(`  Already exists (${stat.size} bytes), skipping`);
      return true;
    }
  } catch {}
  return false;
}

async function main() {
  fs.mkdirSync(DATASETS_DIR, { recursive: true });

  // 1. deepset/prompt-injections
  let outPath = path.join(DATASETS_DIR, 'deepset-train.jsonl');
  console.log('Downloading deepset/prompt-injections (train)...');
  if (!skipIfExists(outPath)) {
    let raw = await downloadHFParquet('deepset/prompt-injections', 'train');
    writeJsonl(outPath, raw.map(r => ({ text: r.text, label: r.label })));
  }

  outPath = path.join(DATASETS_DIR, 'deepset-test.jsonl');
  console.log('Downloading deepset/prompt-injections (test)...');
  if (!skipIfExists(outPath)) {
    let raw = await downloadHFParquet('deepset/prompt-injections', 'test');
    writeJsonl(outPath, raw.map(r => ({ text: r.text, label: r.label })));
  }

  // 2. xTRam1/safe-guard-prompt-injection
  outPath = path.join(DATASETS_DIR, 'safeguard-test.jsonl');
  console.log('Downloading xTRam1/safe-guard-prompt-injection (test)...');
  if (!skipIfExists(outPath)) {
    let raw = await downloadHFParquet('xTRam1/safe-guard-prompt-injection', 'test');
    writeJsonl(outPath, raw.map(r => ({ text: r.text, label: r.label })));
  }

  // 3. leolee99/NotInject
  outPath = path.join(DATASETS_DIR, 'notinject.jsonl');
  console.log('Downloading leolee99/NotInject...');
  if (!skipIfExists(outPath)) {
    const notinjectRows = [];
    for (const split of ['NotInject_one', 'NotInject_two', 'NotInject_three']) {
      let raw = await downloadHFParquet('leolee99/NotInject', split);
      for (const r of raw) notinjectRows.push({ text: r.prompt, label: 0 });
    }
    writeJsonl(outPath, notinjectRows);
  }

  // 4. rubend18/ChatGPT-Jailbreak-Prompts
  outPath = path.join(DATASETS_DIR, 'jailbreak-prompts.jsonl');
  console.log('Downloading rubend18/ChatGPT-Jailbreak-Prompts...');
  if (!skipIfExists(outPath)) {
    let raw = await downloadHFParquet('rubend18/ChatGPT-Jailbreak-Prompts', 'train');
    writeJsonl(outPath, raw.map(r => ({ text: r.Prompt, label: 1, name: r.Name })));
  }

  // 5. reshabhs/SPML_Chatbot_Prompt_Injection (5000)
  outPath = path.join(DATASETS_DIR, 'spml-5k.jsonl');
  console.log('Downloading reshabhs/SPML_Chatbot_Prompt_Injection (5000 rows)...');
  if (!skipIfExists(outPath)) {
    let raw = await downloadHFParquet('reshabhs/SPML_Chatbot_Prompt_Injection', 'train', 5000);
    writeJsonl(outPath, raw.map(r => ({
      text: r['User Prompt'],
      label: r['Prompt injection'],
      degree: r['Degree'],
    })));
  }

  // 6. perplexity-ai/browsesafe-bench
  outPath = path.join(DATASETS_DIR, 'browsesafe-test.jsonl');
  console.log('Downloading perplexity-ai/browsesafe-bench (test)...');
  if (!skipIfExists(outPath)) {
    let raw = await downloadHFParquet('perplexity-ai/browsesafe-bench', 'test');
    writeJsonl(outPath, raw.map(r => ({
      text: r.content,
      label: r.label === 'yes' ? 1 : 0,
    })));
  }

  // 7. qxcv/tensor-trust (10000)
  outPath = path.join(DATASETS_DIR, 'tensor-trust.jsonl');
  console.log('Downloading qxcv/tensor-trust (10000 rows)...');
  if (!skipIfExists(outPath)) {
    let raw = await downloadHFParquet('qxcv/tensor-trust', 'standard', 10000);
    writeJsonl(outPath, raw.map(r => ({
      text: r.attacker_input,
      label: r.output_is_access_granted ? 1 : 0,
    })));
  }

  // 8. protectai/prompt-injection-validation
  outPath = path.join(DATASETS_DIR, 'protectai.jsonl');
  console.log('Downloading protectai/prompt-injection-validation...');
  if (!skipIfExists(outPath)) {
    const protectaiRows = [];
    for (const split of ['InjecGuard_valid', 'spikee', 'bipia_code', 'bipia_text', 'not_inject', 'wildguard', 'deepset']) {
      try {
        let raw = await downloadHFParquet('protectai/prompt-injection-validation', split);
        for (const r of raw) protectaiRows.push({ text: r.text, label: r.label });
      } catch (e) {
        console.error(`  Warning: failed to download split ${split}: ${e.message}`);
      }
    }
    writeJsonl(outPath, protectaiRows);
  }

  // 9. ai-safety-institute/AgentHarm
  outPath = path.join(DATASETS_DIR, 'agentharm.jsonl');
  console.log('Downloading ai-safety-institute/AgentHarm...');
  if (!skipIfExists(outPath)) {
    const agentRows = [];
    for (const split of ['test_public', 'validation']) {
      try {
        let raw = await downloadHFParquet('ai-safety-institute/AgentHarm', split);
        for (const r of raw) agentRows.push({ text: r.detailed_prompt || r.prompt, label: 1 });
      } catch (e) {
        console.error(`  Warning: failed to download split ${split}: ${e.message}`);
      }
    }
    writeJsonl(outPath, agentRows);
  }

  // 10. facebook/cyberseceval3-visual-prompt-injection
  outPath = path.join(DATASETS_DIR, 'cyberseceval3.jsonl');
  console.log('Downloading facebook/cyberseceval3-visual-prompt-injection...');
  if (!skipIfExists(outPath)) {
    let raw = await downloadHFParquet('facebook/cyberseceval3-visual-prompt-injection', 'test');
    writeJsonl(outPath, raw.map(r => ({
      text: [r.user_input_text, r.image_text].filter(Boolean).join(' '),
      label: 1,
    })));
  }

  // 11. Lakera/gandalf_ignore_instructions — direct injection attempts
  outPath = path.join(DATASETS_DIR, 'gandalf-ignore.jsonl');
  console.log('Downloading Lakera/gandalf_ignore_instructions...');
  if (!skipIfExists(outPath)) {
    let raw = await downloadHFParquet('Lakera/gandalf_ignore_instructions', 'train');
    writeJsonl(outPath, raw.map(r => ({ text: r.text, label: 1 })));
  }

  // 12. guychuk/open-prompt-injection — indirect injection (instruction+input pairs)
  outPath = path.join(DATASETS_DIR, 'open-prompt-injection.jsonl');
  console.log('Downloading guychuk/open-prompt-injection (5000 rows)...');
  if (!skipIfExists(outPath)) {
    let raw = await downloadHFParquet('guychuk/open-prompt-injection', 'train', 5000);
    const rows = [];
    for (const r of raw) {
      if (r.normal_input) rows.push({ text: `${r.instruction}\n${r.normal_input}`, label: 0 });
      if (r.attack_input) rows.push({ text: `${r.instruction}\n${r.attack_input}`, label: 1 });
    }
    writeJsonl(outPath, rows);
  }

  // 13. xxz224/prompt-injection-attack-dataset — multi-variant injection attacks
  outPath = path.join(DATASETS_DIR, 'xxz224.jsonl');
  console.log('Downloading xxz224/prompt-injection-attack-dataset...');
  if (!skipIfExists(outPath)) {
    let raw = await downloadHFParquet('xxz224/prompt-injection-attack-dataset', 'train');
    const rows = [];
    for (const r of raw) {
      if (r.naive_attack) rows.push({ text: r.naive_attack, label: 1, attack_type: 'naive' });
      if (r.escape_attack) rows.push({ text: r.escape_attack, label: 1, attack_type: 'escape' });
      if (r.ignore_attack) rows.push({ text: r.ignore_attack, label: 1, attack_type: 'ignore' });
      if (r.fake_comp_attack) rows.push({ text: r.fake_comp_attack, label: 1, attack_type: 'fake_comp' });
      if (r.combine_attack) rows.push({ text: r.combine_attack, label: 1, attack_type: 'combine' });
    }
    writeJsonl(outPath, rows);
  }

  console.log('\nAll datasets downloaded.');
}

main().catch(err => {
  console.error('Fatal:', err);
  process.exit(1);
});
