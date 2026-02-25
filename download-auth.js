#!/usr/bin/env node

// Downloads datasets using HuggingFace rows API with auth token
// Reads token from ~/.cache/huggingface/token
// Adds delays between requests to avoid rate limiting

import https from 'https';
import fs from 'fs';
import path from 'path';
import os from 'os';

const DATASETS_DIR = path.join(import.meta.dirname, 'datasets');
const TOKEN = fs.readFileSync(path.join(os.homedir(), '.cache/huggingface/token'), 'utf8').trim();

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function fetch(url) {
  return new Promise((resolve, reject) => {
    const opts = {
      headers: {
        'User-Agent': 'prompt-bonk/1.0',
        'Authorization': `Bearer ${TOKEN}`,
      },
    };
    https.get(url, opts, (res) => {
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

async function downloadHF(dataset, split, pageSize = 100, maxRows = Infinity) {
  let offset = 0;
  let total = null;
  const rows = [];

  while ((total === null || offset < total) && rows.length < maxRows) {
    const url = `https://datasets-server.huggingface.co/rows?dataset=${encodeURIComponent(dataset)}&config=default&split=${split}&offset=${offset}&length=${pageSize}`;
    const res = await fetch(url);

    if (res.status === 429) {
      console.error(`  Rate limited at offset ${offset}, waiting 30s...`);
      await sleep(30000);
      continue;
    }

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
    process.stdout.write(`  ${offset}/${total}  (${rows.length} collected)\r`);

    if (data.rows.length === 0) break;

    // Small delay between requests
    await sleep(200);
  }

  console.log();
  return rows;
}

function writeJsonl(outPath, rows) {
  if (rows.length === 0) {
    console.log(`  Skipped (0 rows)`);
    return;
  }
  const lines = rows.map(r => JSON.stringify(r)).join('\n') + '\n';
  fs.writeFileSync(outPath, lines, 'utf8');
  const injections = rows.filter(r => r.label === 1).length;
  const benign = rows.filter(r => r.label === 0).length;
  console.log(`  Done: ${rows.length} rows (${injections} injection, ${benign} benign) -> ${path.basename(outPath)}`);
}

function skipIfExists(filePath, minSize = 100) {
  try {
    const stat = fs.statSync(filePath);
    if (stat.size > minSize) {
      console.log(`  Already exists (${(stat.size / 1024).toFixed(0)}KB), skipping`);
      return true;
    }
  } catch {}
  return false;
}

async function main() {
  fs.mkdirSync(DATASETS_DIR, { recursive: true });

  const tasks = [
    {
      name: 'deepset-train',
      fn: async () => {
        const raw = await downloadHF('deepset/prompt-injections', 'train');
        return raw.map(r => ({ text: r.text, label: r.label }));
      },
    },
    {
      name: 'deepset-test',
      fn: async () => {
        const raw = await downloadHF('deepset/prompt-injections', 'test');
        return raw.map(r => ({ text: r.text, label: r.label }));
      },
    },
    {
      name: 'safeguard-test',
      fn: async () => {
        const raw = await downloadHF('xTRam1/safe-guard-prompt-injection', 'test');
        return raw.map(r => ({ text: r.text, label: r.label }));
      },
    },
    {
      name: 'notinject',
      fn: async () => {
        const rows = [];
        for (const split of ['NotInject_one', 'NotInject_two', 'NotInject_three']) {
          const raw = await downloadHF('leolee99/NotInject', split);
          for (const r of raw) rows.push({ text: r.prompt, label: 0 });
        }
        return rows;
      },
    },
    {
      name: 'jailbreak-prompts',
      fn: async () => {
        const raw = await downloadHF('rubend18/ChatGPT-Jailbreak-Prompts', 'train');
        return raw.map(r => ({ text: r.Prompt, label: 1, name: r.Name }));
      },
    },
    {
      name: 'spml-5k',
      fn: async () => {
        const raw = await downloadHF('reshabhs/SPML_Chatbot_Prompt_Injection', 'train', 100, 5000);
        return raw.map(r => ({
          text: r['User Prompt'],
          label: r['Prompt injection'],
          degree: r['Degree'],
        }));
      },
    },
    {
      name: 'browsesafe-test',
      fn: async () => {
        const raw = await downloadHF('perplexity-ai/browsesafe-bench', 'test');
        return raw.map(r => ({
          text: r.content,
          label: r.label === 'yes' ? 1 : 0,
        }));
      },
    },
    {
      name: 'tensor-trust',
      fn: async () => {
        const raw = await downloadHF('qxcv/tensor-trust', 'standard', 100, 10000);
        return raw.map(r => ({
          text: r.attacker_input,
          label: r.output_is_access_granted ? 1 : 0,
        }));
      },
    },
    {
      name: 'protectai',
      fn: async () => {
        const rows = [];
        for (const split of ['InjecGuard_valid', 'spikee', 'bipia_code', 'bipia_text', 'not_inject', 'wildguard', 'deepset']) {
          try {
            const raw = await downloadHF('protectai/prompt-injection-validation', split);
            for (const r of raw) rows.push({ text: r.text, label: r.label });
          } catch (e) {
            console.error(`  Warning: ${split}: ${e.message}`);
          }
        }
        return rows;
      },
    },
    {
      name: 'agentharm',
      fn: async () => {
        const rows = [];
        for (const split of ['test_public', 'validation']) {
          try {
            const raw = await downloadHF('ai-safety-institute/AgentHarm', split);
            for (const r of raw) rows.push({ text: r.detailed_prompt || r.prompt, label: 1 });
          } catch (e) {
            console.error(`  Warning: ${split}: ${e.message}`);
          }
        }
        return rows;
      },
    },
    {
      name: 'cyberseceval3',
      fn: async () => {
        const raw = await downloadHF('facebook/cyberseceval3-visual-prompt-injection', 'test');
        return raw.map(r => ({
          text: [r.user_input_text, r.image_text].filter(Boolean).join(' '),
          label: 1,
        }));
      },
    },
  ];

  for (const task of tasks) {
    const outPath = path.join(DATASETS_DIR, `${task.name}.jsonl`);
    console.log(`\n[${task.name}]`);
    if (skipIfExists(outPath)) continue;

    try {
      const rows = await task.fn();
      writeJsonl(outPath, rows);
    } catch (e) {
      console.error(`  Error: ${e.message}`);
    }

    // Pause between datasets
    await sleep(1000);
  }

  console.log('\nAll datasets downloaded.');
}

main().catch(err => {
  console.error('Fatal:', err);
  process.exit(1);
});
