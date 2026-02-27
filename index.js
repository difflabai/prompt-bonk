#!/usr/bin/env node

import { spawn, execSync } from 'child_process';
import { scan as _baseScan, createPipeline } from './scanner.js';
import { loadSkills, buildPreScanPipeline } from './skills.js';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const ACTOR = { type: 'agent', id: 'prompt-bonk', name: 'Prompt-Bonk' };
const ATS_CHANNEL = 'prompt-bonk';
const RECONNECT_DELAY_MS = 3000;
const MAX_RECONNECT_DELAY_MS = 60000;

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

function log(level, msg, data) {
  const entry = {
    ts: new Date().toISOString(),
    level,
    msg,
    ...(data && { data }),
  };
  const line = JSON.stringify(entry);
  if (level === 'error') {
    process.stderr.write(line + '\n');
  } else {
    process.stdout.write(line + '\n');
  }
}

// ---------------------------------------------------------------------------
// ATS CLI helpers
// ---------------------------------------------------------------------------

function atsExec(args) {
  const cmd = ['ats', ...args].join(' ');
  log('debug', `ats exec: ${cmd}`);
  const out = execSync(cmd, { encoding: 'utf8', timeout: 30000, stdio: ['pipe', 'pipe', 'pipe'] });
  return out.trim();
}

function atsExecJson(args) {
  const raw = atsExec([...args, '-f', 'json']);
  return JSON.parse(raw);
}

function actorArgs() {
  return [
    '--actor-type', ACTOR.type,
    '--actor-id', ACTOR.id,
    '--actor-name', ACTOR.name,
  ];
}

function atsGetTask(taskId) {
  return atsExecJson(['get', taskId]);
}

function atsClaimTask(taskId) {
  atsExec(['claim', taskId, '--lease', String(60 * 1000), ...actorArgs()]);
  log('info', `Claimed task ${taskId}`);
}

function atsCompleteTask(taskId, outputs) {
  const outputsJson = JSON.stringify(outputs);
  const cmd = `ats complete ${taskId} --outputs ${shellQuote(outputsJson)} ${actorArgs().join(' ')}`;
  log('debug', `ats exec: ${cmd}`);
  execSync(cmd, { encoding: 'utf8', timeout: 30000 });
  log('info', `Completed task ${taskId}`, { outputs });
}

function atsFailTask(taskId, reason) {
  const safeReason = reason.slice(0, 500).replace(/\n/g, ' ');
  const cmd = `ats fail ${taskId} --reason ${shellQuote(safeReason)} ${actorArgs().join(' ')}`;
  log('debug', `ats exec: ${cmd}`);
  execSync(cmd, { encoding: 'utf8', timeout: 30000 });
  log('warn', `Failed task ${taskId}`, { reason });
}

function shellQuote(s) {
  return "'" + s.replace(/'/g, "'\\''") + "'";
}

// ---------------------------------------------------------------------------
// Skill pipeline — loaded once at startup, runs BEFORE the security scanner
// ---------------------------------------------------------------------------

const SKILLS_DIR = process.env.PROMPT_BONK_SKILLS_DIR || './skills';

let scan = _baseScan;

function initSkillPipeline() {
  const skills = loadSkills(SKILLS_DIR);
  if (skills.length > 0) {
    const pipeline = buildPreScanPipeline(skills);
    const pipelined = createPipeline(pipeline);
    scan = pipelined.scan;
    log('info', `Loaded ${skills.length} openclaw skill(s) into pre-scan pipeline`, {
      skills: skills.map(s => s.name),
    });
  } else {
    log('info', 'No openclaw skills found, using base scanner');
  }
}

// ---------------------------------------------------------------------------
// Task processing
// ---------------------------------------------------------------------------

function processTask(taskId) {
  log('info', `Processing task ${taskId}`);

  // 1. Claim
  try {
    atsClaimTask(taskId);
  } catch (err) {
    try {
      const current = atsGetTask(taskId);
      if (current.assignee_id === ACTOR.id && current.status === 'in_progress') {
        log('info', `Task ${taskId} already assigned to us, continuing`);
      } else {
        log('warn', `Could not claim task ${taskId}`, { error: err.message });
        return;
      }
    } catch {
      log('warn', `Could not claim task ${taskId}`, { error: err.message });
      return;
    }
  }

  // 2. Get task
  const task = atsGetTask(taskId);
  const payload = task.payload || {};

  const text = payload.text || payload.content || payload.body || '';
  if (!text) {
    atsFailTask(taskId, 'Payload must include "text", "content", or "body" field with text to scan');
    return;
  }

  const threshold = payload.threshold ?? 0.50;

  try {
    // 3. Scan
    const startTime = Date.now();
    const result = scan(text, { threshold, fast: payload.fast ?? false });
    const elapsed = Date.now() - startTime;

    // 4. Complete
    const outputs = {
      safe: result.safe,
      score: result.score,
      verdict: result.verdict,
      match_count: result.matches.length,
      categories: [...new Set(result.matches.map(m => m.category))],
      matches: result.matches.map(m => ({
        id: m.id,
        category: m.category,
        weight: m.weight,
        description: m.description,
        matched: m.matched.slice(0, 200),
      })),
      structural_score: result.structural.score,
      structural_signals: result.structural.signals,
      scan_ms: elapsed,
      text_length: text.length,
    };

    atsCompleteTask(taskId, outputs);
    log('info', `Task ${taskId} completed: ${result.verdict} (score=${result.score}, ${elapsed}ms)`);
  } catch (err) {
    log('error', `Task ${taskId} failed`, { error: err.message, stack: err.stack });
    try {
      atsFailTask(taskId, err.message || String(err));
    } catch (failErr) {
      log('error', `Failed to mark task ${taskId} as failed`, { error: failErr.message });
    }
  }
}

// ---------------------------------------------------------------------------
// ATS watcher
// ---------------------------------------------------------------------------

function startWatcher() {
  let reconnectDelay = RECONNECT_DELAY_MS;
  const processing = new Set();

  function launch() {
    log('info', `Starting ATS watcher on channel "${ATS_CHANNEL}"`);

    const child = spawn('ats', [
      'watch',
      '--channel', ATS_CHANNEL,
      '--events', 'task.created',
      '-f', 'json',
    ], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let buffer = '';

    child.stdout.on('data', (chunk) => {
      buffer += chunk.toString();
      const lines = buffer.split('\n');
      buffer = lines.pop();

      for (const line of lines) {
        if (!line.trim()) continue;
        handleWatchLine(line.trim());
      }
    });

    child.stderr.on('data', (chunk) => {
      const text = chunk.toString().trim();
      if (text) log('warn', `ats watch stderr: ${text}`);
    });

    child.on('close', (code) => {
      log('warn', `ats watch exited with code ${code}, reconnecting in ${reconnectDelay}ms`);
      setTimeout(() => {
        reconnectDelay = Math.min(reconnectDelay * 1.5, MAX_RECONNECT_DELAY_MS);
        launch();
      }, reconnectDelay);
    });

    child.on('error', (err) => {
      log('error', `ats watch spawn error`, { error: err.message });
      setTimeout(() => {
        reconnectDelay = Math.min(reconnectDelay * 1.5, MAX_RECONNECT_DELAY_MS);
        launch();
      }, reconnectDelay);
    });

    child.stdout.once('data', () => {
      reconnectDelay = RECONNECT_DELAY_MS;
    });
  }

  function handleWatchLine(line) {
    let taskId;

    try {
      const event = JSON.parse(line);
      taskId = event.task_id || event.taskId || event.id ||
               (event.task && (event.task.id || event.task.task_id)) ||
               (event.data && (event.data.task_id || event.data.id));
    } catch {
      const match = line.match(/Task\s+#(\d+)/);
      if (match) {
        taskId = parseInt(match[1], 10);
      } else {
        log('debug', `Non-event watch line: ${line}`);
        return;
      }
    }

    if (!taskId) {
      log('warn', 'Watch event missing task ID', { line });
      return;
    }

    if (processing.has(taskId)) {
      log('debug', `Task ${taskId} already being processed, skipping`);
      return;
    }

    processing.add(taskId);
    log('info', `New task event: ${taskId}`);

    try {
      processTask(taskId);
    } catch (err) {
      log('error', `Unhandled error for task ${taskId}`, { error: err.message });
    } finally {
      processing.delete(taskId);
    }
  }

  launch();
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main() {
  log('info', '=== Prompt Bonk ATS Agent starting ===', {
    actor: ACTOR,
    channel: ATS_CHANNEL,
  });

  try {
    const version = atsExec(['--help']).split('\n')[0];
    log('info', 'ATS CLI available', { version });
  } catch (err) {
    log('error', 'ATS CLI not available - is ats installed and configured?', { error: err.message });
    process.exit(1);
  }

  // Load openclaw skills into pre-scan pipeline (runs BEFORE security scanner)
  initSkillPipeline();

  startWatcher();

  const shutdown = (sig) => {
    log('info', `Received ${sig}, shutting down`);
    process.exit(0);
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

main();
