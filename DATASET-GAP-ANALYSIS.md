# Prompt Injection Dataset Gap Analysis

## Current Datasets (15 total)

| # | Dataset | Source | Size | Type | Labels |
|---|---------|--------|------|------|--------|
| 1 | deepset/prompt-injections (train) | HuggingFace | ~550 | Direct injection | binary |
| 2 | deepset/prompt-injections (test) | HuggingFace | ~112 | Direct injection | binary |
| 3 | xTRam1/safe-guard-prompt-injection | HuggingFace | ~4,600 | Direct injection | binary |
| 4 | leolee99/NotInject | HuggingFace | ~339 | Benign-only (FP test) | all 0 |
| 5 | rubend18/ChatGPT-Jailbreak-Prompts | HuggingFace | ~78 | Jailbreaks | all 1 |
| 6 | reshabhs/SPML (5k sample) | HuggingFace | 5,000 | System prompt manipulation | binary |
| 7 | protectai/prompt-injection-validation | HuggingFace | ~3,500 | Mixed (7 sub-sources) | binary |
| 8 | perplexity-ai/browsesafe-bench | HuggingFace | ~1,980 | Indirect (HTML/web) | binary |
| 9 | BIPIA | GitHub | 250 | Indirect (embedded) | binary |
| 10 | InjecAgent | GitHub | ~124 | Indirect (tool-use) | binary |
| 11 | ai-safety-institute/AgentHarm | HuggingFace | ~214 | Harmful agent actions | all 1 |
| 12 | facebook/cyberseceval3 | HuggingFace | ~546 | Visual injection text | all 1 |
| 13 | qxcv/tensor-trust | HuggingFace | 10,000 | Instruction hijacking CTF | success-based |
| 14 | hackaprompt | HuggingFace | ~6,000 | CTF competition | success-based |
| 15 | (various in protectai) | HuggingFace | included | InjecGuard, spikee, wildguard, etc. | binary |

---

## MISSING Datasets - Recommended Additions

### TIER 1: High Value (directly tests prompt injection detection, public, labeled)

#### 1. hendzh/PromptShield
- **Source**: https://huggingface.co/datasets/hendzh/PromptShield
- **Size**: 43.4K rows (18.9K train, 1K validation, 23.5K test)
- **What**: Binary classification of prompt injection attempts, built from curated open-source datasets plus Ultrachat/LMSYS benign data. Includes sophisticated attack strategies.
- **Why add**: Large, well-labeled dataset with structured prompts (system + user). Test set is significantly larger than anything we currently benchmark against. Their eval split specifically uses more sophisticated attacks.
- **Overlap**: Some sub-data may overlap with deepset/protectai, but the composite and structured format is unique.
- **Regex-testable**: YES - contains explicit injection language

#### 2. qualifire/prompt-injections-benchmark
- **Source**: https://huggingface.co/datasets/qualifire/prompt-injections-benchmark
- **Size**: 5,000 prompts
- **What**: Balanced jailbreak/benign classification
- **Why add**: Independent benchmark from Qualifire (Sentinel model creators), likely different distribution than our existing datasets
- **Regex-testable**: YES

#### 3. microsoft/llmail-inject-challenge  <<<< TOP PRIORITY
- **Source**: https://huggingface.co/datasets/microsoft/llmail-inject-challenge
- **Size**: 462K raw (Phase1: 371K, Phase2: 91K). ~160K unique after dedup.
- **Format**: Parquet. Fields: `subject` (email subject), `body` (email body with injection), `scenario` (40 attack scenarios), `objectives` (13 attack objectives), `output` (JSON with success booleans: email.retrieved, defense.undetected, exfil.sent, exfil.destination, exfil.content)
- **What**: Indirect prompt injection via email targeting LLM email assistant. SaTML 2025 competition. 224 teams. All entries are attack attempts (label=1).
- **Why #1 priority**: (1) Only email-based injection dataset — enterprise attack vector #1. (2) Human-crafted adversarial attacks, not synthetic. (3) Exercises our existing email exfiltration patterns. (4) Separate FP test file (203 benign emails). (5) Sales-ready: "tested against 160K email injection attacks from Microsoft SaTML competition."
- **Integration plan**: Sample 10K from Phase1. Scan `subject + ' ' + body`. All label=1 (attack-only set). Download separately: `emails_for_fp_tests.jsonl` (203 benign emails, label=0).
- **Attack techniques observed**: Delimiter injection (`<<...>>`, `</context>`), JSON/XML embedded instructions, multi-message fragmentation, encoding/obfuscation, social engineering, role-play
- **Language**: Primarily English (competition was English-focused). Minimal non-English.
- **License**: MIT
- **Overlap**: None — unique email-based format

#### 4. Lakera/gandalf_ignore_instructions
- **Source**: https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions
- **Size**: ~millions of prompts (filtered by semantic similarity to "ignore instructions")
- **What**: Real-world prompt injection attempts from Gandalf CTF game, filtered to ignore-instructions style attacks
- **Why add**: Massive corpus of real human creativity in prompt injection. These are actual attack attempts, not synthetic.
- **Regex-testable**: YES - explicitly filtered for instruction-override patterns

#### 5. Lakera/mosscap_prompt_injection
- **Source**: https://huggingface.co/datasets/Lakera/mosscap_prompt_injection
- **Size**: Hundreds of thousands of prompts
- **What**: Prompt injections from DEF CON 31 Mosscap CTF
- **Why add**: DEF CON crowd produces creative, adversarial attacks. Mix of actual injections and benign queries.
- **Regex-testable**: YES

#### 6. TrustAIRLab/in-the-wild-jailbreak-prompts
- **Source**: https://huggingface.co/datasets/TrustAIRLab/in-the-wild-jailbreak-prompts
- **Size**: 15,140 prompts (1,405 jailbreak)
- **What**: Real jailbreak prompts from Reddit, Discord, websites. CCS 2024 paper.
- **Why add**: In-the-wild distribution vs synthetic. Binary jailbreak/benign labels.
- **Overlap**: Some with rubend18/Jailbreak-Prompts but much larger with benign baseline
- **Regex-testable**: YES

#### 7. jackhhao/jailbreak-classification
- **Source**: https://huggingface.co/datasets/jackhhao/jailbreak-classification
- **Size**: 1,306 (640 benign, 666 jailbreak)
- **What**: Balanced binary jailbreak classification dataset
- **Why add**: Small but well-balanced, good for quick regression testing
- **Regex-testable**: YES

#### 8. SaTML LLM CTF 2024
- **Source**: https://github.com/ethz-spylab/satml-llm-ctf
- **Size**: 144,838 adversarial chats + 72 defenses
- **What**: Multi-turn prompt injection/extraction from SaTML 2024 CTF competition
- **Why add**: Multi-turn attacks, complex filter bypass attempts, real competition data
- **Regex-testable**: YES - many use explicit injection patterns

### TIER 2: Valuable but with caveats

#### 9. Lakera/gandalf-rct
- **Source**: https://huggingface.co/datasets/Lakera/gandalf-rct
- **Size**: 279,675 prompts from 15,402 users
- **What**: Randomized controlled trial of Gandalf prompt attacks (Oct-Nov 2024)
- **Why add**: Rigorous RCT design, multiple defense setups. Largest controlled prompt injection dataset.
- **Caveat**: Not labeled as injection/benign (all are attack attempts). Best used as injection-only test set.

#### 10. ScaleAI/mhj (Multi-Turn Human Jailbreaks)
- **Source**: https://huggingface.co/datasets/ScaleAI/mhj
- **Size**: 2,912 prompts across 537 multi-turn conversations
- **What**: Professional red team jailbreaks from Scale AI commercial engagements
- **Why add**: High-quality, professional-grade attacks. >70% ASR against hardened defenses.
- **Caveat**: Multi-turn format may need flattening. CC BY-NC 4.0 license.
- **Regex-testable**: PARTIALLY - some use explicit injection, others are pure social engineering

#### 11. walledai/JailbreakHub
- **Source**: https://huggingface.co/datasets/walledai/JailbreakHub
- **Size**: 15,140 prompts (1,405 jailbreak)
- **What**: Same underlying data as TrustAIRLab but via walledai organization
- **Overlap**: HIGH with TrustAIRLab - likely same dataset, pick one

#### 12. JailbreakBench/JBB-Behaviors
- **Source**: https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors
- **Size**: 100 misuse behaviors + 100 benign behaviors
- **What**: Curated harmful request behaviors (not injection per se)
- **Caveat**: Small, more about content safety than injection detection

#### 13. Lakera/gandalf_summarization
- **Source**: https://huggingface.co/datasets/Lakera/gandalf_summarization
- **Size**: Unknown
- **What**: Indirect prompt injection from Gandalf Adventure 4 level
- **Why add**: Specifically indirect injection (injection via summarization task)
- **Regex-testable**: PARTIALLY

#### 14. geekyrakshit/prompt-injection-dataset
- **Source**: https://huggingface.co/datasets/geekyrakshit/prompt-injection-dataset
- **Size**: Unknown
- **What**: Another prompt injection dataset on HuggingFace
- **Needs investigation**: May overlap with existing

#### 15. PromptInject (AgencyEnterprise)
- **Source**: https://github.com/agencyenterprise/PromptInject
- **Size**: Framework generates combinations (not a static dataset)
- **What**: NeurIPS ML Safety 2022 Best Paper. Modular framework for goal hijacking + prompt leaking
- **Why add**: Generates adversarial prompts programmatically. Could extract static test set.
- **Regex-testable**: YES

### TIER 3: Niche / Limited Utility for Regex Scanner

#### 16. walledai/HarmBench
- **Source**: https://huggingface.co/datasets/walledai/HarmBench
- **What**: Harmful behaviors for red-teaming (content safety, not injection)
- **Why skip**: Content safety, not injection detection

#### 17. Agent-SafetyBench
- **Source**: https://github.com/thu-coai/Agent-SafetyBench
- **Size**: 2,000 test cases across 349 environments
- **What**: LLM agent safety evaluation (broader than injection)
- **Why limited**: Tests agent behavior, not injection detection

#### 18. EIA (Environmental Injection Attack)
- **Source**: Research paper, 177 action steps from Mind2Web
- **What**: Visual/environmental injection for web agents
- **Why limited**: Visual attack - not text-scannable

#### 19. WebInject
- **Source**: EMNLP 2025 paper
- **What**: Pixel-level injection on web agent screenshots
- **Why skip**: Image-based, not text-scannable

#### 20. RedBench
- **Source**: HuggingFace papers
- **Size**: 29,362 samples aggregating 37 benchmarks
- **What**: Meta-benchmark across 22 risk categories
- **Caveat**: Aggregation of existing datasets, likely significant overlap

#### 21. PINT Benchmark (Lakera)
- **Source**: https://github.com/lakeraai/pint-benchmark
- **Size**: 4,314 inputs (3,016 English, 1,298 non-English)
- **What**: Intentionally private dataset to prevent overfitting
- **Why limited**: Dataset itself is not public (by design)

---

## Coverage Gap Analysis

### What we cover well:
- Direct instruction override ("ignore previous instructions")
- Jailbreak prompts (DAN, developer mode)
- System prompt extraction
- Basic indirect injection (HTML, documents)
- Over-defense testing (NotInject)

### Systemic blind spot: Multilingual
- ALL 15 current datasets are English-only
- ALL 418 scanner patterns are English regex
- PINT benchmark (private) specifically includes 1,298 non-English inputs because that's where scanners fail
- Our own project memory confirms: German `\w+` doesn't match umlauts, Cyrillic homoglyph normalization was needed
- **No public multilingual prompt injection benchmark exists** — this is an industry-wide gap
- Potential sources: Lakera/gandalf datasets may have non-English submissions, hendzh/PromptShield may contain multilingual prompts

### What we're missing:

| Gap | Recommended Dataset | Priority |
|-----|-------------------|----------|
| **Email-based indirect injection** | microsoft/llmail-inject-challenge | HIGH |
| **Large-scale real human attacks** | Lakera/gandalf_ignore_instructions | HIGH |
| **Structured prompt format** (system+user) | hendzh/PromptShield | HIGH |
| **In-the-wild jailbreaks** with benign baseline | TrustAIRLab/in-the-wild-jailbreak-prompts | HIGH |
| **DEF CON / security community attacks** | Lakera/mosscap_prompt_injection | MEDIUM |
| **Multi-turn attacks** | SaTML LLM CTF 2024 | MEDIUM |
| **Independent benchmark** (different source) | qualifire/prompt-injections-benchmark | MEDIUM |
| **RCT-validated attack corpus** | Lakera/gandalf-rct | MEDIUM |
| **Professional red team** attacks | ScaleAI/mhj | LOW |
| **Summarization-based indirect** | Lakera/gandalf_summarization | LOW |

### Recommended Priority Additions (Top 5):

1. **microsoft/llmail-inject-challenge** - 160K+ email injection attacks, fills our email blind spot (enterprise attack vector #1). Human-crafted adversarial attacks from SaTML 2025 competition. Includes 203 FP test emails. Start with 10K sample.
2. **TrustAIRLab/in-the-wild-jailbreak-prompts** - 15K real-world prompts with labels from Reddit/Discord/websites. Different distribution than synthetic datasets.
3. **Lakera/gandalf_ignore_instructions** - Massive real attack corpus from CTF game. Millions of creative human attempts.
4. **Lakera/mosscap_prompt_injection** - DEF CON 31 security community attacks. High adversarial quality.
5. **qualifire/prompt-injections-benchmark** - 5K independent benchmark from different source

**Deprioritized:** hendzh/PromptShield (43K) — composite of existing open-source datasets. We already score 95-100% precision on direct injection. Adding more direct injection samples provides volume, not signal. Our gap is in *indirect injection coverage*, not direct.

---

*Generated: 2026-02-07 | Iteration 1 of dataset research loop*
