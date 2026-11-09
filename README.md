# LLM-WPCG
LLM-Powered WiFi Password Candidate Generator

A desktop GUI tool that turns an ESSID list into high-quality password candidates for
[Hashcat](https://hashcat.net/hashcat/), powered by any locally hosted,
OpenAI-compatible large language model.

It targets WPA/WPA2/WPA3 hashes in Hashcat's `22000` format
(`WPA-PBKDF2-PMKID+EAPOL`) and feeds its output directly into wordlist and rule
based attacks.

---

## Motivation

While working with the combined `WPA-PBKDF2-PMKID+EAPOL` lists from
[hashmob.net](https://hashmob.net/hashlists/combined_lists), I noticed that the
ESSID alone is often enough to crack a meaningful share of hashes — typically
around 1% as a plain wordlist, and up to **30%+** when combined with good rules,
as long as the targets use non-default home router passwords.

The problem: with tens of thousands of hashes (the hashmob dataset alone counts
~190,000), generated wordlists grow quickly and lose feasibility with every
additional entry.

The idea behind this tool: let an LLM parse each ESSID, understand its
language and structure, and generate *candidate seeds* tailored to that specific
network — then cycle forever, always rejecting anything it has already produced,
so each round contributes genuinely new material for rule based attacks.

## Features

- **Tkinter desktop GUI** — no web server, no browser required.
- **Any OpenAI-compatible endpoint** — llama.cpp `llama-server`, vLLM, Ollama's
  OpenAI shim, etc.
- **Deduplicated output** — every candidate is checked against the current wordlist
  *and* every previous run, so no duplicates ever reach Hashcat.
- **Perpetual generation loop** — cycles through the ESSID list endlessly,
  explicitly instructing the model to avoid previously generated passwords.
- **Configurable run modes** — run forever, or stop after a single full cycle.
- **Identified backup shards (`backups/<id>.json`)** — each run is a database
  identified by its run ID. Pick an existing ID to extend that database (full
  history-aware dedup included), or generate a fresh one to start clean.
- **Atomic writes** — the wordlist and backup shards are always written via
  temp-file + rename, so a crash can never corrupt your data.
- **Software engineering niceties** — exponential backoff with capped retry
  delays, rotating log file, bounded in-memory state, live counters
  (current ESSID / cycle / total unique / new per run).

## Included Tools

| File | Purpose |
|------|---------|
| `app.py` | The GUI application itself. |
| `config.json` | All settings: endpoint, file paths, loop mode, run ID, generation parameters. |
| `essid_extractor.py` | Extracts ESSIDs from an `.hc22000` hash file: `python essid_extractor.py <input_file.hc22000> [output_file]` |
| `regexp_essid_filter.py` | Filters out default/vendor ESSIDs with regexes: `python regexp_essid_filter.py <input_file> [trash_output] [usable_output]` — the bundled regexes are intentionally broad; review and adapt them to your dataset. |
| `backups/` | JSON shards, one per run ID, containing every password ever generated plus per-ESSID statistics. |

## Setup

1. Install the only external dependency:

    ```sh
    pip install requests
    ```

2. Start an OpenAI-compatible LLM server (see [Model selection](#model-selection)).

3. Review `config.json` and adjust it to your setup (paths, endpoint URL, prompt sizes).

4. Launch the GUI:

    ```sh
    python app.py
    ```

## Usage

1. Set the **LLM endpoint**, **ESSID file**, and **output wordlist** paths.
2. Choose a **Database ID** — it identifies the backup shard:
    - Selecting an existing ID resumes that database, keeping all previous
      passwords in the deduplication set.
    - Pressing **New random ID** (or leaving it empty) starts a fresh database.
3. Tick **Infinite loop (perpetual generation)** to keep cycling forever; leave it
   unchecked to run exactly one full cycle and stop.
4. Click **Start generation** (`Ctrl+S`); press **Stop** (`Esc`) at any time —
   the stop is graceful and flushes everything to disk.

## Model Selection

### GPU (recommended)

A small instruct model is enough. Example using llama.cpp's `llama-server` on an
RTX 5080:

```sh
llama-server -m LFM3-1.7B-SR-NVFP4.gguf -np 1 --host 0.0.0.0 --port 8080 \
  --no-slots -ctxcp 0 --jinja -c 1024 --cache-ram 0 --load-mode mlock \
  --webui-mcp-proxy --reasoning-budget -1 --reasoning on
```

With this setup, the model reliably parses ESSIDs and produces coherent
candidates at ~310–350 tokens/s, which works out to roughly
**6 passwords per second**.

### CPU

For CPU-only inference, a 1.7B ABLiterated Q4_K_M quantization works well — it is
fast and does not waste tokens on visible reasoning. Model choice matters: a
model that "thinks" before answering is slower and less reliable for this task;
prefer a small non-reasoning instruct model.

### Context size

Run with `1024–4096` tokens of context and pick the smallest value that works for
your model. Smaller contexts are faster, but reasoning-style models may need more.

## Cracking Workflow

Once `generated_passwords.txt` is populated, feed it to Hashcat with a good rule
set:

```sh
hashcat -m 22000 d.hc22000 -S -w 4 -a 0 generated_passwords.txt -r rules/OneRuleToRuleThemAll2.rule
```

The generated list is intentionally compact — it is designed as candidate *seeds*
for rules, not as a massive brute-force wordlist.

## Recommendations

- **Filter default ESSIDs first.** Networks named after their default SSID
  (router vendor defaults) get little value from creative generation; strip them
  with `regexp_essid_filter.py` before generating.
- **Language awareness.** The model usually infers the target's language from the
  ESSID and generates in-scope passwords on its own. If you need stricter control,
  specify the language explicitly in the prompt — note that some small models
  only support ~16 languages, so pick yours accordingly.
- **Growth is inherently sublinear.** Each cycle finds fewer new candidates for
  an ESSID; multiple runs with different models or temperatures increase overall
  coverage.

## Disclaimer

This tool is intended for auditing wireless networks **you own or have explicit
written authorization to test**. Unauthorized access to computer networks is
illegal in most jurisdictions. The authors are not responsible for misuse.

---

Happy auditing!
