#!/usr/bin/env python3
"""WiFi password-seed generator (PySide-free Tkinter edition).

Desktop GUI - A worker thread talks to a
local LLM (OpenAI-compatible endpoint), asks for password seeds related to each
ESSID and feeds unique candidates into a hashcat-style wordlist.

Key production features
-----------------------
* Tkinter GUI.
* Persistent *backup store*: every run is a shard identified by a unique run id
  (`backups/<id>.json` + `backups/index.json`). All shards are merged into an
  in-memory "seen" set at startup, so switching between backup files / old runs
  still guarantees only NEW passwords are ever emitted.
* Perpetual generation loop: the worker keeps cycling the ESSID list forever,
  telling the LLM which passwords it already produced for that ESSID so every
  cycle yields different candidates.
* Incremental, atomic writes (wordlist is never corrupted if the app dies).
* Exponential backoff on LLM errors, hard stop button, graceful shutdown.
* Logging to console + rotating file, counters in the status bar.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import queue
import random
import re
import string
import threading
import time
import tkinter as tk
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Any, Dict, List, Optional, Set

import requests

# --------------------------------------------------------------------------- #
# Configuration                                                               #
# --------------------------------------------------------------------------- #

SCRIPT_DIR = Path(__file__).resolve().parent


@dataclass
class Config:
    """Runtime configuration, editable from the GUI."""

    llama_url: str = "http://localhost:8080/v1/chat/completions"
    essid_file: Path = SCRIPT_DIR / "essids.txt"
    output_file: Path = SCRIPT_DIR / "generated_passwords.txt"
    backup_dir: Path = SCRIPT_DIR / "backups"
    log_file: Path = SCRIPT_DIR / "generator.log"

    max_retries: int = 5
    timeout: float = 600.0
    temperature: float = 1.0
    max_tokens: int = 1024
    run_id: str = ""                     # backup-shard id = which database to extend
    infinite_loop: bool = True           # False = run exactly one full ESSID cycle

    passwords_per_prompt: int = 6
    avoid_sample_size: int = 25          # previously generated passwords shown to the LLM
    backup_flush_interval: float = 10.0  # seconds between backup flushes
    poll_ms: int = 100                   # GUI -> worker queue poll interval

    # Password validation rules (mirrors the original parser).
    min_len: int = 4
    max_len: int = 16

    def as_dict(self) -> Dict[str, Any]:
        return {
            "llama_url": self.llama_url,
            "essid_file": str(self.essid_file),
            "output_file": str(self.output_file),
            "backup_dir": str(self.backup_dir),
            "max_retries": self.max_retries,
            "timeout": self.timeout,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "passwords_per_prompt": self.passwords_per_prompt,
            "run_id": self.run_id,
            "infinite_loop": self.infinite_loop,
        }


SYSTEM_PROMPT = (
    "You are an expert in creative password generation and WiFi security auditing. "
    "Your only job is to look at a WiFi network name (ESSID) and reply with likely "
    "password candidates in the exact format the user asks for. "
    "Output passwords only, one per line, no numbering, no explanations."
)

# Candidate must look like a plausible password: alnum, not a single repeated char.
RE_CANDIDATE = re.compile(r"[A-Za-z0-9!@#$%^&*_.\-]{4,16}")


# --------------------------------------------------------------------------- #
# Logging                                                                     #
# --------------------------------------------------------------------------- #

def setup_logging(log_file: Path) -> logging.Logger:
    logger = logging.getLogger("pwgen")
    if logger.handlers:            # avoid duplicate handlers on reload
        return logger
    logger.setLevel(logging.INFO)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")

    console = logging.StreamHandler()
    console.setFormatter(fmt)
    logger.addHandler(console)

    log_file.parent.mkdir(parents=True, exist_ok=True)
    rotating = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=2_000_000, backupCount=5, encoding="utf-8"
    )
    rotating.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    )
    logger.addHandler(rotating)
    return logger


# --------------------------------------------------------------------------- #
# Backup store: shard per run, identified by a unique id                      #
# --------------------------------------------------------------------------- #

def _atomic_write(path: Path, data: str) -> None:
    """Write file atomically so a crash can never truncate existing data."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(data, encoding="utf-8")
    tmp.replace(path)


def _new_run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return f"{stamp}_{suffix}"


RE_INVALID_ID = re.compile(r"[^A-Za-z0-9_\-]+")


def sanitize_run_id(raw: str) -> str:
    """Keep only filename-safe characters for shard ids."""
    cleaned = RE_INVALID_ID.sub("-", raw.strip()).strip("-._")
    return cleaned[:64] if len(cleaned) >= 3 else ""


def generate_run_id() -> str:
    """Random id for a brand-new database shard."""
    return _new_run_id()


CONFIG_FILE = SCRIPT_DIR / "config.json"


def save_config(cfg: Config, path: Path = CONFIG_FILE) -> None:
    try:
        _atomic_write(path, json.dumps(cfg.as_dict(), indent=2))
    except OSError as exc:
        logging.getLogger("pwgen").error("Could not save config: %s", exc)


def load_config(path: Path = CONFIG_FILE) -> Config:
    """Load config.json (creating a default one on first run)."""
    cfg = Config()
    if not path.is_file():
        save_config(cfg, path)
        return cfg
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        logging.getLogger("pwgen").warning("Unreadable %s, using defaults", path)
        return cfg
    if not isinstance(data, dict):
        return cfg

    for key in ("essid_file", "output_file", "backup_dir", "log_file"):
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            p = Path(value)
            setattr(cfg, key, p if p.is_absolute() else SCRIPT_DIR / p)
    if isinstance(data.get("llama_url"), str) and data["llama_url"].strip():
        cfg.llama_url = data["llama_url"].strip()
    if isinstance(data.get("run_id"), str):
        cfg.run_id = sanitize_run_id(data["run_id"])
    if isinstance(data.get("infinite_loop"), bool):
        cfg.infinite_loop = data["infinite_loop"]

    numeric_fields = {
        "max_retries": int,
        "timeout": float,
        "temperature": float,
        "max_tokens": int,
        "passwords_per_prompt": int,
        "avoid_sample_size": int,
        "backup_flush_interval": float,
        "min_len": int,
        "max_len": int,
    }
    for key, caster in numeric_fields.items():
        try:
            value = caster(data[key])
        except (KeyError, TypeError, ValueError):
            continue
        if value > 0:
            setattr(cfg, key, value)
    return cfg


@dataclass
class BackupShard:
    """One run's generated passwords, persisted as JSON identified by run id."""

    id: str
    path: Path
    created_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_utc: str = ""
    source_essid_file: str = ""
    essid_counts: Dict[str, int] = field(default_factory=dict)
    passwords: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "created_utc": self.created_utc,
            "updated_utc": self.updated_utc,
            "source_essid_file": self.source_essid_file,
            "essid_counts": self.essid_counts,
            "passwords": self.passwords,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any], path: Path) -> "BackupShard":
        return cls(
            id=str(data.get("id") or path.stem),
            path=path,
            created_utc=str(data.get("created_utc", "")),
            updated_utc=str(data.get("updated_utc", "")),
            source_essid_file=str(data.get("source_essid_file", "")),
            essid_counts={str(k): int(v) for k, v in data.get("essid_counts", {}).items()},
            passwords=[str(p) for p in data.get("passwords", [])],
        )


class BackupStore:
    """Persistent, ID-identified store of every password ever generated.

    * ``new_shard()`` creates a shard with a fresh run id for the current run.
    * ``load_all()`` merges *every* shard found in the backup directory into the
      ``seen`` set, so restarting the app or switching to an older backup file
      never resurrects a password that was already generated.
    * ``add()`` buffers candidates in memory and the worker flushes them
      periodically (and at shutdown) with atomic writes.
    """

    def __init__(self, directory: Path, logger: logging.Logger) -> None:
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self.logger = logger
        self.seen: Set[str] = set()
        self.shards: Dict[str, BackupShard] = {}
        self._current: Optional[BackupShard] = None
        self._buffer: Set[str] = set()          # pending shard passwords
        self._buffer_counts: Dict[str, int] = {}
        self._dirty = False
        self._load_all()

    # -- loading -------------------------------------------------------------- #

    def _load_all(self) -> None:
        for path in sorted(self.directory.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                shard = BackupShard.from_dict(data, path)
            except (ValueError, OSError) as exc:
                self.logger.warning("Skipping unreadable backup %s: %s", path.name, exc)
                continue
            self.shards[shard.id] = shard
            self.seen.update(shard.passwords)
        self.logger.info(
            "Backup store loaded: %d shard(s), %d known passwords",
            len(self.shards), len(self.seen),
        )

    # -- current run -----------------------------------------------------------#

    def shard_ids(self) -> List[str]:
        return sorted(self.shards)

    def shard_files(self) -> List[str]:
        return sorted(s.path.name for s in self.shards.values())

    def use_shard(self, raw_run_id: str, source_essid_file: str = "") -> str:
        """Attach to an existing shard (= keep writing that database), or open a
        brand-new shard identified by ``raw_run_id``."""
        run_id = sanitize_run_id(raw_run_id) or _new_run_id()
        self._buffer.clear()
        self._buffer_counts.clear()
        existing = self.shards.get(run_id)
        if existing is not None:
            self._current = existing
            self.logger.info(
                "Using existing database shard %s (%d passwords, %d ESSID(s))",
                existing.path.name, len(existing.passwords), len(existing.essid_counts),
            )
            return run_id
        shard = BackupShard(
            id=run_id,
            path=self.directory / f"{run_id}.json",
            source_essid_file=source_essid_file,
            updated_utc=datetime.now(timezone.utc).isoformat(),
        )
        self.shards[run_id] = shard
        self._current = shard
        self.flush()
        self.logger.info("New database shard: %s", shard.path.name)
        return run_id

    # -- mutation --------------------------------------------------------------#

    def is_new(self, password: str) -> bool:
        """True only if the password was never generated in ANY shard."""
        return password not in self.seen

    def add(self, password: str, essid: str) -> None:
        self.seen.add(password)
        self._buffer.add(password)
        self._buffer_counts[essid] = self._buffer_counts.get(essid, 0) + 1
        self._dirty = True

    # -- persistence ------------------------------------------------------------#

    def flush(self) -> None:
        """Persist the current shard (and any buffered candidates) to disk."""
        shard = self._current
        if shard is None:
            return
        for pwd in self._buffer:
            shard.passwords.append(pwd)
        self._buffer.clear()
        for essid, count in self._buffer_counts.items():
            shard.essid_counts[essid] = shard.essid_counts.get(essid, 0) + count
        self._buffer_counts.clear()

        if self._dirty or True:  # always rewrite while a run is active
            shard.updated_utc = datetime.now(timezone.utc).isoformat()
            shard.passwords.sort()
            try:
                _atomic_write(shard.path, json.dumps(shard.to_dict(), indent=1))
                self._dirty = False
            except OSError as exc:
                self.logger.error("Failed to write backup shard: %s", exc)


# --------------------------------------------------------------------------- #
# LLM client                                                                  #
# --------------------------------------------------------------------------- #

def load_essids(path: Path) -> List[str]:
    """Read unique ESSIDs from file, newest-file friendly and order stable."""
    if not path.is_file():
        raise FileNotFoundError(f"ESSID file not found: {path}")
    essids = []
    seen: Set[str] = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        essid = line.strip()
        if essid and essid not in seen:
            seen.add(essid)
            essids.append(essid)
    if not essids:
        raise ValueError(f"No ESSIDs found in {path}")
    return essids


class PasswordGenerator:
    """Queries the LLM and yields validated, deduplicated passwords."""

    def __init__(self, config: Config, store: BackupStore, logger: logging.Logger) -> None:
        self.config = config
        self.store = store
        self.logger = logger
        self.session = requests.Session()
        self.session.headers["Content-Type"] = "application/json"
        self.stop_event = threading.Event()
        self.known_per_essid: Dict[str, List[str]] = {}
        self.cycle = 0
        self.generated_count = 0

    # -- prompt ---------------------------------------------------------------- #

    def build_prompt(self, essid: str) -> str:
        cfg = self.config
        avoid = self.known_per_essid.get(essid, [])
        lines = [
            f"WiFi network name (ESSID): {essid}",
            "",
            f"Generate {cfg.passwords_per_prompt} common password seeds "
            f"({cfg.min_len}-{cfg.max_len} characters) that someone who chose this "
            "WiFi name might use.",
        ]
        if avoid:
            sample = random.sample(avoid, min(cfg.avoid_sample_size, len(avoid)))
            lines += [
                "",
                "These passwords were already generated. Do NOT repeat them or "
                "minor variations of them, produce completely NEW different ones:",
            ]
            lines += sample
        if self.cycle > 0:
            lines += [
                "",
                f"This is generation round {self.cycle + 1} for this network: every "
                "round must contain only passwords never produced before.",
            ]
        lines += ["", "Format: one password per line, no extra text."]
        return "\n".join(lines)

    # -- HTTP ------------------------------------------------------------------ #

    def query_llm(self, essid: str) -> Optional[str]:
        payload = {
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": self.build_prompt(essid)},
            ],
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }
        for attempt in range(1, self.config.max_retries + 1):
            if self.stop_event.is_set():
                return None
            try:
                resp = self.session.post(
                    self.config.llama_url, json=payload, timeout=self.config.timeout
                )
                resp.raise_for_status()
                content = resp.json()["choices"][0]["message"]["content"]
                if content and content.strip():
                    return content
                self.logger.warning("Empty LLM response for %s (attempt %d)", essid, attempt)
            except requests.RequestException as exc:
                delay = min(2 ** attempt, 60)
                self.logger.warning(
                    "LLM request failed for %s (attempt %d/%d): %s - retrying in %ds",
                    essid, attempt, self.config.max_retries, exc, delay,
                )
                self.stop_event.wait(delay)
            except (KeyError, IndexError, ValueError) as exc:
                self.logger.error("Malformed LLM response for %s: %s", essid, exc)
                return None
        self.logger.error("Giving up on %s after %d attempts", essid, self.config.max_retries)
        return None

    # -- parsing ----------------------------------------------------------------#

    def parse_passwords(self, raw_text: str) -> List[str]:
        cfg = self.config
        candidates: List[str] = []
        for match in RE_CANDIDATE.findall(raw_text):
            pwd = match.strip()
            if not (cfg.min_len <= len(pwd) <= cfg.max_len):
                continue
            if pwd.isdigit() and len(pwd) < 6:            # skip trivial short numbers
                continue
            if len(set(pwd.lower())) < 2:                 # skip single-char repeats
                continue
            if pwd.lower() in {"password", "admin", "qwerty", "12345678"}:
                continue
            candidates.append(pwd)
        return candidates

    def remember(self, essid: str, password: str) -> None:
        known = self.known_per_essid.setdefault(essid, [])
        known.append(password)
        if len(known) > 200:                              # bounded memory footprint
            del known[: len(known) - 200]


# --------------------------------------------------------------------------- #
# Worker: perpetual generation loop                                           #
# --------------------------------------------------------------------------- #

class GenerationWorker:
    """Runs the endless ESSID -> LLM -> wordlist loop on a background thread."""

    def __init__(
        self,
        config: Config,
        store: BackupStore,
        logger: logging.Logger,
        events: queue.Queue,
    ) -> None:
        self.config = config
        self.store = store
        self.logger = logger
        self.events = events          # dicts consumed by the GUI
        self.gen = PasswordGenerator(config, store, logger)
        self.thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()

    @property
    def running(self) -> bool:
        return bool(self.thread and self.thread.is_alive())

    def start(self) -> None:
        if self.running:
            return
        self.stop_event.clear()
        self.thread = threading.Thread(
            target=self._run_safe, name="generator-worker", daemon=True
        )
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.gen.stop_event.set()

    # -- internals --------------------------------------------------------------#

    def _emit(self, event: Dict[str, Any]) -> None:
        try:
            self.events.put_nowait(event)
        except queue.Full:                                # pragma: no cover
            pass

    def _run_safe(self) -> None:
        try:
            self._run()
        except Exception:                                 # noqa: BLE001 - last resort
            self.logger.exception("Worker crashed")
            self._emit({"type": "fatal", "message": "Worker crashed, see log file."})

    def _run(self) -> None:
        cfg = self.config
        essids = load_essids(cfg.essid_file)
        cfg.run_id = sanitize_run_id(cfg.run_id) or _new_run_id()
        run_id = self.store.use_shard(cfg.run_id, cfg.essid_file.name)

        # Wordlist: start from whatever already exists so it stays one master list.
        output = cfg.output_file
        output.parent.mkdir(parents=True, exist_ok=True)
        existing: Set[str] = {
            p.strip() for p in output.read_text(encoding="utf-8", errors="replace").splitlines() if p.strip()
        } if output.is_file() else set()

        self._emit({"type": "start", "essid_total": len(essids), "run_id": run_id})
        self.logger.info(
            "Run %s started: %d ESSIDs, %d pre-existing wordlist entries",
            run_id, len(essids), len(existing),
        )

        last_flush = time.monotonic()

        # ---------------- perpetual loop: cycle ESSIDs forever ---------------- #
        while not self.stop_event.is_set():
            self.gen.cycle += 1
            for index, essid in enumerate(essids):
                if self.stop_event.is_set():
                    break
                self._emit({
                    "type": "progress",
                    "current": index + 1,
                    "total": len(essids),
                    "cycle": self.gen.cycle,
                    "essid": essid,
                })

                raw = self.gen.query_llm(essid)
                if not raw:
                    continue

                new_count = 0
                for pwd in self.gen.parse_passwords(raw):
                    if self.stop_event.is_set():
                        break
                    # Only truly NEW passwords pass: current run + every backup.
                    if pwd in existing or not self.store.is_new(pwd):
                        continue
                    existing.add(pwd)
                    self.store.add(pwd, essid)
                    self.gen.remember(essid, pwd)
                    self.gen.generated_count += 1
                    new_count += 1
                    self._emit({"type": "password", "password": pwd, "essid": essid})

                if new_count:
                    self.logger.info(
                        "%s -> %d new password(s) (session total: %d)",
                        essid, new_count, self.gen.generated_count,
                    )

                # Periodic atomic flush of backup shard + master wordlist.
                if time.monotonic() - last_flush >= cfg.backup_flush_interval:
                    self._flush_wordlist(output, existing)
                    self.store.flush()
                    last_flush = time.monotonic()

            self._flush_wordlist(output, existing)
            self.store.flush()
            self._emit({"type": "cycle_done", "cycle": self.gen.cycle})
            if not self.config.infinite_loop:
                self.logger.info("Single-cycle run finished (infinite loop disabled).")
                break

        # ------------------------- graceful shutdown -------------------------- #
        self._flush_wordlist(output, existing)
        self.store.flush()
        self._emit({
            "type": "stopped",
            "total": len(existing),
            "session_new": self.gen.generated_count,
        })
        self.logger.info("Worker stopped cleanly, shard flushed.")

    def _flush_wordlist(self, path: Path, passwords: Set[str]) -> None:
        try:
            _atomic_write(path, "\n".join(sorted(passwords)) + "\n")
        except OSError as exc:
            self.logger.error("Failed to write wordlist: %s", exc)


# --------------------------------------------------------------------------- #
# GUI                                                                         #
# --------------------------------------------------------------------------- #

class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("WiFi Password Seed Generator - hashcat feeder")
        self.geometry("920x640")
        self.minsize(720, 520)

        self.config = load_config()
        if not self.config.run_id:
            self.config.run_id = generate_run_id()
            save_config(self.config)
        self.logger = setup_logging(self.config.log_file)
        self.events: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self.store = BackupStore(self.config.backup_dir, self.logger)
        self.worker = GenerationWorker(self.config, self.store, self.logger, self.events)

        self._counters = {
            "current": tk.StringVar(value="-"),
            "cycle": tk.StringVar(value="0"),
            "uniq": tk.StringVar(value=str(len(self.store.seen))),
            "new": tk.StringVar(value="0"),
        }

        self._build_widgets()
        self._bind_keys()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(self.config.poll_ms, self._poll_events)
        self.logger.info("GUI ready, %d backup shard(s) loaded", len(self.store.shards))

    # -- UI construction --------------------------------------------------------#

    def _build_widgets(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        # Settings frame ------------------------------------------------------- #
        settings = ttk.LabelFrame(self, text="Settings", padding=8)
        settings.grid(row=0, column=0, sticky="nsew", padx=10, pady=(10, 5))
        for col in (1,):
            settings.columnconfigure(col, weight=1)

        self.var_url = tk.StringVar(value=self.config.llama_url)
        self.var_essid = tk.StringVar(value=str(self.config.essid_file))
        self.var_output = tk.StringVar(value=str(self.config.output_file))
        self.var_temp = tk.DoubleVar(value=self.config.temperature)

        def _row(grid_row: int, label: str, var: tk.Variable, width: int = 60) -> None:
            ttk.Label(settings, text=label).grid(row=grid_row, column=0, sticky="w", pady=3)
            ttk.Entry(settings, textvariable=var, width=width).grid(
                row=grid_row, column=1, sticky="ew", padx=6
            )

        _row(0, "LLM endpoint:", self.var_url)
        _row(1, "ESSID file:", self.var_essid)
        _row(2, "Output wordlist:", self.var_output)
        ttk.Label(settings, text="Temperature:").grid(row=3, column=0, sticky="w", pady=3)
        ttk.Spinbox(
            settings, from_=0.0, to=2.0, increment=0.05, textvariable=self.var_temp, width=8
        ).grid(row=3, column=1, sticky="w", padx=6)

        ttk.Label(settings, text="Database ID:").grid(row=4, column=0, sticky="w", pady=3)
        self.var_run_id = tk.StringVar(value=self.config.run_id or "")
        self.cmb_runid = ttk.Combobox(
            settings, textvariable=self.var_run_id, width=30,
            values=self.store.shard_ids(),
        )
        self.cmb_runid.grid(row=4, column=1, sticky="ew", padx=6)
        ttk.Button(settings, text="New random ID", command=self._random_run_id).grid(
            row=4, column=2, padx=4
        )

        ttk.Button(settings, text="Browse ESSID...", command=self._browse_essid).grid(
            row=1, column=2, padx=4
        )
        ttk.Button(settings, text="Browse Output...", command=self._browse_output).grid(
            row=2, column=2, padx=4
        )

        # Control frame (sticky top-right, red)- --------------------------------#
        controls = ttk.Frame(self, padding=(10, 0, 10, 5))
        controls.grid(row=1, column=0, sticky="ew")
        controls.columnconfigure(0, weight=1)

        self.var_infinite = tk.BooleanVar(value=self.config.infinite_loop)
        ttk.Checkbutton(
            controls, text="Infinite loop (perpetual generation)", variable=self.var_infinite
        ).grid(row=0, column=0, sticky="w")

        self.btn_start = ttk.Button(controls, text="Start generation", command=self.start)
        self.btn_start.grid(row=0, column=1, padx=4)
        self.btn_stop = ttk.Button(
            controls, text="Stop", command=self.stop, state=tk.DISABLED
        )
        self.btn_stop.grid(row=0, column=2, padx=4)
        self.btn_flush = ttk.Button(
            controls, text="Flush backup now", command=self._manual_flush, state=tk.DISABLED
        )
        self.btn_flush.grid(row=0, column=3, padx=4)

        # Log area --------------------------------------------------------------#
        log_frame = ttk.LabelFrame(self, text="Activity log", padding=4)
        log_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=5)
        log_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)

        self.log_box = scrolledtext.ScrolledText(
            log_frame, height=18, state=tk.DISABLED, wrap="word", font=("Consolas", 9)
        )
        self.log_box.grid(row=0, column=0, sticky="nsew")
        for tag, color, bold in (
            ("info", "#404040", False),
            ("ok", "#106010", False),
            ("warn", "#a06000", False),
            ("error", "#a01010", True),
            ("pwd", "#0050a0", False),
        ):
            self.log_box.tag_configure(tag, foreground=color, font=("Consolas", 10, "bold" if bold else "normal"))

        # Status bar ------------------------------------------------------------#
        status = ttk.Frame(self, relief="sunken", padding=4)
        status.grid(row=3, column=0, sticky="ew", padx=10, pady=(0, 10))
        for col in range(0, 8, 2):
            status.columnconfigure(col, weight=0)
        status.columnconfigure(7, weight=1)

        def _stat(col: int, label: str, var: tk.StringVar) -> None:
            ttk.Label(status, text=label, font=("Segoe UI", 9, "bold")).grid(row=0, column=col, padx=(8, 2))
            ttk.Label(status, textvariable=var, width=12, anchor="w").grid(row=0, column=col + 1)

        _stat(0, "ESSID:", self._counters["current"])
        _stat(2, "Cycle:", self._counters["cycle"])
        _stat(4, "Unique known:", self._counters["uniq"])
        _stat(6, "New this run:", self._counters["new"])

    def _bind_keys(self) -> None:
        self.bind("<Control-s>", lambda _e: self.start())
        self.bind("<Escape>", lambda _e: self.stop())

    # -- actions ----------------------------------------------------------------#

    def _apply_settings(self) -> None:
        cfg = self.config
        cfg.llama_url = self.var_url.get().strip() or cfg.llama_url
        cfg.essid_file = Path(self.var_essid.get().strip())
        cfg.output_file = Path(self.var_output.get().strip())
        try:
            cfg.temperature = max(0.0, min(2.0, float(self.var_temp.get())))
        except (tk.TclError, ValueError):
            pass
        run_id = sanitize_run_id(self.var_run_id.get())
        if not run_id:                       # empty/invalid -> fresh random id
            run_id = generate_run_id()
            self.var_run_id.set(run_id)
        cfg.run_id = run_id
        cfg.infinite_loop = bool(self.var_infinite.get())
        save_config(cfg)

    def start(self) -> None:
        if self.worker.running:
            return
        self._apply_settings()
        try:
            essids = load_essids(self.config.essid_file)
        except (OSError, ValueError) as exc:
            messagebox.showerror("Cannot start", f"ESSID file problem:\n{exc}")
            return
        if not self.var_url.get().strip().startswith(("http://", "https://")):
            messagebox.showerror("Cannot start", "LLM endpoint must be an http(s) URL.")
            return
        self.logger.info("Starting with %d ESSIDs", len(essids))
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.btn_flush.config(state=tk.NORMAL)
        self.worker.start()

    def stop(self) -> None:
        if not self.worker.running:
            return
        if not messagebox.askyesno("Stop", "Stop the perpetual generation loop?"):
            return
        self.logger.info("Stop requested by user")
        self.worker.stop()
        self.btn_stop.config(state=tk.DISABLED)
        self.btn_flush.config(state=tk.DISABLED)

    def _manual_flush(self) -> None:
        self.store.flush()
        self.logger.info("Manual backup flush: %s", self.store.shard_files()[-1])
        self._log("Backup flushed to disk.", tag="ok")

    def _random_run_id(self) -> None:
        """Generate a fresh random database ID (applied on Start)."""
        new_id = generate_run_id()
        self.var_run_id.set(new_id)
        self._log(
            f"New random database ID: {new_id}. Existing IDs are in the dropdown; "
            "picking one continues that database (dedup included).",
            tag="info",
        )

    def _browse_essid(self) -> None:
        path = filedialog.askopenfilename(filetypes=[("Text", "*.txt"), ("All", "*.*")])
        if path:
            self.var_essid.set(path)

    def _browse_output(self) -> None:
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt")])
        if path:
            self.var_output.set(path)

    # -- event pump --------------------------------------------------------------#

    def _poll_events(self) -> None:
        try:
            while True:
                event = self.events.get_nowait()
                self._handle_event(event)
        except queue.Empty:
            pass
        finally:
            self.after(self.config.poll_ms, self._poll_events)

    def _handle_event(self, event: Dict[str, Any]) -> None:
        kind = event["type"]
        if kind == "progress":
            self._counters["current"].set(f"{event['current']}/{event['total']}")
            self._counters["cycle"].set(str(event["cycle"]))
            self.title(f"pwgen - {event['essid']} (cycle {event['cycle']})")
        elif kind == "password":
            self._log(f"[{event['essid']}] {event['password']}", tag="pwd")
            self._counters["uniq"].set(self._counters["uniq"].get())  # noop keep
            self._counters["new"].set(str(int(self._counters["new"].get()) + 1))
        elif kind == "cycle_done":
            self._log(f"Cycle {event['cycle']} complete, next round starts.", tag="info")
        elif kind == "start":
            self._log(
                f"Run {event['run_id']} started - {event['essid_total']} ESSIDs. "
                f"Backup shard: backups/{event['run_id']}.json",
                tag="ok",
            )
        elif kind == "stopped":
            self._counters["current"].set("stopped")
            self._log(
                f"Stopped. New this session: {event['session_new']}. "
                f"Wordlist now has {event['total']} unique entries.",
                tag="ok",
            )
            self._reset_buttons()
        elif kind == "fatal":
            self._log(event["message"], tag="error")
            self._reset_buttons()

    def _reset_buttons(self) -> None:
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.btn_flush.config(state=tk.DISABLED)
        self.title("WiFi Password Seed Generator - hashcat feeder")

    def _log(self, line: str, tag: str = "info") -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_box.configure(state=tk.NORMAL)
        self.log_box.insert("end", f"{ts}  {line}\n", tag)
        # Keep the log bounded so the widget cannot grow forever.
        if int(self.log_box.index("end-1c").split(".")[0]) > 5000:
            self.log_box.delete("1.0", "2000.0")
        self.log_box.configure(state=tk.DISABLED)
        self.log_box.see("end")

    # -- shutdown ----------------------------------------------------------------#

    def _on_close(self) -> None:
        if self.worker.running and not messagebox.askyesno(
            "Quit", "Generation is still running. Stop it and quit?"
        ):
            return
        self.logger.info("Closing application")
        self.worker.stop()
        self.store.flush()
        self.destroy()


def main() -> None:
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
