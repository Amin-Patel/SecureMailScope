"""
Folder watcher for continuous PCAP monitoring.

Polls a directory for newly-appearing capture files and hands each to an
analysis callback, so captures dropped in by a sensor/cron job show up in
the normal results store without a manual upload. This is deliberately a
file watcher, not live packet capture: tshark is only ever run offline
(-r <file>) in this codebase.

Runs in a daemon thread because analysis is blocking subprocess work that
must not stall the async server. A file is only picked up once its size
has been stable across two polls, so half-written captures are skipped.
Processed files are recorded on disk so a restart doesn't re-analyze them.
"""

import json
import threading
import time
from collections import deque
from pathlib import Path
from typing import Callable, Deque, Dict, Optional

WATCHED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
STATE_FILENAME = ".processed.json"


class PcapWatcher:
    def __init__(self, watch_dir: Path, analyze_fn: Callable[[Path], Optional[str]], poll_seconds: float = 5.0):
        """analyze_fn(path) analyzes one capture and returns its capture_id
        (or None on failure). It must not raise for ordinary analysis errors."""
        self.watch_dir = Path(watch_dir)
        self.analyze_fn = analyze_fn
        self.poll_seconds = poll_seconds

        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._pending_sizes: Dict[str, int] = {}
        self._state_path = self.watch_dir / STATE_FILENAME
        self._processed: Dict[str, str] = self._load_state()
        self.recent: Deque[Dict] = deque(maxlen=20)
        self.current_file: Optional[str] = None

    # ─── STATE ───

    def _load_state(self) -> Dict[str, str]:
        try:
            return json.loads(self._state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _save_state(self) -> None:
        try:
            self._state_path.write_text(json.dumps(self._processed), encoding="utf-8")
        except OSError as e:
            print(f"[!] Watcher could not persist state: {e}")

    @staticmethod
    def _fingerprint(path: Path) -> str:
        st = path.stat()
        return f"{path.name}:{st.st_size}:{int(st.st_mtime)}"

    # ─── LIFECYCLE ───

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self.watch_dir.mkdir(parents=True, exist_ok=True)
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="pcap-watcher", daemon=True)
        self._thread.start()
        print(f"[+] PCAP watcher started on {self.watch_dir.resolve()} (poll {self.poll_seconds}s)")

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def status(self) -> Dict:
        return {
            "running": self.running,
            "watch_dir": str(self.watch_dir),
            "poll_seconds": self.poll_seconds,
            "current_file": self.current_file,
            "processed_count": len(self._processed),
            "recent": list(self.recent),
        }

    # ─── POLL LOOP ───

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.scan_once()
            except Exception as e:  # never let one bad poll kill the thread
                print(f"[!] Watcher scan error: {e}")
            self._stop.wait(self.poll_seconds)

    def scan_once(self) -> None:
        """One poll: analyze any capture whose size has been stable for two scans."""
        try:
            entries = [p for p in self.watch_dir.iterdir() if p.is_file() and p.suffix.lower() in WATCHED_EXTENSIONS]
        except OSError:
            return

        seen_now = set()
        for path in sorted(entries):
            key = str(path)
            seen_now.add(key)
            try:
                fingerprint = self._fingerprint(path)
                size = path.stat().st_size
            except OSError:
                continue
            if fingerprint in self._processed.values() or size == 0:
                continue
            if self._pending_sizes.get(key) != size:
                self._pending_sizes[key] = size  # still growing, or first sighting
                continue

            self._process(path, fingerprint)
            self._pending_sizes.pop(key, None)

        for stale in set(self._pending_sizes) - seen_now:
            del self._pending_sizes[stale]

    def _process(self, path: Path, fingerprint: str) -> None:
        self.current_file = path.name
        started = time.time()
        capture_id = None
        error = None
        try:
            capture_id = self.analyze_fn(path)
        except Exception as e:
            error = str(e)
        finally:
            self.current_file = None

        # Record even failures so a broken capture isn't retried every poll.
        self._processed[capture_id or f"failed:{path.name}"] = fingerprint
        self._save_state()
        self.recent.appendleft({
            "filename": path.name,
            "capture_id": capture_id,
            "status": "completed" if capture_id else "failed",
            "error": error,
            "seconds": round(time.time() - started, 1),
            "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        })
        print(f"[{'+' if capture_id else '!'}] Watcher: {path.name} -> {capture_id or 'FAILED'}")
