"""Incremental-read scanner state (spec section 5 & 17).

This tracks ONLY "how far into the raw audit log have we read" — it is
distinct from the aggregated ServiceAccount statistics (see aggregator.py
/ output.py). Losing this file is safe-ish (worst case: some re-scan),
but never conflate it with the aggregate data.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass
from pathlib import Path

logger = logging.getLogger("guardian.collector.state")


@dataclass
class ScannerState:
    offset: int = 0
    # inode is used as a secondary rotation signal alongside size shrink,
    # since some rotation strategies replace the file (new inode) without
    # necessarily shrinking it below the old offset.
    inode: int | None = None

    @classmethod
    def load(cls, path: str) -> "ScannerState":
        p = Path(path)
        if not p.exists():
            logger.info("No existing scanner state at %s — starting from offset 0", path)
            return cls()
        try:
            data = json.loads(p.read_text())
            return cls(offset=int(data.get("offset", 0)), inode=data.get("inode"))
        except (json.JSONDecodeError, ValueError, OSError) as exc:
            logger.error("Scanner state at %s was unreadable (%s) — resetting to offset 0", path, exc)
            return cls()

    def save(self, path: str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = p.with_suffix(p.suffix + f".tmp.{os.getpid()}")
        tmp_path.write_text(json.dumps(asdict(self)))
        with open(tmp_path, "r+b") as f:
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, p)  # atomic on POSIX

    def reconcile_with_file(self, file_size: int, file_inode: int) -> bool:
        """Detect rotation/truncation and reset offset to 0 if needed.

        Returns True if a reset happened (useful for logging).
        """
        if self.offset > file_size:
            logger.warning(
                "Stored offset (%d) exceeds current file size (%d) — log was "
                "rotated/truncated; resetting offset to 0",
                self.offset,
                file_size,
            )
            self.offset = 0
            self.inode = file_inode
            return True
        if self.inode is not None and self.inode != file_inode:
            logger.warning(
                "Audit log inode changed (%s -> %s) — log was rotated; resetting offset to 0",
                self.inode,
                file_inode,
            )
            self.offset = 0
            self.inode = file_inode
            return True
        if self.inode is None:
            self.inode = file_inode
        return False
