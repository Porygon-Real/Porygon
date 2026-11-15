"""Read-only, bounded independent log observation for disposable lab measurements."""

import os
from pathlib import Path


class SourceCursor:
    def __init__(self, max_line_bytes=1048576, max_batch_bytes=8388608):
        self.max_line_bytes = max_line_bytes
        self.max_batch_bytes = max_batch_bytes
        self.positions = {}
        self.resets = 0

    def read_lines(self, path, *, tail_if_new=False):
        lines = []
        used = 0
        with Path(path).open("rb") as stream:
            info = os.fstat(stream.fileno())
            key = (info.st_dev, info.st_ino)
            offset = self.positions.get(key, info.st_size if tail_if_new else 0)
            if info.st_size < offset:
                self.resets += 1
                offset = 0
            # Save an initial EOF immediately; a later poll must not reread history.
            self.positions[key] = offset
            stream.seek(offset)
            while len(lines) < 10000 and used < self.max_batch_bytes:
                before = stream.tell()
                line = stream.readline(self.max_line_bytes + 1)
                if not line:
                    break
                if not line.endswith(b"\n") and len(line) <= self.max_line_bytes:
                    stream.seek(before)
                    break
                self.positions[key] = stream.tell()
                lines.append(line)
                used += len(line)
        return lines
