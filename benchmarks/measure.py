#!/usr/bin/env python3
"""Run one command, time it from spawn to exit and record the peak RSS of its process tree.

    measure.py <result_file> -- <command> [args ...]

Writes a single line to <result_file>:

    <wall_microseconds> <exit_code> <max_rss_kb>

- wall_microseconds: time.perf_counter_ns() taken immediately before Popen and immediately after wait().
- exit_code: the child's exit status; a signal death is reported as 128 + signal (137 for SIGKILL),
  the same convention a shell uses.
- max_rss_kb: ru_maxrss from getrusage(RUSAGE_CHILDREN) after the child has been reaped, which the
  kernel defines as the resident-set high-water mark of the largest process in the reaped tree
  (so for `git clone` it covers the pack-objects / index-pack helpers too). Reported in KiB on every
  platform (macOS returns bytes and is converted).

The child's stdout is discarded; stderr is inherited so the caller can collect it. Standard library only.
"""

from __future__ import annotations

import os
import resource
import subprocess
import sys
import time


def main(argv: list[str]) -> int:
    if len(argv) < 3 or argv[1] != "--":
        print(__doc__, file=sys.stderr)
        return 2
    result_path, cmd = argv[0], argv[2:]
    with open(os.devnull, "wb") as devnull:
        t0 = time.perf_counter_ns()
        try:
            rc = subprocess.Popen(cmd, stdout=devnull).wait()
        except OSError as exc:
            print(f"measure.py: cannot start {cmd[0]}: {exc}", file=sys.stderr)
            rc = 127
        t1 = time.perf_counter_ns()
    if rc < 0:
        rc = 128 - rc
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    max_rss_kb = usage.ru_maxrss // 1024 if sys.platform == "darwin" else usage.ru_maxrss
    with open(result_path, "w", encoding="ascii") as fh:
        fh.write(f"{(t1 - t0) // 1000} {rc} {max_rss_kb}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
