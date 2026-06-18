from __future__ import annotations

import asyncio
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Tuple


async def scan_host_key(address: str, port: int) -> Tuple[str, str]:
    scan = await asyncio.create_subprocess_exec(
        "ssh-keyscan",
        "-p",
        str(port),
        "-T",
        "10",
        address,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await scan.communicate()
    if scan.returncode != 0 or not stdout.strip():
        raise RuntimeError(
            "Unable to read SSH host key: %s"
            % stderr.decode(errors="replace").strip()
        )
    first_line = next(
        line for line in stdout.decode(errors="replace").splitlines() if line.strip()
    )
    fingerprint_process = await asyncio.create_subprocess_exec(
        "ssh-keygen",
        "-lf",
        "-",
        "-E",
        "sha256",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    fingerprint_stdout, fingerprint_stderr = await fingerprint_process.communicate(
        (first_line + "\n").encode("utf-8")
    )
    if fingerprint_process.returncode != 0:
        raise RuntimeError(
            "Unable to calculate SSH host fingerprint: %s"
            % fingerprint_stderr.decode(errors="replace").strip()
        )
    parts = fingerprint_stdout.decode(errors="replace").split()
    if len(parts) < 2:
        raise RuntimeError("SSH host fingerprint output is malformed")
    return first_line, parts[1]


@contextmanager
def temporary_known_hosts(line: str) -> Iterator[Path]:
    descriptor, raw_path = tempfile.mkstemp(prefix="ai-sysadm-known-hosts-")
    path = Path(raw_path)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(line)
            handle.write("\n")
        yield path
    finally:
        path.unlink(missing_ok=True)
