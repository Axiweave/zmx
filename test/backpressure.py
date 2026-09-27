#!/usr/bin/env python3
"""Check byte conservation and FIFO order through the real zmx CLI."""

import argparse
import contextlib
import hashlib
import os
from pathlib import Path
import random
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time
import tty


SEED = 0x5A4D5808
WATERMARK = 256 * 1024
TIMEOUT = 10
# A NUL ends each transfer. Printable payload bytes cannot contain this marker.
ALPHABET = bytes(33 + value % 94 for value in range(256))


def reader(directory):
    """Hold the raw PTY until the driver releases it through a private socket."""
    tty.setraw(0)
    with socket.socket(socket.AF_UNIX) as control:
        control.connect(str(directory / "control"))
        control.settimeout(TIMEOUT * 3)
        with control.makefile("rwb", buffering=0) as channel:
            channel.write(f"ready {os.getpid()}\n".encode())
            if channel.readline() != b"release\n":
                raise AssertionError("The reader did not receive the release command.")
            received = bytearray()
            deadline = time.monotonic() + TIMEOUT
            while b"\0" not in received[-65536:]:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([0], [], [], remaining)[0]:
                    break
                chunk = os.read(0, 65536)
                if not chunk:
                    break
                received.extend(chunk)
            (directory / "received").write_bytes(received)
            channel.write(b"received\n")
            channel.readline()  # Keep the session alive until the driver checks it.


def cli(zmx, env, *args):
    result = subprocess.run(
        [str(zmx), *args], stdin=subprocess.DEVNULL, capture_output=True,
        env=env, timeout=TIMEOUT,
    )
    if result.returncode:
        raise AssertionError(
            f"zmx {' '.join(args)} exited {result.returncode}: "
            f"{result.stderr.decode(errors='replace')}"
        )
    return result.stdout


def check_case(zmx, env, directory, mode, size):
    payload = random.Random(SEED ^ size).randbytes(size).translate(ALPHABET)
    expected = payload + b"\0"
    (directory / "input").write_bytes(expected)
    name = f"bp-{mode}-{size}"
    print(f"case={mode} bytes={size} sha256={hashlib.sha256(payload).hexdigest()}", flush=True)
    processes = []
    reader_pid = None
    channel = None
    with contextlib.ExitStack() as stack:
        listener = stack.enter_context(socket.socket(socket.AF_UNIX))
        listener.bind(str(directory / "control"))
        listener.listen(1)
        listener.settimeout(TIMEOUT)
        errors = stack.enter_context((directory / "stderr").open("w+b"))
        try:
            keeper = subprocess.Popen(
                [str(zmx), "attach", "--labels", f"backpressure={SEED}", name,
                 sys.executable, str(Path(__file__).resolve()), "--reader", str(directory)],
                stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=errors, env=env,
            )
            processes.append(keeper)
            control, _ = listener.accept()
            stack.enter_context(control)
            control.settimeout(TIMEOUT + 2)
            channel = stack.enter_context(control.makefile("rwb", buffering=0))
            ready = channel.readline().split()
            if len(ready) != 2 or ready[0] != b"ready":
                raise AssertionError(f"The reader did not become ready: {ready!r}")
            reader_pid = int(ready[1])

            # The empty case closes a genuinely empty attached stdin first.
            with (directory / "input").open("rb") as source:
                if size == 0:
                    source.seek(0, os.SEEK_END)
                sender = subprocess.Popen(
                    [str(zmx), mode, name], stdin=source,
                    stdout=subprocess.DEVNULL, stderr=errors, env=env,
                )
            processes.append(sender)
            if mode == "send" or size < WATERMARK:
                # Send closes its socket with a complete message still pending.
                if sender.wait(timeout=TIMEOUT) != 0:
                    raise AssertionError("The EOF sender failed.")
                if size == 0:
                    subprocess.run(
                        [str(zmx), "send", name], input=b"\0", check=True,
                        stdout=subprocess.DEVNULL, stderr=errors, env=env, timeout=TIMEOUT,
                    )
            else:
                # The reader stays stopped while the attached sender meets pressure.
                # A timeout is not a pass signal. The byte comparison below is required.
                try:
                    sender.wait(timeout=0.25)
                except subprocess.TimeoutExpired:
                    pass

            labels = cli(zmx, env, "get", name)
            if f"backpressure={SEED}".encode() not in labels.splitlines():
                raise AssertionError("The control request failed while the reader waited.")
            channel.write(b"release\n")
            if sender.wait(timeout=TIMEOUT) != 0:
                raise AssertionError("The EOF sender failed after the reader resumed.")
            if channel.readline() != b"received\n":
                raise AssertionError("The reader did not report its received bytes.")
            received = (directory / "received").read_bytes()
            if received != expected:
                common = min(len(received), len(expected))
                mismatch = next(
                    (i for i in range(common) if received[i] != expected[i]), common,
                )
                raise AssertionError(
                    f"Byte conservation or FIFO failed: mode={mode}, seed={SEED:#x}, "
                    f"expected={len(expected)}, received={len(received)}, "
                    f"first_difference={mismatch}, "
                    f"received_sha256={hashlib.sha256(received).hexdigest()}"
                )
            print(f"PASS {mode} bytes={size} control=responsive EOF=preserved", flush=True)
        finally:
            if channel is not None:
                with contextlib.suppress(OSError):
                    channel.write(b"stop\n")
            # Every command and PID belongs to this case's private session.
            try:
                subprocess.run(
                    [str(zmx), "kill", name, "--force"], stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=errors, env=env, timeout=TIMEOUT,
                )
            except subprocess.TimeoutExpired:
                if reader_pid is not None:
                    with contextlib.suppress(ProcessLookupError):
                        os.kill(reader_pid, signal.SIGKILL)
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=TIMEOUT)
                if process.stdin is not None:
                    process.stdin.close()
            errors.seek(0)
            diagnostics = errors.read().decode(errors="replace").strip()
            if diagnostics:
                print(diagnostics, file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("zmx", nargs="?", type=Path)
    parser.add_argument("--zmx-dir", type=Path, help="An empty, test-owned ZMX_DIR.")
    parser.add_argument("--reader", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.reader is not None:
        reader(args.reader)
        return
    if args.zmx is None:
        parser.error("Provide the path to the prebuilt zmx binary.")
    zmx = args.zmx.resolve()
    if not os.access(zmx, os.X_OK):
        parser.error("The zmx binary does not exist or cannot execute.")
    # Short paths also fit Darwin's Unix socket path limit.
    with tempfile.TemporaryDirectory(prefix="zmx-bp-", dir="/tmp") as temporary:
        root = Path(temporary)
        socket_dir = args.zmx_dir.resolve() if args.zmx_dir else root / "sockets"
        socket_dir.mkdir(parents=True, exist_ok=True)
        if any(socket_dir.iterdir()):
            parser.error("The test requires an empty, test-owned ZMX_DIR.")
        env = {key: value for key, value in os.environ.items() if not key.startswith("ZMX_")}
        env.update(ZMX_DIR=str(socket_dir), ZMX_TRACK_ENV="", TERM="xterm-256color")
        print(f"seed={SEED:#x} watermark={WATERMARK}", flush=True)
        # A complete Send message exceeds the old cap by itself. Stock 0.8.1
        # drops it even with an empty queue, so the red case needs no race.
        cases = [("send", WATERMARK), ("send", 5 * 1024 * 1024 + 17)]
        cases += [("attach", size) for size in (0, 1, WATERMARK - 1, WATERMARK + 1, 5 * 1024 * 1024 + 17)]
        cases += [("send", size) for size in (1, WATERMARK - 1)]
        for index, (mode, size) in enumerate(cases):
            directory = root / str(index)
            directory.mkdir()
            check_case(zmx, env, directory, mode, size)


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
