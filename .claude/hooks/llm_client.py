#!/usr/bin/env python3
"""
Thin client for the persistent NLP detection service.

Replaces direct llm_filter.py invocation in Claude Code hooks.
On first call, auto-starts the background service. Subsequent calls
reuse the running service for fast plugin-less detection (~1-5ms
instead of 100-500ms cold start).

Falls back to direct llm_filter.py invocation if the service is
unavailable after startup attempt.

Compatible with Linux, macOS, and Windows.

Usage (same interface as llm_filter.py — drop-in replacement):
    echo '<hook_input_json>' | python3 llm_client.py <config.json>
"""

import json
import os
import socket
import struct
import subprocess
import sys
import time


def get_lock_path(config_path: str) -> str:
    """Return the lock file path for this config (must match llm_service.py)."""
    import hashlib
    import tempfile

    config_hash = hashlib.sha256(
        os.path.abspath(config_path).encode()
    ).hexdigest()[:12]
    uid = os.getuid() if hasattr(os, "getuid") else os.getpid()
    return os.path.join(
        tempfile.gettempdir(),
        f"claude-llm-service-{uid}-{config_hash}.json",
    )


def read_lock(lock_path: str) -> dict | None:
    """Read lock file. Returns {"pid": ..., "port": ...} or None."""
    try:
        with open(lock_path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def is_process_alive(pid: int) -> bool:
    """Check if a process is running (cross-platform)."""
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def send_request(port: int, hook_input: dict, timeout: float = 5.0) -> dict | None:
    """Send a detection request to the service. Returns response or None."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(("127.0.0.1", port))

        request = json.dumps({"hook_input": hook_input}).encode("utf-8")
        sock.sendall(struct.pack(">I", len(request)))
        sock.sendall(request)

        # Read response length
        header = _recv_exact(sock, 4)
        if not header:
            return None
        length = struct.unpack(">I", header)[0]
        if length > 10 * 1024 * 1024:
            return None

        data = _recv_exact(sock, length)
        if not data:
            return None

        return json.loads(data)
    except (socket.error, json.JSONDecodeError, OSError):
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    """Receive exactly n bytes."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def start_service(config_path: str, hooks_dir: str) -> dict | None:
    """Start the service in the background. Returns lock info or None."""
    service_script = os.path.join(hooks_dir, "llm_service.py")
    if not os.path.isfile(service_script):
        return None

    # Start as detached background process
    kwargs = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "start_new_session": True,
    }
    # On Windows, use CREATE_NEW_PROCESS_GROUP
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

    try:
        subprocess.Popen(
            [sys.executable, service_script, config_path],
            **kwargs,
        )
    except OSError:
        return None

    # Wait for service to be ready (check lock file)
    lock_path = get_lock_path(config_path)
    for _ in range(20):  # up to 2 seconds
        time.sleep(0.1)
        info = read_lock(lock_path)
        if info and is_process_alive(info["pid"]):
            return info

    return None


def fallback_direct(config_path: str, hook_input_raw: str) -> None:
    """Fall back to direct llm_filter.py invocation."""
    hooks_dir = os.path.dirname(os.path.abspath(config_path))
    filter_script = os.path.join(hooks_dir, "llm_filter.py")

    result = subprocess.run(
        [sys.executable, filter_script, config_path],
        input=hook_input_raw,
        capture_output=True,
        text=True,
    )

    if result.stdout:
        sys.stdout.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)
    sys.exit(result.returncode)


def main():
    if len(sys.argv) < 2:
        print("Usage: llm_client.py <config.json>", file=sys.stderr)
        sys.exit(1)

    config_path = os.path.expandvars(sys.argv[1])
    if not os.path.isfile(config_path):
        print(f"Config not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    hooks_dir = os.path.dirname(os.path.abspath(config_path))

    # Read stdin first (one-shot)
    hook_input_raw = sys.stdin.read()
    if not hook_input_raw.strip():
        sys.exit(0)

    try:
        hook_input = json.loads(hook_input_raw)
    except json.JSONDecodeError:
        sys.exit(0)

    lock_path = get_lock_path(config_path)

    # Try to connect to existing service
    info = read_lock(lock_path)
    if info and is_process_alive(info["pid"]):
        response = send_request(info["port"], hook_input, timeout=5.0)
        if response is not None:
            _handle_response(response)
            return

    # Service not running or stale — start it
    info = start_service(config_path, hooks_dir)
    if info:
        response = send_request(info["port"], hook_input, timeout=10.0)
        if response is not None:
            _handle_response(response)
            return

    # Service failed — fall back to direct invocation
    fallback_direct(config_path, hook_input_raw)


def _handle_response(response: dict) -> None:
    """Process a service response and exit."""
    stdout = response.get("stdout", "")
    stderr = response.get("stderr", "")
    exit_code = response.get("exit_code", 0)

    if stdout:
        sys.stdout.write(stdout)
    if stderr:
        sys.stderr.write(stderr)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
