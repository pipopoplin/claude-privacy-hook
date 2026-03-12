#!/usr/bin/env python3
"""
Persistent NLP detection service for Claude Code hooks.

Loads all NLP plugins once at startup and serves detection requests over
a local TCP socket. Auto-starts on first client request and shuts down
after an idle timeout.

Compatible with Linux, macOS, and Windows — uses TCP on 127.0.0.1 with
a lock file for port discovery.

Usage:
    python3 llm_service.py <config.json> [--idle-timeout 1800]

The service writes its PID and port to a lock file so clients can find it.
"""

import hashlib
import importlib
import json
import os
import signal
import socketserver
import struct
import sys
import tempfile
import threading
import time

# Add hooks dir to path for imports
_hooks_dir = os.path.dirname(os.path.abspath(__file__))
if _hooks_dir not in sys.path:
    sys.path.insert(0, _hooks_dir)

from hook_utils import normalize_unicode, resolve_field


# --- Lock file management ---

def get_lock_path(config_path: str) -> str:
    """Return a deterministic lock file path for this config.

    Uses a hash of the absolute config path so multiple projects can
    each have their own service instance.
    """
    config_hash = hashlib.sha256(
        os.path.abspath(config_path).encode()
    ).hexdigest()[:12]
    uid = os.getuid() if hasattr(os, "getuid") else os.getpid()
    return os.path.join(
        tempfile.gettempdir(),
        f"claude-llm-service-{uid}-{config_hash}.json",
    )


def write_lock(lock_path: str, pid: int, port: int) -> None:
    """Atomically write the lock file with PID and port."""
    tmp = lock_path + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"pid": pid, "port": port}, f)
    os.replace(tmp, lock_path)  # atomic on all platforms


def read_lock(lock_path: str) -> dict | None:
    """Read lock file. Returns {"pid": ..., "port": ...} or None."""
    try:
        with open(lock_path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def remove_lock(lock_path: str) -> None:
    try:
        os.remove(lock_path)
    except OSError:
        pass


# --- Plugin loading ---

def load_plugin_registry(hooks_dir: str) -> dict:
    """Load plugin registry from plugins/plugins.json."""
    registry_path = os.path.join(hooks_dir, "plugins", "plugins.json")
    if not os.path.isfile(registry_path):
        return {}
    with open(registry_path) as f:
        data = json.load(f)
    return {
        name: (info["module"], info["class"])
        for name, info in data.get("plugins", {}).items()
    }


def load_plugin(name: str, plugin_config: dict, registry: dict):
    """Load and configure a plugin. Returns instance or None."""
    if name not in registry:
        return None
    module_path, class_name = registry[name]
    try:
        module = importlib.import_module(module_path)
        cls = getattr(module, class_name)
        instance = cls()
        instance.configure(plugin_config.get(name, {}))
        if not instance.is_available():
            return None
        return instance
    except Exception:
        return None


def load_all_plugins(config: dict, registry: dict) -> dict:
    """Eagerly load all enabled plugins. Returns {name: instance}."""
    plugins = {}
    plugin_configs = config.get("plugins", {})
    priority = config.get("plugin_priority", ["presidio", "spacy", "distilbert"])
    supplementary = config.get(
        "supplementary_plugins",
        ["prompt_injection", "sensitive_categories", "entropy_detector", "semantic_intent"],
    )

    for name in list(priority) + list(supplementary):
        if not plugin_configs.get(name, {}).get("enabled", True):
            continue
        instance = load_plugin(name, plugin_configs, registry)
        if instance is not None:
            plugins[name] = instance

    return plugins


# --- Core detection ---

def run_detection(
    hook_input: dict,
    config: dict,
    hooks_dir: str,
    plugins: dict,
) -> dict | None:
    """Run NLP detection with pre-loaded plugins.

    Returns the hook output dict, or None if nothing detected.
    """
    if not config.get("enabled", True):
        return None

    field = config.get("field", "tool_input.command")
    text = resolve_field(hook_input, field)
    if not text:
        return None
    text = normalize_unicode(text)

    priority = config.get("plugin_priority", ["presidio", "spacy", "distilbert"])
    supplementary = config.get(
        "supplementary_plugins",
        ["prompt_injection", "sensitive_categories", "entropy_detector", "semantic_intent"],
    )
    min_confidence = config.get("min_confidence", 0.7)
    action = config.get("action", "deny")
    entity_types = list(config.get("entity_types") or [])

    # Load overrides (pro feature — skipped when pro is not available)
    nlp_ovr: dict = {}
    overrides: list = []
    try:
        from tier_check import is_pro_available
        if is_pro_available():
            from override_resolver import load_overrides, merge_nlp_overrides
            overrides = load_overrides(hooks_dir)
            nlp_ovr = merge_nlp_overrides(overrides)
    except ImportError:
        pass

    # Apply NLP overrides: filter disabled entity types
    if nlp_ovr.get("disabled_entity_types"):
        entity_types = [
            e for e in entity_types
            if e not in nlp_ovr["disabled_entity_types"]
        ]

    confidence_overrides = nlp_ovr.get("confidence_overrides", {})

    all_findings = []
    reporting_plugin = None

    # First available PII plugin
    for plugin_name in priority:
        if plugin_name in supplementary:
            continue
        if plugin_name not in plugins:
            continue

        plugin = plugins[plugin_name]
        try:
            detections = plugin.detect(text, entity_types if entity_types else None)
        except Exception:
            continue

        for d in detections:
            threshold = confidence_overrides.get(d.entity_type, min_confidence)
            if d.score >= threshold:
                all_findings.append(d)

        if all_findings:
            reporting_plugin = plugin
        break

    # Supplementary plugins
    for plugin_name in supplementary:
        if plugin_name not in plugins:
            continue

        plugin = plugins[plugin_name]
        try:
            detections = plugin.detect(text, entity_types if entity_types else None)
        except Exception:
            continue

        findings = [d for d in detections if d.score >= min_confidence]
        if findings:
            all_findings.extend(findings)
            if reporting_plugin is None:
                reporting_plugin = plugin

    # Check pattern overrides (pro feature)
    if overrides and all_findings:
        try:
            from tier_check import is_pro_available
            if not is_pro_available():
                raise ImportError("pro not available")
            from override_resolver import check_override
            dummy_rule = {"name": "llm_filter", "overridable": True}
            filtered = []
            overridden = []
            for finding in all_findings:
                override = check_override(overrides, dummy_rule, finding.text)
                if override:
                    overridden.append((finding, override))
                else:
                    filtered.append(finding)

            if overridden:
                try:
                    from audit_logger import log_event
                    command = resolve_field(hook_input, "tool_input.command")
                    for finding, override in overridden:
                        log_event(
                            log_dir=hooks_dir,
                            filter_name="llm_filter",
                            rule_name=override.get("override_name", "unknown"),
                            action="override_allow",
                            matched=[f"{finding.entity_type}: {finding.text}"],
                            command=command,
                            session_id=hook_input.get("session_id", ""),
                            override_name=override.get("override_name", ""),
                            override_source=override.get("source", ""),
                        )
                except Exception:
                    pass

            all_findings = filtered
        except Exception:
            pass

    if not all_findings:
        return None

    # Audit log
    try:
        from audit_logger import log_event
        command = resolve_field(hook_input, "tool_input.command")
        log_event(
            log_dir=hooks_dir,
            filter_name="llm_filter",
            rule_name=reporting_plugin.name if reporting_plugin else "unknown",
            action=action,
            matched=[f"{d.entity_type}: {d.text}" for d in all_findings],
            command=command,
            session_id=hook_input.get("session_id", ""),
        )
    except Exception:
        pass

    findings_text = "\n".join(
        f"  - {d.entity_type}: '{d.text}' (confidence: {d.score:.2f})"
        for d in all_findings
    )

    hook_event = hook_input.get("hook_event_name", "PreToolUse")
    if hook_event == "PreToolUse":
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny" if action == "deny" else "ask",
                "permissionDecisionReason": (
                    f"Sensitive content detected by {reporting_plugin.name} ({reporting_plugin.tier}):\n"
                    f"{findings_text}"
                ),
            }
        }
    else:
        return {
            "decision": "block" if action == "deny" else action,
            "reason": f"Sensitive content detected by {reporting_plugin.name}:\n{findings_text}",
        }


# --- TCP Server ---

class DetectionHandler(socketserver.StreamRequestHandler):
    """Handle a single detection request.

    Protocol (length-prefixed JSON):
    - Client sends: 4-byte big-endian length + JSON bytes
    - Server responds: 4-byte big-endian length + JSON bytes
    """

    def handle(self):
        try:
            # Read length prefix
            header = self._read_exact(4)
            if not header:
                return
            length = struct.unpack(">I", header)[0]
            if length > 10 * 1024 * 1024:  # 10 MB sanity limit
                return

            data = self._read_exact(length)
            if not data:
                return

            request = json.loads(data)
            hook_input = request.get("hook_input", {})

            # Reset idle timer
            self.server.reset_idle_timer()

            # Hot-reload config if changed
            self.server.maybe_reload_config()

            # Run detection
            result = run_detection(
                hook_input,
                self.server.config,
                self.server.hooks_dir,
                self.server.plugins,
            )

            response = {
                "exit_code": 0,
                "stdout": json.dumps(result) if result else "",
                "stderr": "",
            }
        except Exception as e:
            response = {
                "exit_code": 1,
                "stdout": "",
                "stderr": str(e),
            }

        resp_bytes = json.dumps(response).encode("utf-8")
        self.wfile.write(struct.pack(">I", len(resp_bytes)))
        self.wfile.write(resp_bytes)
        self.wfile.flush()

    def _read_exact(self, n: int) -> bytes | None:
        """Read exactly n bytes from the socket."""
        buf = bytearray()
        while len(buf) < n:
            chunk = self.rfile.read(n - len(buf))
            if not chunk:
                return None
            buf.extend(chunk)
        return bytes(buf)


class DetectionServer(socketserver.ThreadingTCPServer):
    """Persistent TCP server for NLP detection requests."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, config_path: str, idle_timeout: int = 1800):
        self.hooks_dir = os.path.dirname(os.path.abspath(config_path))
        self.config_path = os.path.abspath(config_path)
        self.idle_timeout = idle_timeout
        self.lock_path = get_lock_path(self.config_path)

        # Load config
        self.config = self._load_config()
        self._config_mtime = os.path.getmtime(self.config_path)

        # Load all plugins eagerly
        registry = load_plugin_registry(self.hooks_dir)
        self.plugins = load_all_plugins(self.config, registry)
        self._registry = registry

        # Bind to random port on localhost
        super().__init__(("127.0.0.1", 0), DetectionHandler)
        self._port = self.server_address[1]

        # Idle timer
        self._idle_lock = threading.Lock()
        self._idle_timer: threading.Timer | None = None
        self._start_idle_timer()

        # License heartbeat (pro feature — no-op when pro unavailable)
        self._running = True
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop, daemon=True
        )
        self._heartbeat_thread.start()

        # Write lock file
        write_lock(self.lock_path, os.getpid(), self._port)

        plugin_names = list(self.plugins.keys()) or ["none"]
        print(
            f"LLM service started on 127.0.0.1:{self._port} "
            f"(plugins: {', '.join(plugin_names)}, "
            f"idle timeout: {self.idle_timeout}s)",
            file=sys.stderr,
        )

    def _load_config(self) -> dict:
        with open(self.config_path) as f:
            return json.load(f)

    def maybe_reload_config(self) -> None:
        """Reload config if the file has been modified."""
        try:
            mtime = os.path.getmtime(self.config_path)
            if mtime != self._config_mtime:
                self.config = self._load_config()
                self._config_mtime = mtime
                # Reload plugins in case config changed plugin settings
                self.plugins = load_all_plugins(self.config, self._registry)
        except OSError:
            pass

    def _start_idle_timer(self) -> None:
        with self._idle_lock:
            if self._idle_timer is not None:
                self._idle_timer.cancel()
            self._idle_timer = threading.Timer(
                self.idle_timeout, self._idle_shutdown
            )
            self._idle_timer.daemon = True
            self._idle_timer.start()

    def reset_idle_timer(self) -> None:
        self._start_idle_timer()

    def _heartbeat_loop(self) -> None:
        """Periodically renew license token (pro feature).

        Runs every 10 minutes. No-op when pro is not available.
        """
        while self._running:
            try:
                from tier_check import is_pro_available

                if is_pro_available():
                    try:
                        from license.heartbeat import renew_token

                        renew_token()
                    except ImportError:
                        pass  # No license module — transition mode
                    except Exception:
                        pass
            except ImportError:
                pass
            # Sleep in small increments so shutdown is responsive
            for _ in range(120):  # 120 * 5s = 600s = 10 min
                if not self._running:
                    break
                time.sleep(5)

    def _idle_shutdown(self) -> None:
        print("LLM service shutting down (idle timeout)", file=sys.stderr)
        remove_lock(self.lock_path)
        # Shut down in a separate thread to avoid deadlock
        threading.Thread(target=self.shutdown, daemon=True).start()

    def server_close(self):
        self._running = False
        super().server_close()
        remove_lock(self.lock_path)
        with self._idle_lock:
            if self._idle_timer is not None:
                self._idle_timer.cancel()


def main():
    if len(sys.argv) < 2:
        print("Usage: llm_service.py <config.json> [--idle-timeout 1800]", file=sys.stderr)
        sys.exit(1)

    config_path = os.path.expandvars(sys.argv[1])
    if not os.path.isfile(config_path):
        print(f"Config not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    idle_timeout = 1800  # 30 minutes default
    if "--idle-timeout" in sys.argv:
        idx = sys.argv.index("--idle-timeout")
        if idx + 1 < len(sys.argv):
            idle_timeout = int(sys.argv[idx + 1])

    server = DetectionServer(config_path, idle_timeout)

    # Handle SIGTERM/SIGINT gracefully
    _shutdown_requested = threading.Event()

    def signal_handler(sig, frame):
        print("LLM service shutting down (signal)", file=sys.stderr)
        _shutdown_requested.set()

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    # Use a short poll interval so signals are processed promptly
    server_thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.5}
    )
    server_thread.daemon = True
    server_thread.start()

    try:
        # Wait with short timeouts so signal handlers can run
        while not _shutdown_requested.is_set():
            _shutdown_requested.wait(timeout=0.5)
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
