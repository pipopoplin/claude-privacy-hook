"""Tier check for free vs pro feature gating.

Determines whether pro features (overrides, managed rules, etc.) are available.
Checks two conditions:
1. Pro modules exist (override_resolver importable)
2. License is valid (status file or transition mode)

Free hooks call is_pro_available() before attempting pro imports.
This module is a convenience hint — pro modules self-enforce independently.
"""

import hashlib
import json
import os
import sys

_pro_modules_available: bool | None = None

# Server public key for manifest signature verification.
# Same key embedded in pro code. Set at build time.
_SERVER_PUBLIC_KEY_HEX = "50eba91eb60d5560b55bd6322b4187fdb049d7119e052c40c889ae08335557dd"


def _setup_pro_path() -> None:
    """Add pro/hooks/ and pro/ to sys.path for monorepo development."""
    hooks_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(os.path.dirname(hooks_dir))
    # Add pro/hooks/ for override_resolver, override_cli
    pro_hooks = os.path.join(project_root, "pro", "hooks")
    if os.path.isdir(pro_hooks) and pro_hooks not in sys.path:
        sys.path.insert(0, pro_hooks)
    # Add pro/ for license package
    pro_dir = os.path.join(project_root, "pro")
    if os.path.isdir(pro_dir) and pro_dir not in sys.path:
        sys.path.insert(0, pro_dir)


def _check_pro_modules() -> bool:
    """Check if pro modules are importable."""
    global _pro_modules_available
    if _pro_modules_available is None:
        _setup_pro_path()
        try:
            import override_resolver  # noqa: F401

            _pro_modules_available = True
        except ImportError:
            _pro_modules_available = False
    return _pro_modules_available


def _get_status_path() -> str:
    """Return the license status file path."""
    uid = os.getuid() if hasattr(os, "getuid") else os.getpid()
    return os.path.join(
        os.environ.get("TMPDIR", "/tmp"),
        f"claude-hook-license-{uid}.json",
    )


def _is_license_valid() -> bool:
    """Read the license status file. No network call, no crypto."""
    try:
        with open(_get_status_path()) as f:
            status = json.load(f)
        return status.get("status") == "valid"
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return False


def is_pro_available() -> bool:
    """Check if pro features should be enabled.

    Returns True when:
    - Pro modules are importable AND
    - Either: license is valid, OR no license module exists (transition mode)

    Transition mode allows pro features during development before
    the license server is built. Once the license module exists,
    a valid license token is required.
    """
    if not _check_pro_modules():
        return False
    # Check if our pro license package exists (not stdlib license)
    try:
        from license.token import verify_token  # noqa: F401
        from license.config import get_token_path

        # If no token file exists, we're in transition/development mode
        if not os.path.isfile(get_token_path()):
            return True
        # Token file exists — check the status file
        return _is_license_valid()
    except ImportError:
        # Transition mode: no license module yet, allow pro based on module presence
        return True


def verify_pro_manifest(hooks_dir: str | None = None) -> bool:
    """Verify that installed pro modules haven't been tampered with.

    Checks pro_manifest.json:
    1. Manifest exists and has a valid signature
    2. Every listed file hash matches the actual file on disk

    Returns True if manifest is valid or doesn't exist (transition mode).
    Returns False if manifest exists but is tampered with.
    """
    if hooks_dir is None:
        hooks_dir = os.path.dirname(os.path.abspath(__file__))

    manifest_path = os.path.join(hooks_dir, "pro_manifest.json")

    # No manifest = transition/development mode → allow
    if not os.path.isfile(manifest_path):
        return True

    try:
        with open(manifest_path) as f:
            manifest = json.load(f)
    except (json.JSONDecodeError, OSError):
        return False

    files = manifest.get("files", {})
    signature = manifest.get("signature", "")

    if not files or not signature:
        return False

    # Verify manifest signature
    files_json = json.dumps(files, sort_keys=True).encode()
    try:
        # Try Ed25519 verification first (production)
        from nacl.signing import VerifyKey

        vk = VerifyKey(bytes.fromhex(_SERVER_PUBLIC_KEY_HEX))
        sig_bytes = bytes.fromhex(signature)
        vk.verify(files_json, sig_bytes)
    except ImportError:
        # Fall back to HMAC-SHA256 (development)
        import hmac as _hmac

        key = bytes.fromhex(_SERVER_PUBLIC_KEY_HEX)
        expected = _hmac.new(key, files_json, hashlib.sha256).hexdigest()
        if not _hmac.compare_digest(signature, expected):
            return False
    except Exception:
        return False

    # Verify individual file hashes
    for filename, expected_hash in files.items():
        filepath = os.path.join(hooks_dir, filename)
        try:
            with open(filepath, "rb") as f:
                actual = "sha256:" + hashlib.sha256(f.read()).hexdigest()
            if actual != expected_hash:
                return False
        except FileNotFoundError:
            return False

    return True


def reset_cache() -> None:
    """Reset the pro module availability cache. Used by tests."""
    global _pro_modules_available
    _pro_modules_available = None
