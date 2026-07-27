"""Secure local configuration for PineAI."""

import base64
import json
import os
import secrets
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional


DEFAULT_CONFIG_DIR = Path("/root/.PineAI")
DEFAULTS = {
    "schema_version": 1,
    "model": "gpt-5.6-terra",
    "language": "en",
    "share_ssids": False,
    "max_ai_targets": 50,
}
SUPPORTED_LANGUAGES = {"en", "fi"}


class ConfigError(ValueError):
    """Raised when PineAI configuration is invalid."""


def resolve_config_dir(config_dir: Optional[str] = None) -> Path:
    """Resolve the configuration directory without exposing its contents."""
    if config_dir:
        return Path(config_dir)
    override = os.environ.get("PINEAI_CONFIG_DIR")
    return Path(override) if override else DEFAULT_CONFIG_DIR


def _ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(str(path), 0o700)
    except OSError:
        # Windows does not implement POSIX permission bits. Mark VII does.
        pass


def _atomic_private_write(path: Path, data: bytes) -> None:
    _ensure_private_directory(path.parent)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".{0}.".format(path.name), dir=str(path.parent)
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temporary_name, 0o600)
        except OSError:
            pass
        os.replace(temporary_name, str(path))
        try:
            os.chmod(str(path), 0o600)
        except OSError:
            pass
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def write_private_file(path: Path, data: bytes) -> None:
    """Atomically write a private file using Mark VII-safe permissions."""
    _atomic_private_write(path, data)


def _validate_settings(settings: Dict[str, Any]) -> Dict[str, Any]:
    result = dict(DEFAULTS)
    result.update(settings)

    if result.get("schema_version") != 1:
        raise ConfigError("Unsupported configuration schema version")
    if not isinstance(result.get("model"), str) or not result["model"].strip():
        raise ConfigError("model must be a non-empty string")
    if result.get("language") not in SUPPORTED_LANGUAGES:
        raise ConfigError("language must be 'en' or 'fi'")
    if not isinstance(result.get("share_ssids"), bool):
        raise ConfigError("share_ssids must be a boolean")
    max_targets = result.get("max_ai_targets")
    if not isinstance(max_targets, int) or isinstance(max_targets, bool):
        raise ConfigError("max_ai_targets must be an integer")
    if max_targets < 1 or max_targets > 50:
        raise ConfigError("max_ai_targets must be between 1 and 50")
    return result


def load_settings(config_dir: Optional[str] = None) -> Dict[str, Any]:
    """Load non-secret settings, applying safe defaults."""
    directory = resolve_config_dir(config_dir)
    path = directory / "config.json"
    if not path.exists():
        return dict(DEFAULTS)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ConfigError("Could not read PineAI configuration: {0}".format(error))
    if not isinstance(raw, dict):
        raise ConfigError("PineAI configuration must be a JSON object")
    return _validate_settings(raw)


def save_settings(settings: Dict[str, Any], config_dir: Optional[str] = None) -> None:
    """Validate and atomically store non-secret settings."""
    validated = _validate_settings(settings)
    payload = json.dumps(validated, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    _atomic_private_write(resolve_config_dir(config_dir) / "config.json", payload)


def save_api_key(api_key: str, config_dir: Optional[str] = None) -> None:
    """Store an OpenAI API key without logging or returning it."""
    if not isinstance(api_key, str) or not api_key.strip():
        raise ConfigError("OpenAI API key must not be empty")
    if "\n" in api_key or "\r" in api_key:
        raise ConfigError("OpenAI API key must be a single line")
    _atomic_private_write(
        resolve_config_dir(config_dir) / "openai.key",
        api_key.strip().encode("utf-8") + b"\n",
    )


def load_api_key(config_dir: Optional[str] = None) -> Optional[str]:
    """Load the API key from an environment override or the private key file."""
    environment_key = os.environ.get("OPENAI_API_KEY")
    if environment_key and environment_key.strip():
        return environment_key.strip()
    path = resolve_config_dir(config_dir) / "openai.key"
    if not path.exists():
        return None
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError as error:
        raise ConfigError("Could not read OpenAI API key: {0}".format(error))
    return value or None


def ensure_pseudonymization_key(config_dir: Optional[str] = None) -> bytes:
    """Return a persistent 256-bit HMAC key, generating it on first use."""
    path = resolve_config_dir(config_dir) / "pseudonymization.key"
    if path.exists():
        try:
            raw = base64.b64decode(path.read_bytes().strip(), validate=True)
        except (OSError, ValueError) as error:
            raise ConfigError(
                "Could not read pseudonymization key: {0}".format(error)
            )
        if len(raw) != 32:
            raise ConfigError("Pseudonymization key must contain 32 bytes")
        return raw

    raw = secrets.token_bytes(32)
    _atomic_private_write(path, base64.b64encode(raw) + b"\n")
    return raw


def public_status(config_dir: Optional[str] = None) -> Dict[str, Any]:
    """Return settings that are safe to expose to the local module UI."""
    settings = load_settings(config_dir)
    return {
        "configured": load_api_key(config_dir) is not None,
        "model": settings["model"],
        "language": settings["language"],
        "share_ssids": settings["share_ssids"],
        "max_ai_targets": settings["max_ai_targets"],
    }
