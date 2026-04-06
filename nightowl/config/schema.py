"""Configuration validation and merging."""

import logging
from pathlib import Path

import yaml

from nightowl.models.config import NightOwlConfig

logger = logging.getLogger("nightowl")


def load_config(path: str | Path) -> NightOwlConfig:
    """Load configuration from a YAML file."""
    path = Path(path)
    if not path.exists():
        return NightOwlConfig()

    with open(path) as f:
        raw = yaml.safe_load(f) or {}

    return NightOwlConfig(**raw)


class ConfigValidationError(Exception):
    """Raised when config has critical errors that prevent safe operation."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__(f"Config validation failed: {'; '.join(errors)}")


def validate_config(config: NightOwlConfig, *, strict: bool = False) -> list[str]:
    """Validate a config and return list of warnings.

    In strict mode, raises ConfigValidationError for critical issues.
    In non-strict mode (default), returns warnings as strings.
    """
    warnings: list[str] = []
    errors: list[str] = []

    # Critical: scope validation
    if not config.scope.allowed_hosts and not config.scope.allowed_networks:
        msg = "No targets defined in scope — scans will be denied until scope is configured"
        if strict:
            errors.append(msg)
        else:
            warnings.append(msg)

    # Dangerous rate limit
    if config.rate_limit.requests_per_second > 100:
        warnings.append(
            f"Rate limit very high ({config.rate_limit.requests_per_second} rps) — "
            f"may trigger WAF/IDS or cause target DoS"
        )

    if config.rate_limit.requests_per_second <= 0:
        errors.append("Rate limit must be > 0")

    # Thread safety
    if config.threads > 50:
        warnings.append(
            f"Thread count very high ({config.threads}) — "
            f"may exhaust system resources"
        )

    if config.threads < 1:
        errors.append("Thread count must be >= 1")

    # Timeout validation
    timeout = getattr(config, "timeout", None)
    if timeout is not None:
        if timeout <= 0:
            errors.append("Timeout must be > 0")
        elif timeout > 300:
            warnings.append(f"Timeout very high ({timeout}s) — requests may hang")

    # DB path validation
    if config.db_path and config.db_path != ":memory:":
        from pathlib import Path
        db_dir = Path(config.db_path).parent
        if not db_dir.exists():
            warnings.append(f"Database directory does not exist: {db_dir}")

    # Module config validation
    if hasattr(config, "modules") and config.modules:
        for module_name, module_config in config.modules.items():
            if not isinstance(module_config, dict):
                errors.append(f"Module config for '{module_name}' must be a dict")

    if errors:
        if strict:
            raise ConfigValidationError(errors)
        warnings.extend(errors)

    return warnings


def merge_configs(base: NightOwlConfig, override: dict) -> NightOwlConfig:
    """Merge override dict into base config."""
    base_dict = base.model_dump()
    base_dict.update({k: v for k, v in override.items() if v is not None})
    return NightOwlConfig(**base_dict)
