"""YAML configuration loader and validator."""

from pathlib import Path

import yaml

from nightowl.models.config import NightOwlConfig


def load_config(path: str | Path) -> NightOwlConfig:
    """Load configuration from a YAML file."""
    path = Path(path)
    if not path.exists():
        return NightOwlConfig()

    with open(path) as f:
        raw = yaml.safe_load(f) or {}

    return NightOwlConfig(**raw)


def validate_config(config: NightOwlConfig) -> list[str]:
    """Validate a config and return list of warnings."""
    warnings = []
    if not config.scope.allowed_hosts and not config.scope.allowed_networks:
        warnings.append("No targets defined in scope")
    if config.rate_limit.requests_per_second > 100:
        warnings.append("Rate limit very high (>100 rps), may cause issues")
    if config.threads > 50:
        warnings.append("Thread count very high (>50)")
    return warnings


def merge_configs(base: NightOwlConfig, override: dict) -> NightOwlConfig:
    """Merge override dict into base config."""
    base_dict = base.model_dump()
    base_dict.update({k: v for k, v in override.items() if v is not None})
    return NightOwlConfig(**base_dict)
