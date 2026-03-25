"""Configuration models."""

from pydantic import BaseModel, Field


class RateLimitConfig(BaseModel):
    requests_per_second: float = 10.0
    burst: int = 20
    delay_between_requests: float = 0.1


class ScopeConfig(BaseModel):
    allowed_hosts: list[str] = Field(default_factory=list)
    allowed_ips: list[str] = Field(default_factory=list)
    allowed_networks: list[str] = Field(default_factory=list)
    excluded_hosts: list[str] = Field(default_factory=list)


class ModuleConfig(BaseModel):
    name: str
    enabled: bool = True
    options: dict = Field(default_factory=dict)


class NightOwlConfig(BaseModel):
    """Main application configuration."""

    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    modules: list[ModuleConfig] = Field(default_factory=list)
    output_dir: str = "./reports"
    db_path: str = "./nightowl.db"
    log_level: str = "INFO"
    log_file: str | None = None
    mode: str = "semi"  # auto, semi, manual
    threads: int = 10
    timeout: int = 30
    user_agent: str = "NightOwl/1.0"
    proxy: str | None = None
    wordlist_dir: str = "./wordlists"

    def is_module_enabled(self, name: str) -> bool:
        for mod in self.modules:
            if mod.name == name:
                return mod.enabled
        return True  # enabled by default if not listed

    def get_module_options(self, name: str) -> dict:
        for mod in self.modules:
            if mod.name == name:
                return mod.options
        return {}
