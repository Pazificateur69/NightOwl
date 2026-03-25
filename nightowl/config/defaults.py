"""Default configuration values."""

DEFAULTS = {
    "mode": "semi",
    "threads": 10,
    "timeout": 30,
    "log_level": "INFO",
    "output_dir": "./reports",
    "db_path": "./nightowl.db",
    "user_agent": "NightOwl/1.0",
    "wordlist_dir": "./wordlists",
    "rate_limit": {
        "requests_per_second": 10.0,
        "burst": 20,
        "delay_between_requests": 0.1,
    },
}

# Common web directories for bruteforce
COMMON_DIRS = [
    "admin", "login", "wp-admin", "wp-login.php", "administrator",
    "api", "v1", "v2", "graphql", "swagger", "docs",
    "backup", "backups", "db", "database", "dump",
    ".git", ".env", ".htaccess", "robots.txt", "sitemap.xml",
    "config", "conf", "settings", "setup", "install",
    "uploads", "files", "media", "images", "assets",
    "test", "debug", "status", "health", "info",
    "phpmyadmin", "adminer", "console", "shell",
]

# Common subdomains
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap",
    "webmail", "ns1", "ns2", "dns", "mx",
    "api", "dev", "staging", "test", "beta",
    "admin", "portal", "vpn", "remote",
    "cdn", "static", "assets", "media",
    "app", "dashboard", "panel", "cms",
    "git", "gitlab", "jenkins", "ci",
    "db", "database", "mysql", "redis",
    "monitor", "grafana", "kibana", "elastic",
]

# Default ports to scan
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1433, 1521, 2049,
    3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017,
]
