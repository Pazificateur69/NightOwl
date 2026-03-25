"""NightOwl recon modules.

This package contains all reconnaissance plugins that gather
information about targets before active vulnerability scanning.
"""

from nightowl.modules.recon.dns_enum import DNSEnumPlugin
from nightowl.modules.recon.port_scanner import PortScannerPlugin
from nightowl.modules.recon.service_fingerprint import ServiceFingerprintPlugin
from nightowl.modules.recon.subdomain import SubdomainPlugin
from nightowl.modules.recon.tech_detect import TechDetectPlugin
from nightowl.modules.recon.web_spider import WebSpiderPlugin
from nightowl.modules.recon.whois_lookup import WhoisPlugin

__all__ = [
    "DNSEnumPlugin",
    "PortScannerPlugin",
    "ServiceFingerprintPlugin",
    "SubdomainPlugin",
    "TechDetectPlugin",
    "WebSpiderPlugin",
    "WhoisPlugin",
]

# Registry of all recon plugins for discovery by the plugin loader
RECON_PLUGINS: list[type] = [
    DNSEnumPlugin,
    PortScannerPlugin,
    SubdomainPlugin,
    ServiceFingerprintPlugin,
    WhoisPlugin,
    TechDetectPlugin,
    WebSpiderPlugin,
]
