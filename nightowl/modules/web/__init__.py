"""NightOwl web scanner modules.

This package contains all web-oriented vulnerability scanning plugins.
Each plugin implements the ScannerPlugin interface and targets specific
web security concerns.
"""

from nightowl.modules.web.api_scanner import APIScannerPlugin
from nightowl.modules.web.auth_tester import AuthTesterPlugin
from nightowl.modules.web.cors_checker import CORSCheckerPlugin
from nightowl.modules.web.crlf_injection import CRLFInjectionPlugin
from nightowl.modules.web.csrf_scanner import CSRFScannerPlugin
from nightowl.modules.web.deserialization import DeserializationPlugin
from nightowl.modules.web.dir_bruteforce import DirBruteforcePlugin
from nightowl.modules.web.graphql_introspect import GraphQLIntrospectPlugin
from nightowl.modules.web.header_analyzer import HeaderAnalyzerPlugin
from nightowl.modules.web.http_smuggling import HTTPSmugglingPlugin
from nightowl.modules.web.jwt_attack import JWTAttackPlugin
from nightowl.modules.web.open_redirect import OpenRedirectPlugin
from nightowl.modules.web.path_traversal import PathTraversalPlugin
from nightowl.modules.web.sqli_scanner import SQLiScannerPlugin
from nightowl.modules.web.ssl_analyzer import SSLAnalyzerPlugin
from nightowl.modules.web.ssrf_scanner import SSRFScannerPlugin
from nightowl.modules.web.ssti_scanner import SSTIPlugin
from nightowl.modules.web.waf_detect import WAFDetectPlugin
from nightowl.modules.web.websocket_fuzzer import WebSocketFuzzerPlugin
from nightowl.modules.web.xss_scanner import XSSScannerPlugin
from nightowl.modules.web.xxe_scanner import XXEPlugin

__all__ = [
    "APIScannerPlugin",
    "AuthTesterPlugin",
    "CORSCheckerPlugin",
    "CRLFInjectionPlugin",
    "CSRFScannerPlugin",
    "DeserializationPlugin",
    "DirBruteforcePlugin",
    "GraphQLIntrospectPlugin",
    "HeaderAnalyzerPlugin",
    "HTTPSmugglingPlugin",
    "JWTAttackPlugin",
    "OpenRedirectPlugin",
    "PathTraversalPlugin",
    "SQLiScannerPlugin",
    "SSLAnalyzerPlugin",
    "SSRFScannerPlugin",
    "SSTIPlugin",
    "WAFDetectPlugin",
    "WebSocketFuzzerPlugin",
    "XSSScannerPlugin",
    "XXEPlugin",
]

# Registry of all web plugins for discovery by the plugin loader
WEB_PLUGINS: list[type] = [
    # ── Recon stage ──
    WAFDetectPlugin,
    HeaderAnalyzerPlugin,
    SSLAnalyzerPlugin,
    DirBruteforcePlugin,
    # ── Scan stage ──
    SQLiScannerPlugin,
    XSSScannerPlugin,
    CSRFScannerPlugin,
    SSRFScannerPlugin,
    PathTraversalPlugin,
    CORSCheckerPlugin,
    AuthTesterPlugin,
    APIScannerPlugin,
    JWTAttackPlugin,
    GraphQLIntrospectPlugin,
    WebSocketFuzzerPlugin,
    SSTIPlugin,
    DeserializationPlugin,
    XXEPlugin,
    CRLFInjectionPlugin,
    OpenRedirectPlugin,
    HTTPSmugglingPlugin,
]
