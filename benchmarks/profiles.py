"""Benchmark target profiles and expected signal."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urljoin


@dataclass(frozen=True)
class QuietExpectation:
    probe_path: str
    module_name: str
    rationale: str


@dataclass(frozen=True)
class BenchmarkProfile:
    name: str
    description: str
    expected_modules: tuple[str, ...]
    expected_finding_families: tuple[str, ...] = ()
    reviewed_confirmed_families: tuple[str, ...] = ()
    probe_paths: tuple[str, ...] = ("/",)
    expected_quiet_checks: tuple[QuietExpectation, ...] = ()
    notes: tuple[str, ...] = ()


DEFAULT_CORE_MODULES = (
    "header-analyzer",
    "xss-scanner",
    "sqli-scanner",
    "cors-checker",
    "ssl-analyzer",
    "dir-bruteforce",
)


TARGET_PROFILES: dict[str, BenchmarkProfile] = {
    "dvwa": BenchmarkProfile(
        name="dvwa",
        description="Authenticated multi-probe benchmark for DVWA with setup bootstrap and targeted XSS/SQLi routes.",
        expected_modules=("header-analyzer", "dir-bruteforce", "xss-scanner", "sqli-scanner", "ssl-analyzer"),
        expected_finding_families=(
            "header-analyzer:missing-header:Content-Security-Policy",
            "header-analyzer:missing-header:X-Content-Type-Options",
            "header-analyzer:missing-header:X-Frame-Options",
            "ssl-analyzer:No TLS — target uses plain HTTP",
            "xss-scanner:Reflected XSS in parameter 'name'",
            "sqli-scanner:SQL Injection (Error-Based) in 'id'",
            "dir-bruteforce:discovered-path:/robots.txt",
        ),
        probe_paths=(
            "/",
            "/instructions.php",
            "/vulnerabilities/xss_r/?name=test",
            "/vulnerabilities/sqli/?id=1&Submit=Submit",
            "/robots.txt",
        ),
        notes=(
            "The benchmark bootstraps DVWA setup and logs in as the default admin account before probing lesson routes.",
            "A miss from xss-scanner or sqli-scanner on this profile is now meaningful, because the probes include the dedicated vulnerable routes.",
        ),
    ),
    "juice-shop": BenchmarkProfile(
        name="juice-shop",
        description="Multi-probe benchmark for Juice Shop unauthenticated frontend routes.",
        expected_modules=("header-analyzer", "dir-bruteforce", "sqli-scanner", "ssl-analyzer"),
        expected_finding_families=(
            "header-analyzer:missing-header:Content-Security-Policy",
            "header-analyzer:missing-header:Permissions-Policy",
            "header-analyzer:missing-header:Referrer-Policy",
            "ssl-analyzer:No TLS — target uses plain HTTP",
            "dir-bruteforce:discovered-path:/robots.txt",
            "sqli-scanner:SQL Injection (Error-Based) in 'q'",
        ),
        reviewed_confirmed_families=(
            "sqli-scanner:SQL Injection (Error-Based) in 'q'",
        ),
        probe_paths=(
            "/",
            "/robots.txt",
            "/assets/public/images/uploads/",
            "/rest/products/search?q=apple",
            "/api/Challenges/?page=1",
        ),
        notes=(
            "Most client-side flows are still not exercised without browser-driven interaction.",
            "No signal from SQLi/XSS modules should not be treated as a hard miss here.",
        ),
    ),
    "webgoat": BenchmarkProfile(
        name="webgoat",
        description="Authenticated multi-probe benchmark for WebGoat shell routes and lesson menu access.",
        expected_modules=("header-analyzer", "dir-bruteforce", "xss-scanner", "sqli-scanner", "ssl-analyzer"),
        expected_finding_families=(
            "header-analyzer:missing-header:Content-Security-Policy",
            "header-analyzer:missing-header:X-Content-Type-Options",
            "ssl-analyzer:No TLS — target uses plain HTTP",
            "xss-scanner:Reflected XSS in parameter 'field1'",
            "sqli-scanner:error-based:assignment5b:userid",
            "sqli-scanner:error-based:attack8:name",
            "sqli-scanner:error-based:attack8:auth_tan",
            "sqli-scanner:error-based:attack9:name",
            "sqli-scanner:error-based:attack9:auth_tan",
            "sqli-scanner:error-based:attack10:action_string",
            "dir-bruteforce:discovered-path:/robots.txt",
        ),
        reviewed_confirmed_families=(
            "sqli-scanner:error-based:assignment5b:userid",
            "sqli-scanner:error-based:attack8:name",
            "sqli-scanner:error-based:attack8:auth_tan",
            "sqli-scanner:error-based:attack9:name",
            "sqli-scanner:error-based:attack9:auth_tan",
            "sqli-scanner:error-based:attack10:action_string",
        ),
        probe_paths=(
            "/",
            "/welcome.mvc",
            "/start.mvc?lang=en",
            "/service/lessonmenu.mvc",
            "/SqlInjection.lesson",
            "/CrossSiteScripting.lesson",
            "/CrossSiteScripting/attack5a?QTY1=1&QTY2=1&QTY3=1&QTY4=1&field1=test&field2=111",
        ),
        notes=(
            "The benchmark creates a disposable local WebGoat account and authenticates before probing the lesson shell.",
            "This profile now includes one reflected-XSS lesson action and one SQLi lesson page whose forms are actively submitted by the scanner.",
            "The reviewed SQLi signal now covers confidentiality, integrity, and availability lesson actions via assignment5b, attack8, attack9, and attack10.",
        ),
    ),
    "nightowl-lab": BenchmarkProfile(
        name="nightowl-lab",
        description="Dedicated local benchmark lab for reflected XSS and SQL injection routes.",
        expected_modules=("xss-scanner", "sqli-scanner", "dir-bruteforce"),
        expected_finding_families=(
            "xss-scanner:Reflected XSS in parameter 'q'",
            "sqli-scanner:SQL Injection (Error-Based) in 'q'",
            "sqli-scanner:SQL Injection (Time-Based Blind) in 'q'",
            "dir-bruteforce:discovered-path:/robots.txt",
        ),
        reviewed_confirmed_families=(
            "xss-scanner:Reflected XSS in parameter 'q'",
            "sqli-scanner:SQL Injection (Error-Based) in 'q'",
            "sqli-scanner:SQL Injection (Time-Based Blind) in 'q'",
        ),
        probe_paths=(
            "/",
            "/robots.txt",
            "/xss/reflected?q=hello",
            "/xss/escaped?q=hello",
            "/xss/json?q=hello",
            "/xss/comment?q=hello",
            "/xss/attr?q=hello",
            "/sql/error?q=apple",
            "/sql/time?q=apple",
        ),
        expected_quiet_checks=(
            QuietExpectation(
                probe_path="/xss/escaped",
                module_name="xss-scanner",
                rationale="Escaped HTML reflection is a calibration route where the XSS scanner should stay quiet.",
            ),
            QuietExpectation(
                probe_path="/xss/json",
                module_name="xss-scanner",
                rationale="Reflection inside JSON is a calibration route where the XSS scanner should stay quiet.",
            ),
            QuietExpectation(
                probe_path="/xss/comment",
                module_name="xss-scanner",
                rationale="Reflection inside HTML comments is a calibration route where the XSS scanner should stay quiet.",
            ),
            QuietExpectation(
                probe_path="/xss/attr",
                module_name="xss-scanner",
                rationale="Reflection inside inert HTML attributes is a calibration route where the XSS scanner should stay quiet.",
            ),
        ),
        notes=(
            "This lab is intentionally synthetic and should be used for scanner calibration, not product marketing.",
            "Expected XSS and SQLi signal should come from the dedicated vulnerable routes, while the safe-context routes should stay quiet.",
        ),
    ),
    "cors-lab": BenchmarkProfile(
        name="cors-lab",
        description="Dedicated local benchmark lab for CORS misconfiguration checks.",
        expected_modules=("cors-checker",),
        expected_finding_families=(
            "cors-checker:wildcard-credentials:/wildcard-credentials",
            "cors-checker:reflects-arbitrary-origins:/reflect-credentials",
            "cors-checker:null-origin:/null-origin",
            "cors-checker:dangerous-methods:/dangerous-methods",
        ),
        reviewed_confirmed_families=(
            "cors-checker:wildcard-credentials:/wildcard-credentials",
            "cors-checker:reflects-arbitrary-origins:/reflect-credentials",
            "cors-checker:null-origin:/null-origin",
            "cors-checker:dangerous-methods:/dangerous-methods",
        ),
        probe_paths=(
            "/wildcard-credentials",
            "/reflect-credentials",
            "/null-origin",
            "/dangerous-methods",
            "/allowlist",
        ),
        expected_quiet_checks=(
            QuietExpectation(
                probe_path="/allowlist",
                module_name="cors-checker",
                rationale="The allowlist route is intentionally safe and should not trigger cors-checker findings.",
            ),
        ),
        notes=(
            "This lab exists to validate cors-checker against explicit wildcard, reflected-origin, null-origin, and dangerous-method scenarios.",
            "The /allowlist route is intentionally safe and should stay quiet.",
        ),
    ),
}


def get_profile(target_name: str) -> BenchmarkProfile | None:
    return TARGET_PROFILES.get(target_name)


def resolve_probe_urls(base_url: str, profile: BenchmarkProfile | None) -> list[str]:
    if not profile:
        return [base_url]
    return [urljoin(base_url.rstrip("/") + "/", path.lstrip("/")) for path in profile.probe_paths]
