"""Tests for module registry metadata."""

from nightowl.modules import get_all_modules, get_core_modules


def test_core_modules_are_marked_recommended():
    modules = {m["name"]: m for m in get_all_modules()}

    assert modules["xss-scanner"]["core"] is True
    assert modules["xss-scanner"]["maturity"] == "recommended"
    assert modules["dependency-confusion"]["maturity"] == "usable-with-caution"
    assert modules["csrf-scanner"]["maturity"] == "experimental"


def test_get_core_web_modules_returns_hardened_web_set():
    core_web = get_core_modules(".modules.web.")

    assert "xss-scanner" in core_web
    assert "sqli-scanner" in core_web
    assert "deep-port-scan" not in core_web
