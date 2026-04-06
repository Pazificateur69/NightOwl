"""Tests for the dependency confusion module."""

from nightowl.modules.recon.dependency_confusion import (
    _extract_npm_packages,
    _extract_pypi_packages,
    _extract_pyproject_packages,
    _extract_gemfile_packages,
    _extract_gomod_packages,
    _extract_pom_packages,
)


class TestNpmExtractor:
    def test_basic(self):
        content = '{"dependencies": {"express": "^4.0", "lodash": "4.17.21"}}'
        pkgs = _extract_npm_packages(content)
        assert "express" in pkgs
        assert "lodash" in pkgs

    def test_dev_deps(self):
        content = '{"devDependencies": {"jest": "^29.0"}}'
        pkgs = _extract_npm_packages(content)
        assert "jest" in pkgs

    def test_invalid_json(self):
        assert _extract_npm_packages("not json") == []


class TestPypiExtractor:
    def test_basic(self):
        content = "requests>=2.28\nclick==8.1.3\n# comment\npydantic"
        pkgs = _extract_pypi_packages(content)
        assert "requests" in pkgs
        assert "click" in pkgs
        assert "pydantic" in pkgs

    def test_skips_git(self):
        content = "git+https://github.com/foo/bar.git\nrequests"
        pkgs = _extract_pypi_packages(content)
        assert len(pkgs) == 1


class TestPyprojectExtractor:
    def test_pep621(self):
        content = """
[project]
name = "myapp"
version = "1.0.0"
dependencies = [
    "requests>=2.28",
    "click==8.1.3",
    "pydantic",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0",
    "ruff",
]
"""
        pkgs = _extract_pyproject_packages(content)
        assert "requests" in pkgs
        assert "click" in pkgs
        assert "pydantic" in pkgs
        assert "pytest" in pkgs
        assert "ruff" in pkgs

    def test_poetry(self):
        content = """
[tool.poetry.dependencies]
python = "^3.11"
fastapi = "^0.100"
sqlalchemy = "^2.0"
"""
        pkgs = _extract_pyproject_packages(content)
        assert "fastapi" in pkgs
        assert "sqlalchemy" in pkgs
        assert "python" not in pkgs

    def test_empty(self):
        assert _extract_pyproject_packages("") == []


class TestGemfileExtractor:
    def test_basic(self):
        content = """
source 'https://rubygems.org'
gem 'rails', '~> 7.0'
gem 'pg'
"""
        pkgs = _extract_gemfile_packages(content)
        assert "rails" in pkgs
        assert "pg" in pkgs


class TestGomodExtractor:
    def test_basic(self):
        content = """module github.com/foo/bar

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/lib/pq v1.10.9
)
"""
        pkgs = _extract_gomod_packages(content)
        assert "github.com/gin-gonic/gin" in pkgs
        assert "github.com/lib/pq" in pkgs


class TestPomExtractor:
    def test_basic(self):
        content = """<dependencies>
    <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-core</artifactId>
        <version>5.3.0</version>
    </dependency>
</dependencies>"""
        pkgs = _extract_pom_packages(content)
        assert "spring-core" in pkgs
