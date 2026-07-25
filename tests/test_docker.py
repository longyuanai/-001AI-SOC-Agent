"""Static checks for the production container contract."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).parents[1]
DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")
PROJECT_IGNORE = (ROOT / ".dockerignore").read_text(encoding="utf-8")
PARENT_IGNORE = (ROOT / "Dockerfile.dockerignore").read_text(encoding="utf-8")


def test_dockerfile_uses_slim_multistage_build():
    assert DOCKERFILE.count("FROM python:3.11-slim") == 2
    assert "AS builder" in DOCKERFILE
    assert "AS runtime" in DOCKERFILE
    assert "pip wheel --no-cache-dir" in DOCKERFILE
    assert "pip install --no-cache-dir --no-deps /wheels/*.whl" in DOCKERFILE
    assert "python -m pip check" in DOCKERFILE


def test_dockerfile_runs_api_as_non_root():
    assert "USER 65532:65532" in DOCKERFILE
    assert "EXPOSE 8080" in DOCKERFILE
    assert '"ai_soc_agent.server:app"' in DOCKERFILE
    assert '"--host", "0.0.0.0"' in DOCKERFILE


def test_dockerfile_has_healthcheck_and_no_embedded_credentials():
    assert "HEALTHCHECK" in DOCKERFILE
    # /health is cheap; /alerts serialized the whole store on every probe.
    assert "http://127.0.0.1:8080/health" in DOCKERFILE
    assert "API_KEY" not in DOCKERFILE
    assert "PASSWORD" not in DOCKERFILE
    assert "TOKEN" not in DOCKERFILE


def test_dockerignore_excludes_local_and_sensitive_artifacts():
    for pattern in (".git", ".venv", ".env", ".pytest_cache", "AUDIT", "tests"):
        assert pattern in PROJECT_IGNORE
        assert pattern in PARENT_IGNORE
    assert "!000shared-llm-core/**" in PARENT_IGNORE
    assert "!001AI-SOC-Agent/**" in PARENT_IGNORE


def test_readme_documents_parent_context_build():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "docker build -f 001AI-SOC-Agent/Dockerfile" in readme
    assert "docker run --rm -p 8080:8080" in readme


def test_package_uses_lazy_llm_exports_for_api_runtime():
    package_init = (ROOT / "src" / "ai_soc_agent" / "__init__.py").read_text(
        encoding="utf-8"
    )
    assert "def __getattr__" in package_init
    assert "from ai_soc_agent.analyzer import" not in package_init.split(
        "def __getattr__", maxsplit=1
    )[0]
