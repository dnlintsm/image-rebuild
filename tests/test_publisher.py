import pytest

from image_rebuild.builder import RunResult
from image_rebuild.publisher import (
    DockerHubConfig,
    DockerPublisher,
    PublishError,
    RegistryConfig,
    registry_host,
)


class FakeRunner:
    def __init__(self, results):
        # results: dict keyed by the docker subcommand (cmd[1]) -> RunResult
        self.results = results
        self.calls = []

    def run(self, cmd, cwd=None, input_text=None):
        self.calls.append((cmd, input_text))
        return self.results[cmd[1]]


CFG = DockerHubConfig(user="alice", token="s3cret")


def test_registry_config_from_env_missing(monkeypatch):
    for name in ("DOCKERHUB_USER", "DOCKERHUB_TOKEN", "REGISTRY_USER", "REGISTRY_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(PublishError, match="DOCKERHUB_USER"):
        RegistryConfig.from_env()


def test_registry_env_vars_take_precedence(monkeypatch):
    monkeypatch.setenv("DOCKERHUB_USER", "hub-user")
    monkeypatch.setenv("DOCKERHUB_TOKEN", "hub-token")
    monkeypatch.setenv("REGISTRY_USER", "harbor-user")
    monkeypatch.setenv("REGISTRY_TOKEN", "harbor-token")
    cfg = RegistryConfig.from_env()
    assert cfg.user == "harbor-user"
    assert cfg.token == "harbor-token"


def test_dockerhub_config_alias_still_works(monkeypatch):
    for name in ("REGISTRY_USER", "REGISTRY_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("DOCKERHUB_USER", "alice")
    monkeypatch.setenv("DOCKERHUB_TOKEN", "s3cret")
    assert DockerHubConfig.from_env() == RegistryConfig(user="alice", token="s3cret")


def test_registry_host_detection():
    assert registry_host("penpotapp/mcp:latest") is None          # Docker Hub
    assert registry_host("nginx") is None
    assert registry_host("docker.io/library/nginx") is None       # explicit Hub
    assert registry_host("harbor.corp.com/proj/app:1.0") == "harbor.corp.com"
    assert registry_host("localhost:5000/app") == "localhost:5000"
    assert registry_host("ghcr.io/owner/app:tag") == "ghcr.io"


def test_login_passes_token_via_stdin():
    runner = FakeRunner({"login": RunResult(0, "Login Succeeded", "")})
    DockerPublisher(CFG, runner=runner).login()
    cmd, stdin = runner.calls[0]
    assert cmd[:2] == ["docker", "login"]
    assert "--password-stdin" in cmd
    assert stdin == "s3cret"          # token never on the command line
    assert "s3cret" not in cmd


def test_login_with_registry_appends_host():
    runner = FakeRunner({"login": RunResult(0, "Login Succeeded", "")})
    DockerPublisher(CFG, runner=runner, registry="harbor.corp.com").login()
    cmd, stdin = runner.calls[0]
    assert cmd[-1] == "harbor.corp.com"
    assert stdin == "s3cret"


def test_login_failure_raises():
    runner = FakeRunner({"login": RunResult(1, "", "unauthorized")})
    with pytest.raises(PublishError, match="docker login"):
        DockerPublisher(CFG, runner=runner).login()


def test_push_parses_digest():
    out = "The push refers to repository [docker.io/alice/app]\n" \
          "latest: digest: sha256:deadbeef size: 1234\n"
    runner = FakeRunner({"push": RunResult(0, out, "")})
    digest = DockerPublisher(CFG, runner=runner).push("alice/app:latest")
    assert digest == "sha256:deadbeef"


def test_push_without_digest_returns_none():
    runner = FakeRunner({"push": RunResult(0, "pushed", "")})
    assert DockerPublisher(CFG, runner=runner).push("alice/app:latest") is None


def test_push_failure_raises():
    runner = FakeRunner({"push": RunResult(1, "", "denied")})
    with pytest.raises(PublishError, match="docker push"):
        DockerPublisher(CFG, runner=runner).push("alice/app:latest")
