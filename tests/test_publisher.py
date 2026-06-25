import pytest

from image_rebuild.builder import RunResult
from image_rebuild.publisher import DockerHubConfig, DockerPublisher, PublishError


class FakeRunner:
    def __init__(self, results):
        # results: dict keyed by the docker subcommand (cmd[1]) -> RunResult
        self.results = results
        self.calls = []

    def run(self, cmd, cwd=None, input_text=None):
        self.calls.append((cmd, input_text))
        return self.results[cmd[1]]


CFG = DockerHubConfig(user="alice", token="s3cret")


def test_dockerhub_config_from_env_missing(monkeypatch):
    monkeypatch.delenv("DOCKERHUB_USER", raising=False)
    monkeypatch.delenv("DOCKERHUB_TOKEN", raising=False)
    with pytest.raises(PublishError, match="DOCKERHUB_USER"):
        DockerHubConfig.from_env()


def test_login_passes_token_via_stdin():
    runner = FakeRunner({"login": RunResult(0, "Login Succeeded", "")})
    DockerPublisher(CFG, runner=runner).login()
    cmd, stdin = runner.calls[0]
    assert cmd[:2] == ["docker", "login"]
    assert "--password-stdin" in cmd
    assert stdin == "s3cret"          # token never on the command line
    assert "s3cret" not in cmd


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
