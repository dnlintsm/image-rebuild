import pytest

from image_rebuild.builder import BuildError, DockerBuilder, RunResult


class FakeRunner:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def run(self, cmd, cwd=None):
        self.calls.append((cmd, cwd))
        return self.result


def test_pull_ok():
    runner = FakeRunner(RunResult(0, "", ""))
    DockerBuilder(runner=runner).pull("nginx:1.25")
    assert runner.calls[0][0] == ["docker", "pull", "nginx:1.25"]


def test_pull_failure_raises():
    runner = FakeRunner(RunResult(1, "", "no such image"))
    with pytest.raises(BuildError, match="docker pull"):
        DockerBuilder(runner=runner).pull("nope")


def test_build_constructs_command_and_returns_tag():
    runner = FakeRunner(RunResult(0, "", ""))
    tag = DockerBuilder(runner=runner).build("FROM x\nRUN y\n", "x:fixed")
    assert tag == "x:fixed"
    cmd, cwd = runner.calls[0]
    assert cmd[:4] == ["docker", "build", "-t", "x:fixed"]
    assert cwd == cmd[4]  # built in the temp context dir


def test_build_failure_raises():
    runner = FakeRunner(RunResult(1, "", "step failed"))
    with pytest.raises(BuildError, match="docker build"):
        DockerBuilder(runner=runner).build("FROM x", "x:fixed")


def test_inspect_user_returns_value_or_none():
    assert DockerBuilder(runner=FakeRunner(RunResult(0, "appuser\n", ""))).inspect_user("i") == "appuser"
    assert DockerBuilder(runner=FakeRunner(RunResult(0, "\n", ""))).inspect_user("i") is None
    assert DockerBuilder(runner=FakeRunner(RunResult(1, "", "err"))).inspect_user("i") is None
