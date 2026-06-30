import pytest

from image_rebuild.config import AppConfig, ConfigError


def test_defaults_when_no_file():
    cfg = AppConfig.load(None)
    assert cfg.gate_severity == "critical"
    assert cfg.max_iterations == 3
    assert cfg.package_manager is None
    assert cfg.base_image_bump is False


def test_load_from_yaml(tmp_path):
    f = tmp_path / "image-rebuild.yaml"
    f.write_text(
        "gate_severity: high\n"
        "max_iterations: 5\n"
        "package_manager: apk\n"
        "base_image_bump: true\n"
        "registry:\n"
        "  dockerhub_repo: mycorp/app\n"
        "artifacts_dir: ./out\n"
    )
    cfg = AppConfig.load(str(f))
    assert cfg.gate_severity == "high"
    assert cfg.max_iterations == 5
    assert cfg.package_manager == "apk"
    assert cfg.base_image_bump is True
    assert cfg.dockerhub_repo == "mycorp/app"
    assert cfg.artifacts_dir == "./out"


def test_missing_explicit_path_errors():
    with pytest.raises(ConfigError, match="not found"):
        AppConfig.load("/no/such/config.yaml")


def test_non_mapping_yaml_errors(tmp_path):
    f = tmp_path / "bad.yaml"
    f.write_text("- just\n- a list\n")
    with pytest.raises(ConfigError, match="must be a mapping"):
        AppConfig.load(str(f))
