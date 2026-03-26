from cryptography.fernet import Fernet

from app.core import config


def test_ensure_runtime_encryption_key_generates_missing_value(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    runtime_env = tmp_path / ".env.runtime"
    example_env = tmp_path / ".env.example"
    lock_path = tmp_path / ".env.runtime.lock"
    marker_path = tmp_path / ".env.runtime.bootstrap"
    example_env.write_text(
        "\n".join(
            [
                "SECRET_KEY=test-secret",
                "DATABASE_URL=postgresql+psycopg://asset:asset@postgres:5432/assetdb",
                "ENCRYPTION_KEY=",
                "LLM_PROVIDER=mock",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(config, "RUNTIME_ENV_PATH", runtime_env)
    monkeypatch.setattr(config, "EXAMPLE_ENV_PATH", example_env)
    monkeypatch.setattr(config, "RUNTIME_ENV_LOCK_PATH", lock_path)
    monkeypatch.setattr(config, "RUNTIME_ENV_BOOTSTRAP_MARKER_PATH", marker_path)

    state = config.ensure_runtime_encryption_key()

    assert state.generated_encryption_key is True
    assert runtime_env.exists() is True
    content = runtime_env.read_text(encoding="utf-8")
    assert "SECRET_KEY=test-secret" in content
    encryption_line = next(line for line in content.splitlines() if line.startswith("ENCRYPTION_KEY="))
    encryption_key = encryption_line.split("=", 1)[1].strip()
    assert encryption_key
    Fernet(encryption_key.encode())
    assert marker_path.exists() is True
    assert config.consume_runtime_bootstrap_marker() is True
    assert config.consume_runtime_bootstrap_marker() is False


def test_ensure_runtime_encryption_key_keeps_existing_value(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    runtime_env = tmp_path / ".env.runtime"
    example_env = tmp_path / ".env.example"
    lock_path = tmp_path / ".env.runtime.lock"
    marker_path = tmp_path / ".env.runtime.bootstrap"
    existing_key = Fernet.generate_key().decode()
    runtime_env.write_text(
        f"SECRET_KEY=test-secret\nENCRYPTION_KEY={existing_key}\n",
        encoding="utf-8",
    )
    example_env.write_text("SECRET_KEY=test-secret\n", encoding="utf-8")

    monkeypatch.setattr(config, "RUNTIME_ENV_PATH", runtime_env)
    monkeypatch.setattr(config, "EXAMPLE_ENV_PATH", example_env)
    monkeypatch.setattr(config, "RUNTIME_ENV_LOCK_PATH", lock_path)
    monkeypatch.setattr(config, "RUNTIME_ENV_BOOTSTRAP_MARKER_PATH", marker_path)

    state = config.ensure_runtime_encryption_key()

    assert state.generated_encryption_key is False
    assert runtime_env.read_text(encoding="utf-8").splitlines() == [
        "SECRET_KEY=test-secret",
        f"ENCRYPTION_KEY={existing_key}",
    ]
    assert marker_path.exists() is False


def test_migrate_legacy_llm_api_key_storage_promotes_plaintext(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    runtime_env = tmp_path / ".env.runtime"
    example_env = tmp_path / ".env.example"
    encrypted_key = Fernet.generate_key()
    encrypted_value = Fernet(encrypted_key).encrypt(b"sk-legacy-secret").decode()
    runtime_env.write_text(
        "\n".join(
            [
                "SECRET_KEY=test-secret",
                f"ENCRYPTION_KEY={encrypted_key.decode()}",
                "LLM_API_KEY=",
                f"LLM_API_KEY_ENCRYPTED={encrypted_value}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    example_env.write_text("SECRET_KEY=test-secret\n", encoding="utf-8")

    monkeypatch.setattr(config, "RUNTIME_ENV_PATH", runtime_env)
    monkeypatch.setattr(config, "EXAMPLE_ENV_PATH", example_env)

    migrated = config.migrate_legacy_llm_api_key_storage()

    assert migrated is True
    content = runtime_env.read_text(encoding="utf-8")
    assert "LLM_API_KEY=sk-legacy-secret" in content
    assert "LLM_API_KEY_ENCRYPTED=" not in content


def test_read_runtime_env_value_prefers_process_env_over_runtime_file(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    runtime_env = tmp_path / ".env.runtime"
    example_env = tmp_path / ".env.example"
    runtime_env.write_text(
        "\n".join(
            [
                "SECRET_KEY=test-secret",
                "LLM_PROVIDER=mock",
                "LLM_MODEL=gpt-4o-mini",
                "LLM_BASE_URL=",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    example_env.write_text(runtime_env.read_text(encoding="utf-8"), encoding="utf-8")

    monkeypatch.setattr(config, "RUNTIME_ENV_PATH", runtime_env)
    monkeypatch.setattr(config, "EXAMPLE_ENV_PATH", example_env)
    monkeypatch.setenv("LLM_PROVIDER", "custom_proxy")
    monkeypatch.setenv("LLM_MODEL", "gpt-5.4")
    monkeypatch.setenv("LLM_BASE_URL", "https://gmncode.cn/v1")

    snapshot = config.read_runtime_env_snapshot()

    assert snapshot["LLM_PROVIDER"] == "custom_proxy"
    assert snapshot["LLM_MODEL"] == "gpt-5.4"
    assert snapshot["LLM_BASE_URL"] == "https://gmncode.cn/v1"
    assert config.read_runtime_env_value("LLM_PROVIDER", "mock") == "custom_proxy"
