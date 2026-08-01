import sys

import pytest

if sys.platform != "win32":
    pytest.skip("Windows msvcrt lock", allow_module_level=True)

from steamguard_pc import operation_lock

STEAMID64 = "76561197960287930"


def test_account_operation_lock_blocks_second_lock(monkeypatch, tmp_path):
    monkeypatch.setenv("STEAMGUARD_PC_CONFIG_DIR", str(tmp_path))
    expected = f"another steamguard-pc operation is already running for {STEAMID64}"

    with operation_lock.account_operation_lock(STEAMID64):
        with pytest.raises(operation_lock.OperationLockError) as excinfo:
            with operation_lock.account_operation_lock(STEAMID64):
                pass

    assert str(excinfo.value) == expected


def test_lock_path_uses_config_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("STEAMGUARD_PC_CONFIG_DIR", str(tmp_path))

    assert operation_lock.lock_path(STEAMID64) == tmp_path / "locks" / f"{STEAMID64}.lock"


@pytest.mark.parametrize(
    "steamid64",
    [
        "..\\..\\evil",
        "76561197960287930/../x",
        "abc",
        "",
        "１２３４５６７８９０１２３４５６",
        "1" * 21,
    ],
)
def test_lock_path_rejects_invalid_steamid64(steamid64):
    with pytest.raises(ValueError, match="invalid SteamID64"):
        operation_lock.lock_path(steamid64)


def test_account_operation_lock_rejects_traversal_before_creating_files(monkeypatch, tmp_path):
    monkeypatch.setenv("STEAMGUARD_PC_CONFIG_DIR", str(tmp_path))

    with pytest.raises(ValueError, match="invalid SteamID64"):
        with operation_lock.account_operation_lock("..\\..\\evil"):
            pass

    assert not (tmp_path / "locks").exists()
    assert not list(tmp_path.rglob("evil.lock"))
