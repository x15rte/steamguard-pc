import sys

import pytest

if sys.platform != "win32":
    pytest.skip("Windows msvcrt lock", allow_module_level=True)

from steamguard_pc import operation_lock

STEAMID64 = "76561197960287930"


def test_account_operation_lock_blocks_second_lock(monkeypatch, tmp_path):
    monkeypatch.setenv("STEAMGUARDPC_CONFIG_DIR", str(tmp_path))
    expected = f"another SteamGuardPC operation is already running for {STEAMID64}"

    with operation_lock.account_operation_lock(STEAMID64):
        with pytest.raises(operation_lock.OperationLockError) as excinfo:
            with operation_lock.account_operation_lock(STEAMID64):
                pass

    assert str(excinfo.value) == expected


def test_lock_path_uses_config_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("STEAMGUARDPC_CONFIG_DIR", str(tmp_path))

    assert operation_lock.lock_path(STEAMID64) == tmp_path / "locks" / f"{STEAMID64}.lock"
