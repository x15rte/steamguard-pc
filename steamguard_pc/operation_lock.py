from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
import msvcrt

from . import storage

LOCK_BYTES = 1


class OperationLockError(RuntimeError):
    pass


def lock_path(steamid64: str) -> Path:
    steamid64 = storage.validate_steamid64(steamid64)
    return storage.config_dir() / "locks" / f"{steamid64}.lock"


@contextmanager
def account_operation_lock(steamid64: str) -> Generator[None, None, None]:
    path = lock_path(steamid64)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        handle.seek(0)
        try:
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, LOCK_BYTES)
        except OSError as exc:
            raise OperationLockError(f"another steamguard-pc operation is already running for {steamid64}") from exc
        try:
            yield
        finally:
            handle.seek(0)
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, LOCK_BYTES)
            except OSError:
                pass
