import pytest

from steamguard_pc import storage


@pytest.fixture
def keyring_store(monkeypatch, tmp_path):
    store: dict[tuple[str, str], str] = {}

    class FakeKeyringBackend:
        pass


    def set_password(service: str, name: str, value: str) -> None:
        store[(service, name)] = value

    def get_password(service: str, name: str) -> str | None:
        return store.get((service, name))

    def delete_password(service: str, name: str) -> None:
        store.pop((service, name), None)

    monkeypatch.setenv("STEAMGUARDPC_CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr(storage.keyring, "get_keyring", lambda: FakeKeyringBackend())
    monkeypatch.setattr(storage.keyring, "set_password", set_password)
    monkeypatch.setattr(storage.keyring, "get_password", get_password)
    monkeypatch.setattr(storage.keyring, "delete_password", delete_password)
    return store
