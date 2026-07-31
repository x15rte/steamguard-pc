from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class AccountMetadata:
    steamid64: str
    account_name: str | None = None
    device_id: str | None = None
    last_imported_at: str | None = None


@dataclass(frozen=True)
class ImportedSteamGuard:
    account_name: str | None
    steamid64: str
    shared_secret: str
    identity_secret: str
    revocation_code: str | None = None
    device_id: str | None = None
    refresh_token: str | None = None
    access_token: str | None = None
    steam_login_secure: str | None = None
    sessionid: str | None = None
    serial_number: str | None = None
    token_gid: str | None = None
    uri: str | None = None


@dataclass(frozen=True)
class Confirmation:
    id: str
    nonce: str
    creator_id: str | None = None
    type: str | int | None = None
    type_name: str | None = None
    headline: str | None = None
    summary: str | list[str] | None = None
    creation_time: int | None = None
    raw: dict[str, Any] = field(default_factory=dict)
