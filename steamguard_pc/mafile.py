import json
import os
from collections.abc import Sequence
from json import JSONDecodeError
from pathlib import Path
from typing import Any

from .crypto import generate_device_id, validate_base64_secret
from .models import ImportedSteamGuard


_CLOUD_SYNC_DIRS = {
    "onedrive",
    "dropbox",
    "google drive",
    "googledrive",
    "iclouddrive",
    "icloud photos",
}


def default_mafile_search_dirs() -> list[Path]:
    roots: list[Path] = []
    appdata = os.environ.get("APPDATA")
    if appdata:
        sda_root = Path(appdata) / "Steam Desktop Authenticator"
        roots.extend([sda_root / "maFiles", sda_root])
    else:
        roots.append(Path.home() / "AppData" / "Roaming" / "Steam Desktop Authenticator" / "maFiles")

    roots.append(Path.cwd() / "maFiles")

    unique_roots: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        key = str(root).casefold()
        if key not in seen:
            seen.add(key)
            unique_roots.append(root)
    return unique_roots


def find_mafile_candidates(search_dirs: Sequence[str | Path] | None = None) -> list[Path]:
    roots = [Path(path).expanduser() for path in (search_dirs or default_mafile_search_dirs())]
    candidates: list[Path] = []
    seen: set[str] = set()

    def add_candidate(candidate: Path) -> None:
        try:
            resolved = candidate.resolve()
        except OSError:
            resolved = candidate.absolute()
        key = str(resolved).casefold()
        if key not in seen:
            seen.add(key)
            candidates.append(resolved)

    for root in roots:
        try:
            if root.is_file() and root.suffix.casefold() == ".mafile":
                add_candidate(root)
            elif root.is_dir():
                for candidate in root.rglob("*"):
                    if candidate.is_file() and candidate.suffix.casefold() == ".mafile":
                        add_candidate(candidate)
        except OSError:
            continue

    return sorted(candidates, key=lambda path: str(path).casefold())


def _optional_str(value: object) -> str | None:
    if isinstance(value, str) and value:
        return value
    return None


def _steamid64_from(raw: dict[str, object]) -> str:
    session = raw.get("Session")
    session_dict = session if isinstance(session, dict) else {}

    if "steamid" in raw:
        value = raw["steamid"]
    elif "SteamID" in raw:
        value = raw["SteamID"]
    elif "SteamID" in session_dict:
        value = session_dict["SteamID"]
    else:
        value = ""

    steamid64 = str(value)
    if not steamid64.isdecimal() or len(steamid64) < 16:
        raise ValueError("missing SteamID64")
    return steamid64


def parse_mafile(raw: dict[str, object]) -> ImportedSteamGuard:
    steamid64 = _steamid64_from(raw)

    shared_secret = raw.get("shared_secret")
    if not isinstance(shared_secret, str) or not shared_secret:
        raise ValueError("missing shared_secret")

    identity_secret = raw.get("identity_secret")
    if not isinstance(identity_secret, str) or not identity_secret:
        raise ValueError("missing identity_secret")

    validate_base64_secret(shared_secret, "shared_secret")
    validate_base64_secret(identity_secret, "identity_secret")

    session = raw.get("Session")
    session_dict: dict[str, Any] = session if isinstance(session, dict) else {}

    account_name = _optional_str(raw.get("account_name")) or _optional_str(raw.get("AccountName"))
    device_id = _optional_str(raw.get("device_id")) or generate_device_id(steamid64)

    return ImportedSteamGuard(
        account_name=account_name,
        steamid64=steamid64,
        shared_secret=shared_secret,
        identity_secret=identity_secret,
        revocation_code=_optional_str(raw.get("revocation_code")),
        device_id=device_id,
        refresh_token=_optional_str(session_dict.get("RefreshToken")),
        access_token=_optional_str(session_dict.get("AccessToken")),
        steam_login_secure=(
            _optional_str(session_dict.get("SteamLoginSecure"))
            or _optional_str(session_dict.get("steamLoginSecure"))
        ),
        sessionid=_optional_str(session_dict.get("SessionID"))
        or _optional_str(session_dict.get("sessionid")),
        serial_number=_optional_str(raw.get("serial_number")) or _optional_str(raw.get("SerialNumber")),
        token_gid=_optional_str(raw.get("token_gid")) or _optional_str(raw.get("TokenGID")),
        uri=_optional_str(raw.get("uri")) or _optional_str(raw.get("URI")),
    )


def load_mafile(path: str | Path) -> ImportedSteamGuard:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except JSONDecodeError as exc:
        raise ValueError(
            "encrypted or unsupported .maFile; decrypt it in the source app and retry"
        ) from exc

    if not isinstance(raw, dict):
        raise ValueError("unsupported .maFile format")

    return parse_mafile(raw)


def unsafe_import_path_warnings(path: str | Path) -> list[str]:
    selected = Path(path).expanduser()
    try:
        selected = selected.resolve()
    except OSError:
        selected = selected.absolute()

    warnings: list[str] = []
    for parent in (selected.parent, *selected.parents):
        if (parent / ".git").exists():
            warnings.append("Selected .maFile is under a Git checkout; do not commit authenticator secrets.")
            break

    parts = {part.casefold() for part in selected.parts}
    if "downloads" in parts:
        warnings.append("Selected .maFile is under Downloads; move it to a private folder after import.")

    cloud_parts = parts & _CLOUD_SYNC_DIRS
    if cloud_parts:
        warnings.append("Selected .maFile is under a cloud-sync folder; avoid syncing authenticator secrets.")

    return warnings
