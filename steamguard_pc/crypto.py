import base64
import hashlib
import hmac
import struct
import time


STEAM_CHARS = "23456789BCDFGHJKMNPQRTVWXY"
PERIOD_SECONDS = 30


def _decode_base64_secret(secret_b64: str, field_name: str) -> bytes:
    validate_base64_secret(secret_b64, field_name)
    return base64.b64decode(secret_b64, validate=True)


def validate_base64_secret(secret_b64: str, field_name: str) -> None:
    if not isinstance(secret_b64, str) or not secret_b64:
        raise ValueError(f"invalid {field_name}")

    try:
        base64.b64decode(secret_b64, validate=True)
    except Exception as exc:
        raise ValueError(f"invalid {field_name}") from exc


def steam_totp(shared_secret_b64: str, timestamp: int | None = None) -> str:
    if timestamp is None:
        timestamp = int(time.time())

    secret = _decode_base64_secret(shared_secret_b64, "shared_secret")
    counter = int(timestamp) // PERIOD_SECONDS
    msg = struct.pack(">Q", counter)
    digest = hmac.new(secret, msg, hashlib.sha1).digest()

    offset = digest[19] & 0x0F
    code_int = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF

    code = []
    for _ in range(5):
        code_int, idx = divmod(code_int, len(STEAM_CHARS))
        code.append(STEAM_CHARS[idx])
    return "".join(code)


def confirmation_key(
    identity_secret_b64: str,
    tag: str,
    timestamp: int | None = None,
) -> tuple[int, str]:
    if not isinstance(tag, str) or not tag:
        raise ValueError("confirmation tag must be non-empty ASCII")

    try:
        tag_bytes = tag.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("confirmation tag must be non-empty ASCII") from exc

    if timestamp is None:
        timestamp = int(time.time())
    timestamp = int(timestamp)

    secret = _decode_base64_secret(identity_secret_b64, "identity_secret")
    payload = struct.pack(">Q", timestamp) + tag_bytes
    digest = hmac.new(secret, payload, hashlib.sha1).digest()
    return timestamp, base64.b64encode(digest).decode("ascii")


def generate_device_id(steamid64: str) -> str:
    digest = hashlib.sha1(str(steamid64).encode("ascii")).hexdigest()
    return "android:%s-%s-%s-%s-%s" % (
        digest[:8],
        digest[8:12],
        digest[12:16],
        digest[16:20],
        digest[20:32],
    )


def seconds_remaining(timestamp: int | None = None) -> int:
    if timestamp is None:
        timestamp = int(time.time())
    return PERIOD_SECONDS - (int(timestamp) % PERIOD_SECONDS)
