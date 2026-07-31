import pytest

from steamguard_pc.crypto import (
    confirmation_key,
    generate_device_id,
    steam_totp,
    validate_base64_secret,
)


SHARED_SECRET = "MDEyMzQ1Njc4OWFiY2RlZmdoaWo="
IDENTITY_SECRET = "aWRlbnRpdHktc2VjcmV0LTEyMzQ="
STEAMID64 = "76561197960287930"


@pytest.mark.parametrize(
    ("timestamp", "expected"),
    [
        (0, "CX2MR"),
        (29, "CX2MR"),
        (30, "57G3M"),
        (31, "57G3M"),
        (1700000000, "C96G3"),
        (1700000029, "JGGKH"),
        (1700000030, "JGGKH"),
    ],
)
def test_steam_totp_matches_deterministic_fixtures(timestamp, expected):
    assert steam_totp(SHARED_SECRET, timestamp) == expected


@pytest.mark.parametrize(
    ("tag", "expected"),
    [
        ("conf", "6eXMXFho61EmjoiIvP/WlyItlCU="),
        ("list", "43vC3oBlbDh0ZI7+uZxuhTZNyeo="),
        ("allow", "m/CyWI2HN6Rf8GQWBeANc91afxo="),
        ("accept", "7OA8LfG6pJsWfVIZYl3So5TAslc="),
        ("cancel", "ovSyaVuSNsfuuu1+2OjZmxQDFlo="),
        ("reject", "gWWBsB1CkfuBS8H4Su/CsZyjHao="),
        ("details", "uAqZHEDskpFL2AOFSbIQ4/DrZ34="),
        ("detail", "tfFYzPMRksK8n2XMJmUarFt+i/0="),
    ],
)
def test_confirmation_key_matches_deterministic_fixtures(tag, expected):
    assert confirmation_key(IDENTITY_SECRET, tag, 1700000000) == (1700000000, expected)


def test_generate_device_id_matches_deterministic_fixture():
    assert generate_device_id(STEAMID64) == "android:6d3f10d9-6369-a1ae-97a0-94df28b95192"


@pytest.mark.parametrize("secret", ["", "not base64", object()])
def test_validate_base64_secret_rejects_invalid_values(secret):
    with pytest.raises(ValueError, match="^invalid shared_secret$"):
        validate_base64_secret(secret, "shared_secret")  # type: ignore[arg-type]


def test_confirmation_key_rejects_invalid_identity_secret():
    with pytest.raises(ValueError, match="^invalid identity_secret$"):
        confirmation_key("not base64", "conf", 1700000000)


@pytest.mark.parametrize("tag", ["", "confé"])
def test_confirmation_key_rejects_empty_or_non_ascii_tag(tag):
    with pytest.raises(ValueError, match="^confirmation tag must be non-empty ASCII$"):
        confirmation_key(IDENTITY_SECRET, tag, 1700000000)
