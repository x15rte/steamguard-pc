import time

import requests


QUERY_TIME_URL = "https://api.steampowered.com/ITwoFactorService/QueryTime/v1/"
REQUEST_TIMEOUT = 30


class SteamTimeError(RuntimeError):
    pass


class SteamTimeTransportError(SteamTimeError):
    pass


def query_steam_time(http: requests.Session | None = None) -> int:
    client = http or requests.Session()
    try:
        response = client.post(QUERY_TIME_URL, data={}, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
    except requests.exceptions.RequestException as exc:
        raise SteamTimeTransportError("Steam time request failed") from exc

    try:
        payload = response.json()
    except ValueError as exc:
        raise SteamTimeError("Steam time response is missing server_time") from exc
    if not isinstance(payload, dict):
        raise SteamTimeError("Steam time response is missing server_time")

    response_payload = payload.get("response", payload)
    server_time = response_payload.get("server_time") if isinstance(response_payload, dict) else None
    if server_time is None:
        raise SteamTimeError("Steam time response is missing server_time")
    return int(server_time)


def steam_time_offset(http: requests.Session | None = None, local_time: int | None = None) -> int:
    return query_steam_time(http) - int(local_time or time.time())
