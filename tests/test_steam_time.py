import pytest
import requests

from steamguard_pc import steam_time


def test_query_steam_time_accepts_nested_server_time(requests_mock):
    requests_mock.post(steam_time.QUERY_TIME_URL, json={"response": {"server_time": "1700000000"}})

    assert steam_time.query_steam_time(requests.Session()) == 1700000000


def test_query_steam_time_accepts_flat_server_time(requests_mock):
    requests_mock.post(steam_time.QUERY_TIME_URL, json={"server_time": 1700000001})

    assert steam_time.query_steam_time(requests.Session()) == 1700000001


def test_steam_time_offset_uses_local_time(requests_mock):
    requests_mock.post(steam_time.QUERY_TIME_URL, json={"server_time": 1700000030})

    assert steam_time.steam_time_offset(requests.Session(), local_time=1700000000) == 30


def test_query_steam_time_maps_transport_errors(requests_mock):
    requests_mock.post(steam_time.QUERY_TIME_URL, status_code=500)

    with pytest.raises(steam_time.SteamTimeTransportError, match="^Steam time request failed$"):
        steam_time.query_steam_time(requests.Session())


def test_query_steam_time_rejects_missing_server_time(requests_mock):
    requests_mock.post(steam_time.QUERY_TIME_URL, json={"response": {}})

    with pytest.raises(steam_time.SteamTimeError, match="^Steam time response is missing server_time$"):
        steam_time.query_steam_time(requests.Session())
