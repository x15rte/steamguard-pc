import struct
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal


WireType = Literal["varint", "fixed64", "length", "fixed32"]


@dataclass(frozen=True)
class Field:
    number: int
    name: str
    wire_type: WireType
    repeated: bool = False
    message: Mapping[int, "Field"] | None = None


def _encode_varint(value: int) -> bytes:
    if value < 0:
        value += 1 << 64
    output = bytearray()
    while value >= 0x80:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def _decode_varint(data: bytes, offset: int) -> tuple[int, int]:
    shift = 0
    value = 0
    while True:
        if offset >= len(data):
            raise ValueError("truncated protobuf varint")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7
        if shift >= 70:
            raise ValueError("invalid protobuf varint")


def _field_key(number: int, wire_type: int) -> bytes:
    return _encode_varint((number << 3) | wire_type)


def _encode_length_delimited(number: int, value: bytes) -> bytes:
    return _field_key(number, 2) + _encode_varint(len(value)) + value


def encode_message(fields: Sequence[tuple[int, WireType, Any]]) -> bytes:
    output = bytearray()
    for number, wire_type, value in fields:
        if value is None:
            continue
        if isinstance(value, bool):
            value = int(value)
        if wire_type == "varint":
            output += _field_key(number, 0)
            output += _encode_varint(int(value))
        elif wire_type == "fixed64":
            output += _field_key(number, 1)
            output += struct.pack("<Q", int(value))
        elif wire_type == "length":
            if isinstance(value, str):
                raw = value.encode("utf-8")
            else:
                raw = bytes(value)
            output += _encode_length_delimited(number, raw)
        elif wire_type == "fixed32":
            output += _field_key(number, 5)
            output += struct.pack("<f", float(value))
        else:
            raise ValueError(f"unsupported protobuf wire type: {wire_type}")
    return bytes(output)


def encode_nested(number: int, fields: Sequence[tuple[int, WireType, Any]]) -> tuple[int, WireType, bytes]:
    return number, "length", encode_message(fields)


def decode_message(data: bytes, descriptor: Mapping[int, Field]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    offset = 0
    while offset < len(data):
        key, offset = _decode_varint(data, offset)
        number = key >> 3
        wire_type = key & 0x07
        field = descriptor.get(number)

        if wire_type == 0:
            value, offset = _decode_varint(data, offset)
        elif wire_type == 1:
            if offset + 8 > len(data):
                raise ValueError("truncated protobuf fixed64")
            value = struct.unpack("<Q", data[offset : offset + 8])[0]
            offset += 8
        elif wire_type == 2:
            length, offset = _decode_varint(data, offset)
            if offset + length > len(data):
                raise ValueError("truncated protobuf length-delimited field")
            raw = data[offset : offset + length]
            offset += length
            if field and field.message is not None:
                value = decode_message(raw, field.message)
            elif field and field.wire_type == "length":
                try:
                    value = raw.decode("utf-8")
                except UnicodeDecodeError:
                    value = raw
            else:
                value = raw
        elif wire_type == 5:
            if offset + 4 > len(data):
                raise ValueError("truncated protobuf fixed32")
            value = struct.unpack("<f", data[offset : offset + 4])[0]
            offset += 4
        else:
            raise ValueError(f"unsupported protobuf wire type: {wire_type}")

        if not field:
            continue
        if field.repeated:
            output.setdefault(field.name, []).append(value)
        else:
            output[field.name] = value
    return output
