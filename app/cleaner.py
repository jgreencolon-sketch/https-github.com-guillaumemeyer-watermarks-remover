"""Deterministic metadata inspection and removal for common image containers.

The cleaner rewrites container structures without decoding or re-encoding image
pixels. It intentionally does not claim to remove pixel-domain watermarks.
"""

from __future__ import annotations

import binascii
import struct
from dataclasses import dataclass


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
JPEG_SIGNATURE = b"\xff\xd8\xff"
WEBP_SIGNATURE = b"RIFF"

PNG_METADATA_CHUNKS = {
    b"tEXt": "text",
    b"zTXt": "compressed_text",
    b"iTXt": "international_text",
    b"eXIf": "exif",
    b"tIME": "timestamp",
    b"caBX": "c2pa",
}
PNG_AI_CHUNKS = {b"caBX"}

JPEG_METADATA_MARKERS = {
    0xE1: "APP1_EXIF_XMP",
    0xEB: "APP11_JUMBF_C2PA",
    0xED: "APP13_IPTC",
    0xFE: "COMMENT",
}
JPEG_AI_MARKERS = {0xEB}

WEBP_METADATA_CHUNKS = {
    b"EXIF": "exif",
    b"XMP ": "xmp",
    b"JUMB": "jumbf_c2pa",
    b"C2PA": "c2pa",
}
WEBP_AI_CHUNKS = {b"JUMB", b"C2PA"}


class CleanerError(ValueError):
    """Raised when a file is unsupported or structurally invalid."""


@dataclass(frozen=True)
class MetadataItem:
    type: str
    bytes: int
    ai_related: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "type": self.type,
            "bytes": self.bytes,
            "ai_related": self.ai_related,
        }


def detect_kind(name: str, data: bytes) -> str:
    lower_name = name.lower()
    if data.startswith(PNG_SIGNATURE) or lower_name.endswith(".png"):
        return "png"
    if data.startswith(JPEG_SIGNATURE) or lower_name.endswith((".jpg", ".jpeg")):
        return "jpeg"
    if (
        len(data) >= 12
        and data.startswith(WEBP_SIGNATURE)
        and data[8:12] == b"WEBP"
    ) or lower_name.endswith(".webp"):
        return "webp"
    raise CleanerError("unsupported file type; supported formats are PNG, JPEG, and WebP")


def inspect_file(name: str, data: bytes) -> tuple[str, list[MetadataItem]]:
    kind = detect_kind(name, data)
    if kind == "png":
        return kind, _inspect_png(data)
    if kind == "jpeg":
        return kind, _inspect_jpeg(data)
    return kind, _inspect_webp(data)


def clean_file(
    name: str,
    data: bytes,
    *,
    keep_non_ai_metadata: bool = False,
) -> tuple[str, bytes, list[MetadataItem]]:
    kind = detect_kind(name, data)
    if kind == "png":
        cleaned, removed = _clean_png(data, keep_non_ai_metadata)
    elif kind == "jpeg":
        cleaned, removed = _clean_jpeg(data, keep_non_ai_metadata)
    else:
        cleaned, removed = _clean_webp(data, keep_non_ai_metadata)
    return kind, cleaned, removed


def _png_chunks(data: bytes):
    if not data.startswith(PNG_SIGNATURE):
        raise CleanerError("invalid PNG signature")
    offset = len(PNG_SIGNATURE)
    saw_iend = False
    while offset < len(data):
        if offset + 12 > len(data):
            raise CleanerError("truncated PNG chunk")
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        end = offset + 12 + length
        if end > len(data):
            raise CleanerError("PNG chunk length exceeds file size")
        chunk_type = data[offset + 4 : offset + 8]
        payload = data[offset + 8 : offset + 8 + length]
        stored_crc = struct.unpack(">I", data[offset + 8 + length : end])[0]
        computed_crc = binascii.crc32(chunk_type + payload) & 0xFFFFFFFF
        if stored_crc != computed_crc:
            raise CleanerError(f"invalid PNG CRC for {chunk_type.decode('latin1')}")
        raw = data[offset:end]
        yield chunk_type, payload, raw
        offset = end
        if chunk_type == b"IEND":
            saw_iend = True
            if offset != len(data):
                raise CleanerError("unexpected data after PNG IEND")
            break
    if not saw_iend:
        raise CleanerError("PNG is missing IEND")


def _inspect_png(data: bytes) -> list[MetadataItem]:
    items: list[MetadataItem] = []
    for chunk_type, payload, _raw in _png_chunks(data):
        if chunk_type in PNG_METADATA_CHUNKS:
            items.append(
                MetadataItem(
                    type=chunk_type.decode("ascii"),
                    bytes=len(payload),
                    ai_related=(
                        chunk_type in PNG_AI_CHUNKS or _contains_ai_marker(payload)
                    ),
                )
            )
    return items


def _clean_png(data: bytes, keep_non_ai: bool) -> tuple[bytes, list[MetadataItem]]:
    output = bytearray(PNG_SIGNATURE)
    removed: list[MetadataItem] = []
    for chunk_type, payload, raw in _png_chunks(data):
        is_metadata = chunk_type in PNG_METADATA_CHUNKS
        ai_related = chunk_type in PNG_AI_CHUNKS or _contains_ai_marker(payload)
        should_remove = is_metadata and (ai_related or not keep_non_ai)
        if should_remove:
            removed.append(
                MetadataItem(chunk_type.decode("ascii"), len(payload), ai_related)
            )
        else:
            output.extend(raw)
    return bytes(output), removed


def _jpeg_segments(data: bytes):
    if not data.startswith(b"\xff\xd8"):
        raise CleanerError("invalid JPEG signature")
    offset = 2
    yield 0xD8, b"", data[:2], 0, 2
    while offset < len(data):
        marker_start = offset
        if data[offset] != 0xFF:
            raise CleanerError("invalid JPEG marker stream")
        while offset < len(data) and data[offset] == 0xFF:
            offset += 1
        if offset >= len(data):
            raise CleanerError("truncated JPEG marker")
        marker = data[offset]
        offset += 1
        if marker == 0xDA:
            if offset + 2 > len(data):
                raise CleanerError("truncated JPEG SOS")
            length = struct.unpack(">H", data[offset : offset + 2])[0]
            if length < 2 or offset + length > len(data):
                raise CleanerError("invalid JPEG SOS length")
            yield marker, data[offset + 2 : offset + length], data[marker_start:], marker_start, len(data)
            return
        if marker == 0xD9:
            yield marker, b"", data[marker_start:offset], marker_start, offset
            return
        if marker in {0x01, *range(0xD0, 0xD8)}:
            yield marker, b"", data[marker_start:offset], marker_start, offset
            continue
        if offset + 2 > len(data):
            raise CleanerError("truncated JPEG segment")
        length = struct.unpack(">H", data[offset : offset + 2])[0]
        end = offset + length
        if length < 2 or end > len(data):
            raise CleanerError("invalid JPEG segment length")
        payload = data[offset + 2 : end]
        yield marker, payload, data[marker_start:end], marker_start, end
        offset = end
    raise CleanerError("JPEG ended before SOS or EOI")


def _inspect_jpeg(data: bytes) -> list[MetadataItem]:
    items: list[MetadataItem] = []
    for marker, payload, _raw, _start, _end in _jpeg_segments(data):
        if marker in JPEG_METADATA_MARKERS:
            ai_related = marker in JPEG_AI_MARKERS or _contains_ai_marker(payload)
            items.append(
                MetadataItem(JPEG_METADATA_MARKERS[marker], len(payload), ai_related)
            )
        if marker == 0xDA:
            break
    return items


def _clean_jpeg(data: bytes, keep_non_ai: bool) -> tuple[bytes, list[MetadataItem]]:
    output = bytearray()
    removed: list[MetadataItem] = []
    for marker, payload, raw, _start, _end in _jpeg_segments(data):
        is_metadata = marker in JPEG_METADATA_MARKERS
        ai_related = marker in JPEG_AI_MARKERS or _contains_ai_marker(payload)
        should_remove = is_metadata and (ai_related or not keep_non_ai)
        if should_remove:
            removed.append(
                MetadataItem(JPEG_METADATA_MARKERS[marker], len(payload), ai_related)
            )
        else:
            output.extend(raw)
        if marker in {0xDA, 0xD9}:
            break
    return bytes(output), removed


def _webp_chunks(data: bytes):
    if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        raise CleanerError("invalid WebP signature")
    declared_size = struct.unpack("<I", data[4:8])[0] + 8
    if declared_size > len(data):
        raise CleanerError("WebP RIFF size exceeds file size")
    offset = 12
    while offset + 8 <= declared_size:
        chunk_type = data[offset : offset + 4]
        length = struct.unpack("<I", data[offset + 4 : offset + 8])[0]
        payload_end = offset + 8 + length
        padded_end = payload_end + (length % 2)
        if padded_end > declared_size:
            raise CleanerError("WebP chunk length exceeds RIFF size")
        payload = data[offset + 8 : payload_end]
        yield chunk_type, payload, data[offset:padded_end]
        offset = padded_end
    if offset != declared_size:
        raise CleanerError("truncated WebP chunk header")


def _inspect_webp(data: bytes) -> list[MetadataItem]:
    items: list[MetadataItem] = []
    for chunk_type, payload, _raw in _webp_chunks(data):
        if chunk_type in WEBP_METADATA_CHUNKS:
            items.append(
                MetadataItem(
                    chunk_type.decode("ascii"),
                    len(payload),
                    chunk_type in WEBP_AI_CHUNKS or _contains_ai_marker(payload),
                )
            )
    return items


def _clean_webp(data: bytes, keep_non_ai: bool) -> tuple[bytes, list[MetadataItem]]:
    parsed_chunks = list(_webp_chunks(data))
    removal_decisions: dict[int, bool] = {}
    will_remove_exif = False
    will_remove_xmp = False
    for index, (chunk_type, payload, _raw) in enumerate(parsed_chunks):
        is_metadata = chunk_type in WEBP_METADATA_CHUNKS
        ai_related = chunk_type in WEBP_AI_CHUNKS or _contains_ai_marker(payload)
        should_remove = is_metadata and (ai_related or not keep_non_ai)
        removal_decisions[index] = should_remove
        will_remove_exif = will_remove_exif or (should_remove and chunk_type == b"EXIF")
        will_remove_xmp = will_remove_xmp or (should_remove and chunk_type == b"XMP ")

    chunks: list[bytes] = []
    removed: list[MetadataItem] = []
    for index, (chunk_type, payload, raw) in enumerate(parsed_chunks):
        is_metadata = chunk_type in WEBP_METADATA_CHUNKS
        ai_related = chunk_type in WEBP_AI_CHUNKS or _contains_ai_marker(payload)
        should_remove = removal_decisions[index]
        if should_remove:
            removed.append(MetadataItem(chunk_type.decode("ascii"), len(payload), ai_related))
            continue
        if chunk_type == b"VP8X" and len(payload) == 10 and (will_remove_exif or will_remove_xmp):
            flags = payload[0]
            if will_remove_exif:
                flags &= ~0x08
            if will_remove_xmp:
                flags &= ~0x04
            new_payload = bytes([flags]) + payload[1:]
            raw = _webp_chunk(chunk_type, new_payload)
        chunks.append(raw)
    body = b"WEBP" + b"".join(chunks)
    return b"RIFF" + struct.pack("<I", len(body)) + body, removed


def _webp_chunk(chunk_type: bytes, payload: bytes) -> bytes:
    padding = b"\x00" if len(payload) % 2 else b""
    return chunk_type + struct.pack("<I", len(payload)) + payload + padding


def _contains_ai_marker(payload: bytes) -> bool:
    lower = payload[:262_144].lower()
    markers = (
        b"c2pa",
        b"content credentials",
        b"contentcredentials",
        b"openai",
        b"synthid",
        b"generated with ai",
        b"ai generated",
    )
    return any(marker in lower for marker in markers)
