import binascii
import struct
import unittest
import zlib

from app.cleaner import CleanerError, clean_file, inspect_file


def png_chunk(chunk_type, payload):
    crc = binascii.crc32(chunk_type + payload) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + chunk_type + payload + struct.pack(">I", crc)


def sample_png():
    signature = b"\x89PNG\r\n\x1a\n"
    ihdr = png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    provenance = png_chunk(b"caBX", b"c2pa test manifest")
    pixels = png_chunk(b"IDAT", zlib.compress(b"\x00\xff\xff\xff"))
    iend = png_chunk(b"IEND", b"")
    return signature + ihdr + provenance + pixels + iend


def sample_jpeg():
    app11_payload = b"c2pa test manifest"
    app11 = b"\xff\xeb" + struct.pack(">H", len(app11_payload) + 2) + app11_payload
    sos = b"\xff\xda\x00\x02\x00\xff\xd9"
    return b"\xff\xd8" + app11 + sos


def webp_chunk(chunk_type, payload):
    padding = b"\x00" if len(payload) % 2 else b""
    return chunk_type + struct.pack("<I", len(payload)) + payload + padding


def sample_webp():
    vp8x = webp_chunk(b"VP8X", bytes([0x0C]) + b"\x00" * 9)
    image = webp_chunk(b"VP8 ", b"pixel-stream")
    exif = webp_chunk(b"EXIF", b"camera metadata")
    xmp = webp_chunk(b"XMP ", b"c2pa xmp metadata")
    body = b"WEBP" + vp8x + image + exif + xmp
    return b"RIFF" + struct.pack("<I", len(body)) + body


class CleanerTests(unittest.TestCase):
    def test_png_inspect_and_clean(self):
        original = sample_png()
        kind, metadata = inspect_file("quote.png", original)
        self.assertEqual(kind, "png")
        self.assertEqual(len(metadata), 1)
        self.assertEqual(metadata[0].type, "caBX")
        self.assertTrue(metadata[0].ai_related)

        clean_kind, cleaned, removed = clean_file("quote.png", original)
        self.assertEqual(clean_kind, "png")
        self.assertEqual(len(removed), 1)
        self.assertNotIn(b"caBX", cleaned)
        self.assertIn(b"IDAT", cleaned)
        _kind, remaining = inspect_file("quote.png", cleaned)
        self.assertEqual(remaining, [])

    def test_rejects_unsupported_files(self):
        with self.assertRaises(CleanerError):
            inspect_file("notes.pdf", b"%PDF-1.7")

    def test_jpeg_removes_app11_without_touching_scan(self):
        original = sample_jpeg()
        _kind, metadata = inspect_file("photo.jpg", original)
        self.assertEqual([item.type for item in metadata], ["APP11_JUMBF_C2PA"])
        _kind, cleaned, removed = clean_file("photo.jpg", original)
        self.assertEqual(len(removed), 1)
        self.assertNotIn(b"c2pa test manifest", cleaned)
        self.assertTrue(cleaned.endswith(b"\xff\xda\x00\x02\x00\xff\xd9"))

    def test_webp_removes_metadata_and_updates_vp8x_flags(self):
        original = sample_webp()
        _kind, metadata = inspect_file("photo.webp", original)
        self.assertEqual({item.type for item in metadata}, {"EXIF", "XMP "})
        _kind, cleaned, removed = clean_file("photo.webp", original)
        self.assertEqual(len(removed), 2)
        self.assertNotIn(b"EXIF", cleaned)
        self.assertNotIn(b"XMP ", cleaned)
        vp8x_offset = cleaned.index(b"VP8X")
        self.assertEqual(cleaned[vp8x_offset + 8], 0)


if __name__ == "__main__":
    unittest.main()
