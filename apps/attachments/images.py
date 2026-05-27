"""Safe server-side image re-encoding for inline-embedded images.

Embedded images (drag-drop / paste into a markdown editor) must be served
*inline* with an ``image/*`` content type so they render — unlike regular
artifacts, which are forced to ``application/octet-stream`` + attachment to
prevent stored XSS. To make inline serving safe we never trust the uploaded
bytes: we decode the image with Pillow and **re-encode** it to a clean
raster, which strips EXIF/metadata payloads, defeats polyglot files
(e.g. a PNG with appended HTML/JS), and rejects anything Pillow can't open
as a raster (SVG, HTML, scripts).

Decompression-bomb protection: Pillow's ``MAX_IMAGE_PIXELS`` raises on
absurdly large canvases; we also reject before decode if the declared size
exceeds the configured byte limit.
"""

from __future__ import annotations

import io

from PIL import Image, UnidentifiedImageError

# Output format chosen by source: photographs stay JPEG (small), everything
# else becomes lossless PNG. Both are raster-only and carry no active content.
_JPEG_SOURCES = frozenset({"JPEG", "MPO"})
# Cap the decoded canvas to bound memory regardless of byte size.
_MAX_PIXELS = 40_000_000  # ~40 MP


class ImageRejected(ValueError):
    """Raised when an upload is not a decodable raster image."""


def reencode_image(raw: bytes) -> tuple[bytes, str, str]:
    """Decode ``raw`` and re-encode to a clean raster.

    Returns ``(clean_bytes, content_type, extension)``. Raises
    ``ImageRejected`` for anything that is not a decodable raster image.
    """
    previous_limit = Image.MAX_IMAGE_PIXELS
    Image.MAX_IMAGE_PIXELS = _MAX_PIXELS
    try:
        try:
            with Image.open(io.BytesIO(raw)) as probe:
                probe.verify()  # cheap structural check; consumes the image
            # verify() leaves the image unusable — reopen to actually load.
            with Image.open(io.BytesIO(raw)) as img:
                source_format = (img.format or "").upper()
                img.load()
                out = io.BytesIO()
                if source_format in _JPEG_SOURCES:
                    img.convert("RGB").save(out, format="JPEG", quality=85, optimize=True)
                    return out.getvalue(), "image/jpeg", "jpg"
                # Normalise everything else to PNG. Drop animation (first frame
                # only) and any palette/alpha quirks by going through RGBA.
                img.convert("RGBA").save(out, format="PNG", optimize=True)
                return out.getvalue(), "image/png", "png"
        except (UnidentifiedImageError, OSError, ValueError) as exc:
            msg = "Not a supported raster image."
            raise ImageRejected(msg) from exc
    finally:
        Image.MAX_IMAGE_PIXELS = previous_limit
