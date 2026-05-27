"""File storage for Finding artifacts.

Files live OUTSIDE Django's MEDIA_ROOT (per hardening req #8) so
the static-files plumbing can never serve them. Every read goes through
an authenticated Django view.

Layout:
    {ATTACHMENTS_ROOT}/{finding_id}/{sha256}

Content-addressed by sha256 so identical bytes uploaded twice de-dup
on disk. Original filename + content type are kept in the DB row;
the on-disk file name carries no user-controlled string.
"""

from __future__ import annotations

import hashlib
import re
import shutil
from pathlib import Path
from typing import TYPE_CHECKING

from django.conf import settings

if TYPE_CHECKING:
    from django.core.files.uploadedfile import UploadedFile


# Allowlist of filename characters. We re-derive a safe display name
# from the upload's filename so users can still recognise their files
# in the UI, but the on-disk path is the sha256.
_FILENAME_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")


def safe_display_name(raw: str) -> str:
    """Strip directory components and dangerous chars from a user-supplied
    filename. Empty/blank → 'unnamed'."""
    base = Path(raw or "").name
    cleaned = _FILENAME_SAFE_RE.sub("_", base).strip("._")
    return cleaned[:255] or "unnamed"


def _root() -> Path:
    root = Path(settings.ATTACHMENTS_ROOT)
    root.mkdir(parents=True, exist_ok=True)
    return root


def _bucket(finding_id: str) -> Path:
    bucket = _root() / str(finding_id)
    bucket.mkdir(parents=True, exist_ok=True)
    return bucket


def hash_and_store(upload: UploadedFile, finding_id: str) -> tuple[str, Path, int]:
    """Stream the upload to a temp path under the finding's bucket while
    computing sha256, then rename to the final content-addressed name.

    Returns (sha256_hex, final_path, bytes_written).
    """
    bucket = _bucket(finding_id)
    # Short tmp-file suffix to avoid concurrent-upload collisions; the
    # hash is purely a name generator, not a security primitive (the
    # final on-disk name is the real content sha256 from `sha` below).
    tmp = bucket / f".tmp-{hashlib.sha256(upload.name.encode()).hexdigest()[:16]}"
    sha = hashlib.sha256()
    bytes_written = 0
    try:
        with tmp.open("wb") as fh:
            for chunk in upload.chunks():
                sha.update(chunk)
                fh.write(chunk)
                bytes_written += len(chunk)
        digest = sha.hexdigest()
        final = bucket / digest
        if final.exists():
            tmp.unlink()
        else:
            tmp.rename(final)
        return digest, final, bytes_written
    except Exception:
        if tmp.exists():
            tmp.unlink(missing_ok=True)
        raise


def path_for(finding_id: str, sha256: str) -> Path:
    """Return the on-disk path for a stored attachment."""
    return _bucket(finding_id) / sha256


def store_from_path(src: Path, finding_id: str) -> tuple[str, Path, int]:
    """Hash + copy a file from disk into the finding's attachment bucket.

    Returns (sha256_hex, final_path, bytes_written). De-dups: if the
    sha256-named destination already exists, no copy happens.
    """
    bucket = _bucket(finding_id)
    sha = hashlib.sha256()
    bytes_written = 0
    tmp = bucket / f".tmp-import-{src.name[:16]}"
    try:
        with src.open("rb") as fh_in, tmp.open("wb") as fh_out:
            while True:
                chunk = fh_in.read(64 * 1024)
                if not chunk:
                    break
                sha.update(chunk)
                fh_out.write(chunk)
                bytes_written += len(chunk)
        digest = sha.hexdigest()
        final = bucket / digest
        if final.exists():
            tmp.unlink()
        else:
            tmp.rename(final)
        return digest, final, bytes_written
    except Exception:
        if tmp.exists():
            tmp.unlink(missing_ok=True)
        raise


def store_bytes(data: bytes, finding_id: str) -> tuple[str, Path, int]:
    """Store an in-memory byte blob (e.g. a re-encoded image) content-addressed.

    Returns (sha256_hex, final_path, bytes_written). De-dups: if the
    sha256-named destination already exists, no write happens.
    """
    bucket = _bucket(finding_id)
    digest = hashlib.sha256(data).hexdigest()
    final = bucket / digest
    if not final.exists():
        tmp = bucket / f".tmp-bytes-{digest[:16]}"
        try:
            tmp.write_bytes(data)
            tmp.rename(final)
        except Exception:
            tmp.unlink(missing_ok=True)
            raise
    return digest, final, len(data)


def delete_blob(finding_id: str, sha256: str) -> None:
    """Remove the on-disk file. Idempotent — missing file is not an error."""
    target = path_for(finding_id, sha256)
    if target.exists():
        target.unlink()


def purge_finding_bucket(finding_id: str) -> None:
    """Remove every blob for a finding (called when the Finding is deleted)."""
    bucket = _root() / str(finding_id)
    if bucket.exists():
        shutil.rmtree(bucket, ignore_errors=True)
