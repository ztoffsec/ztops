"""Views for the Artifacts feature on a Finding.

Permission rules mirror the Finding edit gating:
- Upload    → assigned researchers + superadmin (== Finding.can_user_edit)
- List      → any authenticated user (findings are viewable by all)
- Download  → any authenticated user
- Delete    → uploader of the attachment + superadmin

Files NEVER pass through static serving. The download view streams
bytes with Content-Type=application/octet-stream + Content-Disposition:
attachment regardless of the uploaded mime so a malicious .svg / .html
can't be rendered by the browser.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import FileResponse, Http404
from django.shortcuts import get_object_or_404, redirect
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_POST

from apps.findings.models import Finding

from .models import Attachment, ScanStatus
from .storage import delete_blob, hash_and_store, path_for, safe_display_name

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponse


def _can_delete(att: Attachment, user: object) -> bool:
    if not getattr(user, "is_authenticated", False):
        return False
    if getattr(user, "is_superadmin", False):
        return True
    return att.uploaded_by_id == user.pk


@login_required(login_url="/super/login/")
@csrf_protect
@require_POST
def upload(request: HttpRequest, finding_id: str) -> HttpResponse:
    finding = get_object_or_404(Finding, pk=finding_id)
    if not finding.can_user_edit(request.user):
        raise Http404

    upload_files = request.FILES.getlist("file")
    if not upload_files:
        messages.error(request, "Pick one or more files to upload.")
        return redirect(f"/findings/{finding.id}/?tab=artifacts")

    limit = settings.ATTACHMENTS_MAX_SIZE
    created = 0
    skipped_dupe = 0
    too_big: list[str] = []
    for upload_file in upload_files:
        if upload_file.size > limit:
            too_big.append(safe_display_name(upload_file.name))
            continue
        display = safe_display_name(upload_file.name)
        sha256, _path, bytes_written = hash_and_store(upload_file, str(finding.id))
        # Same bytes already attached to this finding → skip the duplicate row.
        if Attachment.objects.filter(finding=finding, sha256_hash=sha256).exists():
            skipped_dupe += 1
            continue
        Attachment.objects.create(
            finding=finding,
            filename=display,
            content_type=getattr(upload_file, "content_type", "") or "",
            size_bytes=bytes_written,
            sha256_hash=sha256,
            storage_path=str(path_for(str(finding.id), sha256)),
            uploaded_by=request.user,
            uploaded_by_email=request.user.email,
            # ClamAV wiring lands in Phase 5; SKIPPED makes the intent explicit.
            scan_status=ScanStatus.SKIPPED,
        )
        created += 1

    if created:
        messages.success(request, f"Uploaded {created} file{'s' if created != 1 else ''}.")
    if skipped_dupe:
        messages.warning(request, f"Skipped {skipped_dupe} already-attached file(s).")
    if too_big:
        mib = limit // (1024 * 1024)
        messages.error(request, f"Skipped (over {mib} MiB): {', '.join(too_big)}.")
    return redirect(f"/findings/{finding.id}/?tab=artifacts")


@login_required(login_url="/super/login/")
def download(request: HttpRequest, finding_id: str, attachment_id: str) -> HttpResponse:
    att = get_object_or_404(
        Attachment,
        pk=attachment_id,
        finding_id=finding_id,
    )
    # ZT-001: mirror the finding-visibility model on the download path.
    # Approved findings are downloadable by any authenticated researcher;
    # pending / under_review / rejected findings only by the reporter,
    # reviewers, and superadmins. 404 (not 403) so we never confirm the
    # attachment exists to an unauthorized user.
    if not att.finding.can_user_view(request.user):
        raise Http404
    target = path_for(str(att.finding_id), att.sha256_hash)
    if not target.exists():
        raise Http404
    # Stream the bytes. force application/octet-stream + attachment
    # disposition so the browser never renders the content.
    response = FileResponse(
        target.open("rb"),
        as_attachment=True,
        filename=att.filename,
        content_type="application/octet-stream",
    )
    response["X-Content-Type-Options"] = "nosniff"
    return response


@login_required(login_url="/super/login/")
@csrf_protect
@require_POST
def delete_attachment(
    request: HttpRequest,
    finding_id: str,
    attachment_id: str,
) -> HttpResponse:
    att = get_object_or_404(Attachment, pk=attachment_id, finding_id=finding_id)
    if not _can_delete(att, request.user):
        raise Http404
    sha = att.sha256_hash
    fid = str(att.finding_id)
    # Only delete the on-disk blob if no other Attachment row references it
    # (content-addressed dedup means the same sha could back another row).
    att.delete()
    if not Attachment.objects.filter(finding_id=fid, sha256_hash=sha).exists():
        delete_blob(fid, sha)
    messages.success(request, "Attachment removed.")
    return redirect(f"/findings/{finding_id}/?tab=artifacts")
