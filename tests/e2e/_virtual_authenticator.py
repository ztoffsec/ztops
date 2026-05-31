"""Minimal in-process WebAuthn authenticator for end-to-end tests.

Implements just enough of the CTAP2 / WebAuthn spec to round-trip a
registration + authentication ceremony through the Duo `webauthn`
library's verifiers. Uses ES256 (ECDSA P-256), attestation format
"none" (no attStmt to validate), and tracks a single credential's
sign count across calls.

This file is in `tests/e2e/` so it is never importable from
application code. If a future change makes this useful as a fixture
helper somewhere else, refactor — don't import from tests/.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass, field
from typing import Any

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

# WebAuthn authData flag bits.
_FLAG_UP = 0b00000001  # User present
_FLAG_UV = 0b00000100  # User verified
_FLAG_AT = 0b01000000  # Attested credential data included

# COSE Key labels for an ES256 EC2 public key.
# https://www.iana.org/assignments/cose/cose.xhtml
_COSE_KTY = 1
_COSE_ALG = 3
_COSE_CRV = -1
_COSE_X = -2
_COSE_Y = -3
_COSE_KTY_EC2 = 2
_COSE_ALG_ES256 = -7
_COSE_CRV_P256 = 1


def _b64u(data: bytes) -> str:
    """URL-safe base64 without padding — the WebAuthn wire format."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _build_cose_es256(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """Serialize a P-256 public key as a CTAP2-canonical COSE_Key map."""
    numbers = public_key.public_numbers()
    x_bytes = numbers.x.to_bytes(32, "big")
    y_bytes = numbers.y.to_bytes(32, "big")
    cose: dict[int, Any] = {
        _COSE_KTY: _COSE_KTY_EC2,
        _COSE_ALG: _COSE_ALG_ES256,
        _COSE_CRV: _COSE_CRV_P256,
        _COSE_X: x_bytes,
        _COSE_Y: y_bytes,
    }
    return cbor2.dumps(cose, canonical=True)


@dataclass
class _Credential:
    """Per-credential state held by the virtual authenticator."""

    credential_id: bytes
    private_key: ec.EllipticCurvePrivateKey
    sign_count: int = 0
    # The user id we registered against. Stored like a resident-key so
    # `.get()` can echo it back as `userHandle` (the usernameless flow
    # binds identity through this field).
    user_id: bytes = b""


@dataclass
class VirtualAuthenticator:
    """A software-only WebAuthn authenticator suitable for tests.

    Produces payloads in the exact shape the browser POSTs to the server
    (`{id, rawId, type, response: {clientDataJSON, attestationObject /
    authenticatorData, signature, ...}}`). Each helper takes the SAME
    parameters the lib used to generate the options on the server side,
    so a test reads server-side options, hands them here, and POSTs the
    result back.
    """

    aaguid: bytes = b"\x00" * 16
    transports: list[str] = field(default_factory=lambda: ["internal"])
    credentials: dict[bytes, _Credential] = field(default_factory=dict)

    def create(
        self,
        *,
        rp_id: str,
        challenge: bytes,
        user_id: bytes,
        origin: str,
    ) -> dict[str, Any]:
        """Mint a fresh credential, return the registration payload."""
        private_key = ec.generate_private_key(ec.SECP256R1())
        credential_id = secrets.token_bytes(32)

        self.credentials[credential_id] = _Credential(
            credential_id=credential_id,
            private_key=private_key,
            sign_count=0,
            user_id=user_id,
        )

        cose_pubkey = _build_cose_es256(private_key.public_key())

        # authData = rpIdHash | flags | signCount | attestedCredentialData
        rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
        flags = _FLAG_UP | _FLAG_UV | _FLAG_AT
        sign_count_bytes = (0).to_bytes(4, "big")
        cred_id_len = len(credential_id).to_bytes(2, "big")
        attested_cred_data = self.aaguid + cred_id_len + credential_id + cose_pubkey
        auth_data = rp_id_hash + bytes([flags]) + sign_count_bytes + attested_cred_data

        # attestationObject (fmt: "none" needs an empty attStmt).
        attestation_object = cbor2.dumps(
            {
                "fmt": "none",
                "attStmt": {},
                "authData": auth_data,
            },
            canonical=True,
        )

        client_data = json.dumps(
            {
                "type": "webauthn.create",
                "challenge": _b64u(challenge),
                "origin": origin,
                "crossOrigin": False,
            },
            separators=(",", ":"),
            sort_keys=False,
        ).encode("utf-8")

        return {
            "id": _b64u(credential_id),
            "rawId": _b64u(credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": _b64u(client_data),
                "attestationObject": _b64u(attestation_object),
                "transports": list(self.transports),
            },
            "clientExtensionResults": {},
        }

    def get(
        self,
        *,
        rp_id: str,
        challenge: bytes,
        origin: str,
        credential_id: bytes | None = None,
    ) -> dict[str, Any]:
        """Sign a challenge with the (chosen, or first) credential."""
        if credential_id is None:
            credential_id = next(iter(self.credentials))
        cred = self.credentials[credential_id]
        cred.sign_count += 1

        rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
        flags = _FLAG_UP | _FLAG_UV
        sign_count_bytes = cred.sign_count.to_bytes(4, "big")
        auth_data = rp_id_hash + bytes([flags]) + sign_count_bytes

        client_data = json.dumps(
            {
                "type": "webauthn.get",
                "challenge": _b64u(challenge),
                "origin": origin,
                "crossOrigin": False,
            },
            separators=(",", ":"),
            sort_keys=False,
        ).encode("utf-8")
        client_data_hash = hashlib.sha256(client_data).digest()

        # ECDSA signature over `authenticatorData || sha256(clientDataJSON)`.
        signature = cred.private_key.sign(
            auth_data + client_data_hash,
            ec.ECDSA(hashes.SHA256()),
        )

        return {
            "id": _b64u(credential_id),
            "rawId": _b64u(credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": _b64u(client_data),
                "authenticatorData": _b64u(auth_data),
                "signature": _b64u(signature),
                # Resident credential: echo the registered user id back as
                # the userHandle, the way a real authenticator does in the
                # usernameless flow.
                "userHandle": _b64u(cred.user_id) if cred.user_id else None,
            },
            "clientExtensionResults": {},
        }
