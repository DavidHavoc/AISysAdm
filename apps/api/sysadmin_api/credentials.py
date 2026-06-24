from __future__ import annotations

import hashlib
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, List, Optional
from uuid import uuid4

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .models import SshCredential, utc_now
from .repository import Repository


class CredentialService:
    """Encrypts SSH key material at rest and exposes short-lived worker files."""

    def __init__(self, repository: Repository, encryption_key: bytes) -> None:
        if len(encryption_key) != 32:
            raise ValueError("Credential encryption key must be 32 bytes")
        self.repository = repository
        self.cipher = AESGCM(encryption_key)

    def save_private_key(self, name: str, content: bytes) -> SshCredential:
        if b"PRIVATE KEY" not in content:
            raise ValueError("Uploaded file does not look like a private SSH key")
        if len(content) > 1024 * 1024:
            raise ValueError("SSH private key file is too large")
        credential_id = "credential-%s" % uuid4().hex[:12]
        nonce = os.urandom(12)
        encrypted = self.cipher.encrypt(nonce, content, credential_id.encode("utf-8"))
        credential = SshCredential(
            id=credential_id,
            name=name,
            fingerprint=hashlib.sha256(content).hexdigest()[:24],
            created_at=utc_now(),
        )
        return self.repository.save_credential(credential, encrypted, nonce)

    def list_credentials(self) -> List[SshCredential]:
        return self.repository.list_credentials()

    def delete_credential(self, credential_id: str) -> None:
        attached_hosts = [
            host
            for host in self.repository.list_hosts()
            if host.credential_id == credential_id
        ]
        if attached_hosts:
            names = ", ".join(sorted(host.name for host in attached_hosts))
            raise ValueError(
                "Credential is still assigned to host(s): %s. Remove it from those "
                "hosts before deleting the credential." % names
            )
        self.repository.delete_credential(credential_id)

    def _decrypt_private_key(self, credential_id: str) -> bytes:
        record = self.repository.get_credential_record(credential_id)
        if not record:
            raise ValueError("SSH credential not found")
        _, encrypted, nonce = record
        return self.cipher.decrypt(
            nonce,
            encrypted,
            credential_id.encode("utf-8"),
        )

    @contextmanager
    def temporary_key(self, credential_id: Optional[str]) -> Iterator[Path]:
        if not credential_id:
            raise ValueError("Host has no SSH credential")
        content = self._decrypt_private_key(credential_id)
        file_descriptor, raw_path = tempfile.mkstemp(prefix="ai-sysadm-key-")
        path = Path(raw_path)
        try:
            os.fchmod(file_descriptor, 0o600)
            with os.fdopen(file_descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            yield path
        finally:
            try:
                if path.exists():
                    path.write_bytes(b"\x00" * path.stat().st_size)
                    path.unlink()
            except OSError:
                path.unlink(missing_ok=True)
