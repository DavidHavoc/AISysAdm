from __future__ import annotations

import hashlib
import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Union
from uuid import uuid4

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .models import CredentialType, SshCredential, SnapshotPlatform, utc_now
from .repository import Repository


class CredentialService:
    """Encrypts operator-supplied credential material at rest."""

    def __init__(self, repository: Repository, encryption_key: bytes) -> None:
        if len(encryption_key) != 32:
            raise ValueError("Credential encryption key must be 32 bytes")
        self.repository = repository
        self.cipher = AESGCM(encryption_key)

    def save_private_key(self, name: str, content: bytes) -> SshCredential:
        return self.save_secret(
            name=name,
            credential_type=CredentialType.SSH_PRIVATE_KEY,
            secret=content,
        )

    def save_secret(
        self,
        name: str,
        credential_type: Union[CredentialType, str],
        secret: bytes,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SshCredential:
        resolved_type = CredentialType(credential_type)
        metadata = metadata or {}
        self._validate_secret(resolved_type, secret, metadata)
        if len(secret) > 1024 * 1024:
            raise ValueError("Credential secret is too large")
        credential_id = "credential-%s" % uuid4().hex[:12]
        nonce = os.urandom(12)
        encrypted = self.cipher.encrypt(nonce, secret, credential_id.encode("utf-8"))
        fingerprint_source = secret
        if resolved_type != CredentialType.SSH_PRIVATE_KEY or metadata:
            fingerprint_source += json.dumps(
                metadata,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        credential = SshCredential(
            id=credential_id,
            name=name,
            credential_type=resolved_type,
            fingerprint=hashlib.sha256(fingerprint_source).hexdigest()[:24],
            metadata=metadata,
            created_at=utc_now(),
        )
        return self.repository.save_credential(credential, encrypted, nonce)

    def _validate_secret(
        self,
        credential_type: CredentialType,
        secret: bytes,
        metadata: Dict[str, Any],
    ) -> None:
        if credential_type == CredentialType.SSH_PRIVATE_KEY:
            self._validate_private_key(secret)
            return
        if credential_type == CredentialType.AWS_ROLE:
            if not metadata.get("roleArn") and not metadata.get("role_arn"):
                raise ValueError("AWS role credentials require roleArn metadata")
            return
        if not secret.strip():
            raise ValueError("%s credentials require a secret" % credential_type.value)

    @staticmethod
    def _validate_private_key(content: bytes) -> None:
        if b"PRIVATE KEY" not in content:
            raise ValueError("Uploaded file does not look like a private SSH key")
        if len(content) > 1024 * 1024:
            raise ValueError("SSH private key file is too large")

    def list_credentials(self) -> List[SshCredential]:
        return self.repository.list_credentials()

    def delete_credential(self, credential_id: str) -> None:
        attached_hosts = [
            host
            for host in self.repository.list_hosts()
            if host.credential_id == credential_id
            or host.snapshot_credential_id == credential_id
        ]
        if attached_hosts:
            names = ", ".join(sorted(host.name for host in attached_hosts))
            raise ValueError(
                "Credential is still assigned to host(s): %s. Remove it from those "
                "hosts before deleting the credential." % names
            )
        self.repository.delete_credential(credential_id)

    def _decrypt_secret(
        self,
        credential_id: str,
        expected_type: Optional[CredentialType] = None,
    ) -> bytes:
        record = self.repository.get_credential_record(credential_id)
        if not record:
            raise ValueError("Credential not found")
        credential, encrypted, nonce = record
        if expected_type and CredentialType(credential.credential_type) != expected_type:
            raise ValueError(
                "Credential %s is not a %s credential"
                % (credential_id, expected_type.value)
            )
        return self.cipher.decrypt(
            nonce,
            encrypted,
            credential_id.encode("utf-8"),
        )

    def _decrypt_private_key(self, credential_id: str) -> bytes:
        return self._decrypt_secret(
            credential_id,
            CredentialType.SSH_PRIVATE_KEY,
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

    @contextmanager
    def temporary_secret(
        self,
        credential_id: Optional[str],
    ) -> Iterator[Path]:
        if not credential_id:
            raise ValueError("Snapshot credential is not configured")
        content = self._decrypt_secret(credential_id)
        file_descriptor, raw_path = tempfile.mkstemp(prefix="ai-sysadm-secret-")
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


SNAPSHOT_CREDENTIAL_TYPES: Dict[SnapshotPlatform, set[CredentialType]] = {
    SnapshotPlatform.PROXMOX: {CredentialType.PROXMOX_TOKEN},
    SnapshotPlatform.AWS: {CredentialType.AWS_ACCESS_KEY, CredentialType.AWS_ROLE},
    SnapshotPlatform.VMWARE: {CredentialType.VMWARE_SECRET},
    SnapshotPlatform.LIBVIRT: {CredentialType.LIBVIRT_SSH},
}
