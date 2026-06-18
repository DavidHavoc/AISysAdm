import hashlib
import os
from pathlib import Path
from typing import Dict, Optional
from uuid import uuid4

from .models import SshCredential, utc_now


class CredentialVault:
    """Demo key vault. Replace with a managed secret store before production use."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self._credentials: Dict[str, SshCredential] = {}

    def save_private_key(self, name: str, content: bytes) -> SshCredential:
        if b"PRIVATE KEY" not in content:
            raise ValueError("Uploaded file does not look like a private SSH key")
        credential_id = "credential-%s" % uuid4().hex[:12]
        path = self.root / credential_id
        path.write_bytes(content)
        os.chmod(path, 0o600)
        credential = SshCredential(
            id=credential_id,
            name=name,
            fingerprint=hashlib.sha256(content).hexdigest()[:16],
            created_at=utc_now(),
        )
        self._credentials[credential_id] = credential
        return credential

    def key_path(self, credential_id: Optional[str]) -> Optional[Path]:
        if not credential_id:
            return None
        path = self.root / credential_id
        return path if path.exists() else None
