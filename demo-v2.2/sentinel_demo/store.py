"""Small read-only content stores for the explicitly local demo profile."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from urllib import error, parse, request

MAX_BLOB = 64 * 1024 * 1024
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def validate_digest(value: str) -> str:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise ValueError("Expected a lowercase SHA-256 digest")
    return value


def descriptor(data: bytes, media_type: str) -> dict:
    return {"digest": digest(data), "size": len(data), "mediaType": media_type}


class DirectoryStore:
    def __init__(self, root: Path):
        self.root = Path(root).resolve()

    def read_blob(self, value: str) -> bytes:
        validate_digest(value)
        path = (self.root / "blobs" / "sha256" / value[7:]).resolve()
        if not path.is_relative_to(self.root):
            raise OSError("Blob path escapes store")
        with path.open("rb") as stream:
            data = stream.read(MAX_BLOB + 1)
        if len(data) > MAX_BLOB:
            raise OSError("Blob exceeds demo size limit")
        return data

    read_manifest = read_blob

    def write(self, data: bytes) -> str:
        if len(data) > MAX_BLOB:
            raise OSError("Blob exceeds demo size limit")
        value = digest(data)
        path = self.root / "blobs" / "sha256" / value[7:]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return value


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise OSError("Registry redirects are outside the local demo profile")


class RegistryStore:
    """No authentication, non-loopback hosts, redirects or remote endpoints."""

    def __init__(self, repository: str, export: DirectoryStore | None = None):
        parsed = parse.urlsplit("http://" + repository)
        if (parsed.hostname not in {"127.0.0.1", "localhost"}
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or not parsed.port or not re.fullmatch(r"/[a-z0-9]+(?:[._/-][a-z0-9]+)*", parsed.path)):
            raise ValueError("This demo accepts only an explicit loopback registry repository")
        self.base = f"http://{parsed.netloc}/v2{parsed.path}"
        self.export = export
        self.opener = request.build_opener(_NoRedirect)

    def _read(self, endpoint: str, accept: str = OCI_MANIFEST) -> bytes:
        req = request.Request(self.base + endpoint, headers={"Accept": accept})
        try:
            with self.opener.open(req, timeout=15) as response:
                data = response.read(MAX_BLOB + 1)
        except error.HTTPError as exc:
            if exc.code == 404:
                raise FileNotFoundError("Required registry object is missing") from exc
            raise OSError(f"Registry returned HTTP {exc.code}") from exc
        except error.URLError as exc:
            raise OSError("Registry unavailable") from exc
        if len(data) > MAX_BLOB:
            raise OSError("Registry object exceeds demo size limit")
        if self.export:
            self.export.write(data)
        return data

    def read_manifest(self, value: str) -> bytes:
        return self._read("/manifests/" + validate_digest(value))

    def read_blob(self, value: str) -> bytes:
        return self._read("/blobs/" + validate_digest(value), "application/octet-stream")

    def discover(self, image_digest: str) -> list[dict]:
        """Producer-only discovery. Verification always uses pinned digests."""
        validate_digest(image_digest)
        try:
            raw = self._read("/referrers/" + image_digest,
                             "application/vnd.oci.image.index.v1+json")
        except FileNotFoundError:
            raw = self._read("/manifests/" + image_digest.replace(":", "-"),
                             "application/vnd.oci.image.index.v1+json")
        # The producer creates exactly three attestations. Verification does not
        # depend on enumeration or a complete referrers listing.
        return json.loads(raw)["manifests"]
