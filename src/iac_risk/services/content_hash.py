"""SHA-256 content hashing for cache invalidation."""

import hashlib
from pathlib import Path


def hash_file(path: Path) -> str:
    """Compute SHA-256 hash of a file's contents."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_directory(path: Path) -> str:
    """Compute a stable SHA-256 hash of all files in a directory.

    Files are sorted by path for deterministic ordering.
    """
    h = hashlib.sha256()
    files = sorted(p for p in path.rglob("*") if p.is_file())
    for file_path in files:
        # Include relative path in hash so renames are detected
        h.update(str(file_path.relative_to(path)).encode())
        h.update(hash_file(file_path).encode())
    return h.hexdigest()


def hash_string(content: str) -> str:
    """Compute SHA-256 hash of a string."""
    return hashlib.sha256(content.encode()).hexdigest()
