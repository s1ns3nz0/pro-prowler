"""Filesystem storage for PipelineResult JSON blobs."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from iac_risk.core.schemas import PipelineResult

logger = logging.getLogger(__name__)


def save_snapshot(
    snapshots_dir: Path, snapshot_id: str, result: PipelineResult,
) -> Path:
    """Write a PipelineResult as a JSON file."""
    snapshots_dir.mkdir(parents=True, exist_ok=True)
    path = snapshots_dir / f"{snapshot_id}.json"
    with open(path, "w") as f:
        f.write(result.model_dump_json(indent=2))
    return path


def load_snapshot(snapshots_dir: Path, snapshot_id: str) -> PipelineResult:
    """Read a PipelineResult from a JSON file.

    Raises FileNotFoundError if file doesn't exist.
    """
    path = snapshots_dir / f"{snapshot_id}.json"
    if not path.exists():
        raise FileNotFoundError(f"Snapshot file not found: {path}")
    with open(path) as f:
        data = json.load(f)
    return PipelineResult.model_validate(data)


def delete_snapshot_blob(snapshots_dir: Path, snapshot_id: str) -> bool:
    """Delete a snapshot JSON file. Returns True if deleted."""
    path = snapshots_dir / f"{snapshot_id}.json"
    if path.exists():
        path.unlink()
        return True
    return False


def snapshot_exists(snapshots_dir: Path, snapshot_id: str) -> bool:
    """Check if a snapshot JSON file exists."""
    return (snapshots_dir / f"{snapshot_id}.json").exists()
