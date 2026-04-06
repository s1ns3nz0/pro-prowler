"""Web server configuration."""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel


class WebConfig(BaseModel):
    """Configuration for the web server."""

    data_dir: Path = Path("./data")
    host: str = "0.0.0.0"
    port: int = 8000
    skip_context_analysis: bool = True
    default_fail_threshold: int = 60
    api_key: str | None = None

    def model_post_init(self, __context: object) -> None:
        if self.api_key is None:
            self.api_key = os.environ.get("IAC_RISK_API_KEY")

    @property
    def db_path(self) -> Path:
        return self.data_dir / "snapshots.db"

    @property
    def snapshots_dir(self) -> Path:
        return self.data_dir / "snapshots"
