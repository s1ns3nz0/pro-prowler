"""Configuration loading with defaults and optional YAML config file."""

from __future__ import annotations

from pathlib import Path

import yaml

from iac_risk.core.schemas import PipelineConfig


def load_config(
    config_file: Path | None = None,
    output_dir: str = "./reports",
    formats: tuple[str, ...] = ("html", "json"),
    business_docs: str | None = None,
    cache_dir: str = ".pro-prowler-cache",
    skip_context: bool = False,
    fail_threshold: int = 60,
    extra_documents: list[str] | None = None,
    repository: str = "",
) -> PipelineConfig:
    """Load pipeline config from optional YAML file merged with CLI flags."""
    base: dict = {}

    if config_file and config_file.exists():
        with open(config_file) as f:
            base = yaml.safe_load(f) or {}

    return PipelineConfig(
        output_dir=Path(base.get("output_dir", output_dir)),
        output_formats=list(base.get("output_formats", formats)),
        business_docs_dir=Path(business_docs) if business_docs else base.get("business_docs_dir"),
        cache_dir=Path(base.get("cache_dir", cache_dir)),
        skip_context_analysis=base.get("skip_context_analysis", skip_context),
        fail_threshold=base.get("fail_threshold", fail_threshold),
        extra_documents=extra_documents or [],
        repository=repository,
    )
