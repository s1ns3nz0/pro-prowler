"""Context Analysis Agent — AI-driven business context from docs, app code, and governance."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from iac_risk.agents.base import BaseAgent, ValidationResult
from iac_risk.core.schemas import (
    AppInsight,
    BusinessContext,
    ContextAnalysisInput,
    ContextAnalysisOutput,
    GovernanceInsight,
)
from iac_risk.services.content_hash import hash_string
from iac_risk.services.llm_client import analyze_business_context

logger = logging.getLogger(__name__)

CACHE_FILENAME = "context_cache.json"


def _load_cache(cache_dir: Path) -> dict[str, Any]:
    cache_file = cache_dir / CACHE_FILENAME
    if cache_file.exists():
        try:
            with open(cache_file) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _save_cache(
    cache_dir: Path, doc_hash: str,
    contexts: list[BusinessContext],
) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = cache_dir / CACHE_FILENAME
    data = {
        "document_hash": doc_hash,
        "contexts": [c.model_dump() for c in contexts],
    }
    with open(cache_file, "w") as f:
        json.dump(data, f, indent=2)


def _read_documents(docs_dir: Path) -> list[str]:
    """Read all text/markdown files from a directory."""
    documents: list[str] = []
    if not docs_dir.exists():
        return documents
    for ext in ("*.md", "*.txt", "*.yaml", "*.yml"):
        for file_path in sorted(docs_dir.glob(ext)):
            try:
                documents.append(file_path.read_text())
            except Exception:
                continue
    return documents


def _build_enrichment_docs(
    app_insights: list[AppInsight],
    governance_insights: list[GovernanceInsight],
) -> list[str]:
    """Build additional context documents from repo analysis."""
    docs: list[str] = []

    for insight in app_insights:
        if not insight.tech_stack and not insight.data_indicators:
            continue
        parts = [f"Application repository: {insight.repo}"]
        if insight.description:
            parts.append(f"Description: {insight.description}")
        if insight.tech_stack:
            parts.append(
                f"Tech stack: {', '.join(insight.tech_stack)}"
            )
        if insight.data_indicators:
            parts.append(
                f"Data indicators: {', '.join(insight.data_indicators)}"
            )
        if insight.dependencies:
            parts.append(
                f"Key dependencies: "
                f"{', '.join(insight.dependencies[:10])}"
            )
        docs.append("\n".join(parts))

    for gov in governance_insights:
        if not gov.documents_found:
            continue
        parts = [
            f"Governance repository: {gov.repo}",
            f"Documents: {', '.join(gov.documents_found[:5])}",
        ]
        if gov.data_classification_rules:
            parts.append("Data classification rules:")
            for rule in gov.data_classification_rules[:5]:
                parts.append(f"  - {rule}")
        if gov.compliance_scope_rules:
            parts.append("Compliance scope rules:")
            for rule in gov.compliance_scope_rules[:5]:
                parts.append(f"  - {rule}")
        if gov.security_policies:
            parts.append("Security policies:")
            for policy in gov.security_policies[:5]:
                parts.append(f"  - {policy}")
        if gov.raw_content_summary:
            parts.append(
                f"\nPolicy content:\n"
                f"{gov.raw_content_summary[:1500]}"
            )
        docs.append("\n".join(parts))

    return docs


class ContextAnalysisAgent(BaseAgent):
    name = "context_analysis"
    critical = False

    def validate_input(self, input_data: Any) -> ValidationResult:
        if not isinstance(input_data, ContextAnalysisInput):
            return ValidationResult(
                valid=False, error="Expected ContextAnalysisInput",
            )
        return ValidationResult(valid=True)

    def assess(
        self, input_data: ContextAnalysisInput,
    ) -> ContextAnalysisOutput:
        docs_dir = input_data.business_docs_dir
        cache_dir = input_data.cache_dir
        app_insights = input_data.app_insights
        governance_insights = input_data.governance_insights

        # Collect all document sources
        all_documents: list[str] = []

        # Source 1: Business docs from directory
        if docs_dir and docs_dir.exists():
            all_documents.extend(_read_documents(docs_dir))

        # Source 2: App config insights from Repo Analysis
        # Source 3: Governance docs from Repo Analysis
        enrichment_docs = _build_enrichment_docs(
            app_insights, governance_insights,
        )
        all_documents.extend(enrichment_docs)

        # Source 4: Extra documents (governance uploads, project context sources)
        if input_data.extra_documents:
            all_documents.extend(input_data.extra_documents)

        if not all_documents:
            logger.info("No context sources available")
            return ContextAnalysisOutput(
                contexts=[], cache_hit=False, document_hash="",
            )

        # Compute combined hash for caching
        combined = "\n---\n".join(all_documents)
        doc_hash = hash_string(combined)

        # Check cache
        cache = _load_cache(cache_dir)
        if cache.get("document_hash") == doc_hash:
            logger.info(
                "Context cache hit (hash: %s)", doc_hash[:12],
            )
            contexts = [
                BusinessContext.model_validate(c)
                for c in cache.get("contexts", [])
            ]
            return ContextAnalysisOutput(
                contexts=contexts,
                cache_hit=True,
                document_hash=doc_hash,
            )

        # Cache miss — call LLM
        logger.info(
            "Analyzing context: %d docs (%d from files, "
            "%d from repo analysis)",
            len(all_documents),
            len(all_documents) - len(enrichment_docs),
            len(enrichment_docs),
        )

        contexts = analyze_business_context(all_documents)

        # Only cache non-empty results to avoid persisting LLM failures
        if contexts:
            _save_cache(cache_dir, doc_hash, contexts)
        else:
            logger.warning(
                "Context analysis returned empty — not caching "
                "(docs: %d, hash: %s)", len(all_documents), doc_hash[:12],
            )

        return ContextAnalysisOutput(
            contexts=contexts,
            cache_hit=False,
            document_hash=doc_hash,
        )
