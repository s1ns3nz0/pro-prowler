"""Governance document management — upload, list, delete."""

from __future__ import annotations

import io
import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader

from iac_risk.services.content_hash import hash_string
from iac_risk.web.config import WebConfig
from iac_risk.web.storage.database import (
    GovernanceDoc,
    delete_governance_doc,
    insert_governance_doc,
    list_governance_docs,
)

logger = logging.getLogger(__name__)
router = APIRouter()

_SUMMARIZE_SYSTEM = (
    "You are a security governance analyst. Given a policy document, "
    "produce a structured analysis in JSON format:\n"
    '{"summary": "2-3 sentence summary of the document",'
    '"data_classification_rules": ["rule 1", "rule 2"],'
    '"compliance_scope_rules": ["rule 1", "rule 2"],'
    '"security_policies": ["policy 1", "policy 2"]}'
    "\n\nExtract specific, actionable rules. "
    "Be precise about data categories and compliance frameworks."
)


def _summarize_document(text: str) -> dict:
    """Use LLM to summarize a governance document."""
    import json as _json

    from iac_risk.services.llm_client import call_llm

    if not text or len(text) < 20:
        return {
            "summary": "",
            "data_classification_rules": [],
            "compliance_scope_rules": [],
            "security_policies": [],
        }

    truncated = text[:4000]
    result = call_llm(
        _SUMMARIZE_SYSTEM,
        f"Analyze this governance document:\n\n{truncated}",
        max_tokens=2048,
    )
    if not result:
        return {
            "summary": "AI summary unavailable",
            "data_classification_rules": [],
            "compliance_scope_rules": [],
            "security_policies": [],
        }
    try:
        result = result.strip()
        if result.startswith("```"):
            result = result.split("\n", 1)[1].rsplit("```", 1)[0]
        return _json.loads(result)
    except Exception:
        return {
            "summary": result[:500],
            "data_classification_rules": [],
            "compliance_scope_rules": [],
            "security_policies": [],
        }

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"
_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=True,
)


def _cfg(request: Request) -> WebConfig:
    return request.app.state.config


def _gov_dir(config: WebConfig) -> Path:
    d = config.data_dir / "governance"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _extract_pdf_text(content: bytes) -> str:
    """Extract text from PDF bytes."""
    from pypdf import PdfReader
    reader = PdfReader(io.BytesIO(content))
    parts = []
    for page in reader.pages:
        text = page.extract_text()
        if text:
            parts.append(text)
    return "\n\n".join(parts)


def _extract_docx_text(content: bytes) -> str:
    """Extract text from DOCX bytes."""
    from docx import Document
    doc = Document(io.BytesIO(content))
    return "\n\n".join(p.text for p in doc.paragraphs if p.text)


def _fetch_url_text(url: str) -> str:
    """Fetch and extract text from a URL."""
    import urllib.request
    req = urllib.request.Request(
        url, headers={"User-Agent": "IaCRiskAssessment/1.0"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        html = resp.read().decode("utf-8", errors="ignore")
    # Simple HTML tag stripping
    import re
    text = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=re.DOTALL)
    text = re.sub(r"<style[^>]*>.*?</style>", "", text, flags=re.DOTALL)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:10000]


# --- API Endpoints ---


@router.post("/api/governance")
async def upload_governance_doc(
    request: Request,
    title: str = Form(...),
    doc_type: str = Form("text"),
    content: str = Form(""),
    url: str = Form(""),
    file: UploadFile | None = File(None),
) -> dict:
    """Upload a governance document."""
    config = _cfg(request)
    gov_dir = _gov_dir(config)
    doc_id = str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()

    extracted_text = ""
    filename = ""

    if doc_type == "text":
        extracted_text = content
        filename = f"{doc_id}.txt"
    elif doc_type == "url":
        try:
            extracted_text = _fetch_url_text(url)
            filename = f"{doc_id}.txt"
        except Exception as e:
            raise HTTPException(
                status_code=400, detail=f"Failed to fetch URL: {e}",
            ) from e
    elif doc_type in ("pdf", "docx") and file:
        file_bytes = await file.read()
        ext = "pdf" if doc_type == "pdf" else "docx"
        filename = f"{doc_id}.{ext}"
        # Save original file
        (gov_dir / filename).write_bytes(file_bytes)
        # Extract text
        try:
            if doc_type == "pdf":
                extracted_text = _extract_pdf_text(file_bytes)
            else:
                extracted_text = _extract_docx_text(file_bytes)
        except Exception as e:
            logger.warning("Text extraction failed: %s", e)
            extracted_text = f"[Extraction failed: {e}]"
    else:
        raise HTTPException(
            status_code=400,
            detail="Invalid doc_type or missing file",
        )

    # Save extracted text
    text_file = gov_dir / f"{doc_id}.txt"
    text_file.write_text(extracted_text)

    # AI summarization
    import json as _json
    summary_data = _summarize_document(extracted_text)
    summary_file = gov_dir / f"{doc_id}.summary.json"
    summary_file.write_text(_json.dumps(summary_data, indent=2))

    # Save metadata
    doc = GovernanceDoc(
        id=doc_id,
        title=title,
        doc_type=doc_type,
        filename=filename,
        content_hash=hash_string(extracted_text),
        uploaded_at=now,
        updated_at=now,
    )
    insert_governance_doc(config.db_path, doc)

    logger.info(
        "Governance doc uploaded: %s (%s, %d chars)",
        title, doc_type, len(extracted_text),
    )

    return {
        "id": doc_id,
        "title": title,
        "doc_type": doc_type,
        "text_length": len(extracted_text),
    }


@router.get("/api/governance")
async def get_governance_docs(request: Request) -> list[dict]:
    """List all governance documents."""
    config = _cfg(request)
    docs = list_governance_docs(config.db_path)
    gov_dir = _gov_dir(config)
    result = []
    for d in docs:
        text_file = gov_dir / f"{d.id}.txt"
        text_len = 0
        preview = ""
        if text_file.exists():
            text = text_file.read_text()
            text_len = len(text)
            preview = text[:200]
        result.append({
            "id": d.id,
            "title": d.title,
            "doc_type": d.doc_type,
            "content_hash": d.content_hash,
            "uploaded_at": d.uploaded_at,
            "text_length": text_len,
            "preview": preview,
        })
    return result


@router.get("/api/governance/{doc_id}")
async def get_governance_detail(
    doc_id: str, request: Request,
) -> dict:
    """Get full document detail with summary."""
    import json as _json

    config = _cfg(request)
    gov_dir = _gov_dir(config)
    text_file = gov_dir / f"{doc_id}.txt"
    summary_file = gov_dir / f"{doc_id}.summary.json"

    if not text_file.exists():
        raise HTTPException(
            status_code=404, detail="Document not found",
        )

    text = text_file.read_text()
    summary = {}
    if summary_file.exists():
        try:
            summary = _json.loads(summary_file.read_text())
        except Exception:
            summary = {}

    return {
        "id": doc_id,
        "text": text,
        "summary": summary.get("summary", ""),
        "data_classification_rules": summary.get(
            "data_classification_rules", [],
        ),
        "compliance_scope_rules": summary.get(
            "compliance_scope_rules", [],
        ),
        "security_policies": summary.get(
            "security_policies", [],
        ),
    }


@router.put("/api/governance/{doc_id}")
async def update_governance_doc(
    doc_id: str, request: Request,
) -> dict:
    """Update document text and/or summary."""
    import json as _json

    config = _cfg(request)
    gov_dir = _gov_dir(config)
    body = await request.json()

    # Update text if provided
    if "text" in body:
        text_file = gov_dir / f"{doc_id}.txt"
        text_file.write_text(body["text"])

    # Update summary fields if provided
    summary_file = gov_dir / f"{doc_id}.summary.json"
    summary = {}
    if summary_file.exists():
        try:
            summary = _json.loads(summary_file.read_text())
        except Exception:
            pass
    for key in [
        "summary", "data_classification_rules",
        "compliance_scope_rules", "security_policies",
    ]:
        if key in body:
            summary[key] = body[key]
    summary_file.write_text(_json.dumps(summary, indent=2))

    return {"status": "updated"}


@router.post("/api/governance/{doc_id}/resummarize")
async def resummarize_doc(
    doc_id: str, request: Request,
) -> dict:
    """Re-run AI summarization on a document."""
    import json as _json

    config = _cfg(request)
    gov_dir = _gov_dir(config)
    text_file = gov_dir / f"{doc_id}.txt"

    if not text_file.exists():
        raise HTTPException(
            status_code=404, detail="Document not found",
        )

    text = text_file.read_text()
    summary_data = _summarize_document(text)
    summary_file = gov_dir / f"{doc_id}.summary.json"
    summary_file.write_text(_json.dumps(summary_data, indent=2))

    return summary_data


@router.delete("/api/governance/{doc_id}")
async def remove_governance_doc(
    doc_id: str, request: Request,
) -> dict:
    """Delete a governance document."""
    config = _cfg(request)
    gov_dir = _gov_dir(config)
    deleted = delete_governance_doc(config.db_path, doc_id)
    if not deleted:
        raise HTTPException(
            status_code=404, detail="Document not found",
        )
    # Remove files
    for ext in ("txt", "pdf", "docx", "summary.json"):
        f = gov_dir / f"{doc_id}.{ext}"
        if f.exists():
            f.unlink()
    return {"deleted": doc_id}


# --- Dashboard Page ---


@router.get("/governance", response_class=HTMLResponse)
async def governance_page(request: Request) -> HTMLResponse:
    """Governance document management page."""
    config = _cfg(request)
    docs = list_governance_docs(config.db_path)
    gov_dir = _gov_dir(config)

    doc_list = []
    for d in docs:
        text_file = gov_dir / f"{d.id}.txt"
        text_len = len(text_file.read_text()) if text_file.exists() else 0
        doc_list.append({
            "id": d.id,
            "title": d.title,
            "doc_type": d.doc_type,
            "uploaded_at": d.uploaded_at,
            "text_length": text_len,
        })

    template = _env.get_template("governance.html.j2")
    html = template.render(documents=doc_list)
    return HTMLResponse(content=html)
