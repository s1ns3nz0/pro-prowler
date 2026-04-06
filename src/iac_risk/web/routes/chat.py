"""Chat endpoint — SSE streaming code assistant for resource remediation."""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from iac_risk.services.llm_client import stream_llm

logger = logging.getLogger(__name__)
router = APIRouter()

_SYSTEM_PROMPT = (
    "You are an IaC security remediation assistant embedded in a "
    "risk assessment dashboard. The user is viewing a specific AWS "
    "resource and its security findings.\n\n"
    "Your job is to help them fix Terraform configurations. When "
    "generating code:\n"
    "- Use valid HCL/Terraform syntax\n"
    "- Explain what each change does and why\n"
    "- Consider dependencies on other resources\n"
    "- Warn about potential breaking changes\n"
    "- Reference specific compliance controls when relevant\n"
    "- Be concise — the user is an engineer, not a student\n\n"
    "Context about the resource is provided below. Use it to give "
    "accurate, specific advice."
)


class ChatRequest(BaseModel):
    message: str = Field(description="User's question or request")
    resource_address: str = ""
    resource_type: str = ""
    resource_config: dict = Field(default_factory=dict)
    findings: list[dict] = Field(default_factory=list)
    asset_criticality: str = "MODERATE"
    data_classification: str = "internal"
    compliance_controls: list[str] = Field(default_factory=list)


def _build_context(req: ChatRequest) -> str:
    """Build resource context for the system prompt."""
    parts = []

    parts.append(
        f"Resource: {req.resource_address} ({req.resource_type})"
    )
    parts.append(
        f"Criticality: {req.asset_criticality} | "
        f"Data: {req.data_classification}"
    )

    if req.resource_config:
        config_str = json.dumps(req.resource_config, indent=2)
        if len(config_str) > 1500:
            config_str = config_str[:1500] + "\n..."
        parts.append(f"\nCurrent Terraform config:\n```hcl\n{config_str}\n```")

    if req.findings:
        parts.append("\nSecurity findings:")
        for f in req.findings:
            sev = f.get("severity", "")
            title = f.get("title", "")
            desc = f.get("description", "")
            remediation = f.get("remediation", "")
            parts.append(f"- [{sev}] {title}: {desc}")
            if remediation:
                parts.append(f"  Remediation: {remediation}")

            scenarios = f.get("attack_scenarios", [])
            for s in scenarios[:1]:
                technique = s.get("technique", "")
                mitre = s.get("mitre_tactic", "")
                parts.append(f"  Attack: {technique} ({mitre})")

    if req.compliance_controls:
        parts.append(
            f"\nCompliance controls affected: "
            f"{', '.join(req.compliance_controls[:10])}"
        )

    return "\n".join(parts)


def _sse_generator(system: str, user_msg: str):
    """Generate SSE events from LLM stream."""
    try:
        for chunk in stream_llm(system, user_msg, max_tokens=2048):
            escaped = json.dumps(chunk)
            yield f"data: {escaped}\n\n"
        yield "data: [DONE]\n\n"
    except Exception as e:
        logger.exception("Chat stream error")
        yield f"data: {json.dumps(f'[Error: {e}]')}\n\n"
        yield "data: [DONE]\n\n"


@router.post("/chat")
async def chat(req: ChatRequest, request: Request) -> StreamingResponse:
    """Stream a chat response for resource remediation."""
    context = _build_context(req)
    system = f"{_SYSTEM_PROMPT}\n\n---\n\n{context}"

    return StreamingResponse(
        _sse_generator(system, req.message),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
