"""Multi-provider LLM client supporting Anthropic, OpenAI, and Ollama."""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Generator

from iac_risk.core.schemas import BusinessContext

logger = logging.getLogger(__name__)


def _get_provider() -> str:
    return os.environ.get("LLM_PROVIDER", "anthropic").lower()


def _get_model() -> str:
    provider = _get_provider()
    default_models = {
        "anthropic": "claude-sonnet-4-20250514",
        "openai": "gpt-4o",
        "ollama": "llama3.1",
    }
    return os.environ.get("LLM_MODEL", default_models.get(provider, ""))


def _call_anthropic(
    system: str, user_message: str, max_tokens: int = 4096,
) -> str:
    """Call Anthropic Claude API."""
    import anthropic
    client = anthropic.Anthropic()
    response = client.messages.create(
        model=_get_model(),
        max_tokens=max_tokens,
        system=system,
        messages=[{"role": "user", "content": user_message}],
    )
    for block in response.content:
        if hasattr(block, "text"):
            return block.text
    return ""


def _call_openai(
    system: str, user_message: str, max_tokens: int = 4096,
) -> str:
    """Call OpenAI API."""
    from openai import OpenAI
    client = OpenAI()
    response = client.chat.completions.create(
        model=_get_model(),
        max_tokens=max_tokens,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user_message},
        ],
    )
    return response.choices[0].message.content or ""


def _call_ollama(
    system: str, user_message: str, max_tokens: int = 4096,
) -> str:
    """Call local Ollama server."""
    import urllib.request

    base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
    url = f"{base_url}/api/chat"
    payload = json.dumps({
        "model": _get_model(),
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user_message},
        ],
        "stream": False,
        "options": {"num_predict": max_tokens},
    }).encode()

    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.loads(resp.read())
    return data.get("message", {}).get("content", "")


def call_llm(
    system: str, user_message: str, max_tokens: int = 4096,
) -> str:
    """Call the configured LLM provider. Returns response text.

    Falls back gracefully on any error.
    """
    provider = _get_provider()
    try:
        if provider == "anthropic":
            return _call_anthropic(system, user_message, max_tokens)
        if provider == "openai":
            return _call_openai(system, user_message, max_tokens)
        if provider == "ollama":
            return _call_ollama(system, user_message, max_tokens)
        logger.warning("Unknown LLM provider: %s", provider)
        return ""
    except Exception as e:
        logger.warning("LLM call failed (%s): %s", provider, e)
        return ""


# --- Streaming ---


def _stream_anthropic(
    system: str, user_message: str, max_tokens: int = 4096,
) -> Generator[str, None, None]:
    """Stream from Anthropic Claude API."""
    import anthropic
    client = anthropic.Anthropic()
    with client.messages.stream(
        model=_get_model(),
        max_tokens=max_tokens,
        system=system,
        messages=[{"role": "user", "content": user_message}],
    ) as stream:
        for text in stream.text_stream:
            yield text


def _stream_openai(
    system: str, user_message: str, max_tokens: int = 4096,
) -> Generator[str, None, None]:
    """Stream from OpenAI API."""
    from openai import OpenAI
    client = OpenAI()
    stream = client.chat.completions.create(
        model=_get_model(),
        max_tokens=max_tokens,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user_message},
        ],
        stream=True,
    )
    for chunk in stream:
        delta = chunk.choices[0].delta
        if delta.content:
            yield delta.content


def _stream_ollama(
    system: str, user_message: str, max_tokens: int = 4096,
) -> Generator[str, None, None]:
    """Stream from local Ollama server."""
    import urllib.request

    base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
    url = f"{base_url}/api/chat"
    payload = json.dumps({
        "model": _get_model(),
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user_message},
        ],
        "stream": True,
        "options": {"num_predict": max_tokens},
    }).encode()

    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        for line in resp:
            if line.strip():
                data = json.loads(line)
                content = data.get("message", {}).get("content", "")
                if content:
                    yield content


def stream_llm(
    system: str, user_message: str, max_tokens: int = 4096,
) -> Generator[str, None, None]:
    """Stream from the configured LLM provider.

    Yields text chunks as they arrive.
    """
    provider = _get_provider()
    try:
        if provider == "anthropic":
            yield from _stream_anthropic(
                system, user_message, max_tokens,
            )
        elif provider == "openai":
            yield from _stream_openai(
                system, user_message, max_tokens,
            )
        elif provider == "ollama":
            yield from _stream_ollama(
                system, user_message, max_tokens,
            )
        else:
            logger.warning("Unknown LLM provider: %s", provider)
    except Exception as e:
        logger.warning("LLM stream failed (%s): %s", provider, e)
        yield f"[Error: LLM call failed — {e}]"


# --- Business context analysis (used by Context Analysis Agent) ---

_CONTEXT_SYSTEM_PROMPT = (
    "You are a security analyst. Given business documents describing "
    "an organization's services, data classification policies, and "
    "security governance, analyze them and produce a structured mapping "
    "of resource patterns to business context.\n\n"
    "For each identifiable resource pattern, provide:\n"
    "- resource_pattern: a glob pattern matching Terraform resource "
    "types (e.g., 'aws_s3_bucket.*', 'aws_db_instance.*'). "
    "Use the resource type prefix only, not module paths.\n"
    "- asset_criticality: 1-5 (1=very low, 5=very high)\n"
    "- data_classification: one of 'public', 'internal', "
    "'confidential', 'restricted'\n"
    "- compliance_scope: list of applicable frameworks from "
    "['PCI_DSS', 'ISO_27001', 'ISO_27701', 'SOC_2', 'GDPR', 'ISMS_P']\n"
    "- notes: brief explanation of why this context applies\n\n"
    "Return a JSON array of objects with these fields. "
    "Be conservative — only include patterns you can clearly "
    "derive from the documents."
)


def analyze_business_context(
    documents: list[str],
    resource_types: list[str] | None = None,
) -> list[BusinessContext]:
    """Analyze business documents and derive resource context.

    Returns empty list on any failure (graceful degradation).
    """
    combined_docs = "\n\n---\n\n".join(documents)
    user_message = (
        "Analyze these business documents and produce "
        f"resource-to-context mappings:\n\n{combined_docs}"
    )
    if resource_types:
        rt_list = ", ".join(resource_types)
        user_message += (
            f"\n\nKnown resource types: {rt_list}"
        )

    text = call_llm(_CONTEXT_SYSTEM_PROMPT, user_message)
    if not text:
        logger.warning("Context analysis: LLM returned empty response")
        return []

    try:
        text = text.strip()
        # Extract JSON from markdown code blocks (handles preamble text)
        if "```" in text:
            # Find the code block content
            parts = text.split("```")
            for part in parts[1::2]:  # odd indices = inside backticks
                part = part.strip()
                if part.startswith("json"):
                    part = part[4:].strip()
                if part.startswith("[") or part.startswith("{"):
                    text = part
                    break
        # Try to find JSON array/object if still not pure JSON
        if not text.startswith("[") and not text.startswith("{"):
            start = text.find("[")
            if start == -1:
                start = text.find("{")
            if start != -1:
                text = text[start:]

        data = json.loads(text)
        if not isinstance(data, list):
            data = [data]

        contexts = []
        for item in data:
            try:
                contexts.append(BusinessContext.model_validate(item))
            except Exception as e:
                logger.warning(
                    "Context item validation failed: %s (item: %s)",
                    e, json.dumps(item)[:200],
                )
        logger.info(
            "Context analysis: %d contexts from %d items",
            len(contexts), len(data),
        )
        return contexts
    except Exception as e:
        logger.warning(
            "Context analysis parse failed: %s (text: %s)",
            e, text[:300],
        )
        return []
