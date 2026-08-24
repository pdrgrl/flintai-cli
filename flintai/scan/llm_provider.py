"""
llm_provider.py — LLM model factory shared by agent and MCP scanners.

Single entry point:

  make_model(model_string)
      Returns an ADK-compatible LiteLlm model object for all providers.
      Used by both the agentic reasoner (ADK Runner) and single-pass
      completions (triage) via complete_text().

  complete_text(model, system_prompt, user_message, ...)
      Runs a single-pass LLM completion using generate_content_async
      on the model returned by make_model().

Configuration via SCANNER_MODEL env var in 'provider:model' format
(e.g., 'google:gemini-3.5-flash', 'openai:gpt-5.4', 'anthropic:claude-sonnet-4-6').

API keys are read from standard env vars by the underlying frameworks:
GOOGLE_API_KEY, OPENAI_API_KEY, ANTHROPIC_API_KEY.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import os
import re
from typing import Any

from . import ADKModel
from google.adk.models.llm_request import LlmRequest
from google.genai import types as genai_types
from google.adk.models.google_llm import Gemini

logger = logging.getLogger(__name__)

_REDACT_PATTERNS = re.compile(
    r"("
    r"Bearer\s+[A-Za-z0-9\-_.~+/]+=*"
    r"|sk-[A-Za-z0-9]{10,}"
    r"|key-[A-Za-z0-9]{10,}"
    r"|pat-[A-Za-z0-9]{10,}"
    r"|AIza[A-Za-z0-9_\-]{35,}"
    r"|[A-Za-z0-9]{40,}"
    r")",
    re.IGNORECASE,
)


def _safe_error(exc: Exception) -> str:
    """Return a log-safe string with token-like patterns redacted."""
    return _REDACT_PATTERNS.sub("[REDACTED]", str(exc))


PROVIDER_GOOGLE = "google"
PROVIDER_LITELLM = "litellm"

DEFAULT_MODEL = "gemini-3.6-flash"

_PROVIDER_ALIASES = {"gemini": "google"}

# The env var(s) each provider's SDK reads its API key from. Used to tell a
# *missing* key (skip the LLM stage with a warning — the customer never
# configured one) from an *invalid* one (the provider returns 401, a real
# user-domain failure). Only providers we can check for are listed; anything
# absent is assumed configured so an exotic provider is never skipped on a false
# "missing key" — it runs, and if the key really is absent, fails as before.
_PROVIDER_API_KEY_ENV_VARS = {
    "google": ("GOOGLE_API_KEY", "GEMINI_API_KEY"),
    "openai": ("OPENAI_API_KEY",),
    "anthropic": ("ANTHROPIC_API_KEY",),
}


def _google_adc_present() -> bool:
    """Whether Google credentials exist via the Vertex/ADC path (no API key)."""
    if os.getenv("GOOGLE_GENAI_USE_VERTEXAI", "").lower() in ("1", "true"):
        return True
    return bool(os.getenv("GOOGLE_APPLICATION_CREDENTIALS"))


def api_key_present(model_string: str | None = None) -> bool:
    """Whether an API key (or equivalent credential) is configured for the model.

    Resolves the provider the same way `make_model` does, then checks its known
    key env var(s). Returns True for providers we have no mapping for, so a
    provider we can't preflight is left to run rather than being skipped on a
    guess.
    """
    provider, _ = _resolve_model_string(model_string)
    if provider == PROVIDER_GOOGLE and _google_adc_present():
        return True
    env_vars = _PROVIDER_API_KEY_ENV_VARS.get(provider)
    if env_vars is None:
        return True
    return any(os.getenv(var) for var in env_vars)


# Reasoning effort for OpenAI gpt-5 reasoning models. See _openai_reasoning_effort.
DEFAULT_REASONING_EFFORT = "medium"


def _openai_reasoning_effort(name: str) -> str | None:
    """Return the ``reasoning_effort`` to set for an OpenAI gpt-5 reasoning model.

    The gpt-5 reasoning-model endpoints (e.g. the ``gpt-5.6-*`` proxy) default to
    reasoning **on** server-side and then reject function tools on
    ``/v1/chat/completions`` ("... use /v1/responses or set reasoning_effort to
    'none'"). litellm bridges gpt-5.4+ tool calls to the Responses API — where
    tools and reasoning coexist — **only when ``reasoning_effort`` is set
    explicitly** (any value, including ``"none"``); left unset the call stays on
    chat/completions and fails. So set it here for the gpt-5 reasoning family.

    Returns ``None`` (leave unset) for everything else — non-gpt-5 models, and
    the ``gpt-5-chat*`` variants which are plain chat models that reject
    ``reasoning_effort`` outright. ``SCANNER_REASONING_EFFORT`` overrides the
    level; ``drop_params=True`` drops it for any model that still rejects it.
    """
    base = name.split("/")[-1]
    if "gpt-5" not in name or base.startswith("gpt-5-chat"):
        return None
    return os.getenv("SCANNER_REASONING_EFFORT", DEFAULT_REASONING_EFFORT)

_KNOWN_PROVIDERS = {

    "google",
    "gemini",
    "openai",
    "anthropic",
    "litellm",
    "groq",
    "mistral",
    "ollama",
    "deepseek",
}

def parse_model_string(model_string: str) -> tuple[str, str | None]:
    """Parse model string into (provider, model_name)."""
    ms = model_string.strip()
    if ":" in ms:
        provider, model = ms.split(":", 1)
        provider = provider.strip().lower()
        provider = _PROVIDER_ALIASES.get(provider, provider)
        return provider, model.strip() if model else None

    # Handle provider prefix with slash: e.g. "openai/cf/llama-3.3-70b" -> ("openai", "cf/llama-3.3-70b")
    if "/" in ms:
        first_segment, rest = ms.split("/", 1)
        first_segment_clean = first_segment.strip().lower()
        if (
            first_segment_clean in _KNOWN_PROVIDERS
            or first_segment_clean in _PROVIDER_ALIASES
        ):
            provider = _PROVIDER_ALIASES.get(
                first_segment_clean, first_segment_clean
            )
            return provider, rest.strip()

    if ms.lower() in ("google", "gemini"):
        return PROVIDER_GOOGLE, None

    if ms.lower() == "litellm":
        return PROVIDER_LITELLM, None

    if "gemini" in ms.lower():
        return PROVIDER_GOOGLE, ms

    if os.getenv("OPENAI_BASE_URL") or os.getenv("OPENAI_API_BASE"):
        return "openai", ms

    return PROVIDER_GOOGLE, ms


def _resolve_model_string(model_string: str | None = None) -> tuple[str, str]:
    """Resolve provider and model from argument or SCANNER_MODEL env var."""
    ms = (model_string or os.getenv("SCANNER_MODEL", "")).strip()
    if not ms:
        return PROVIDER_GOOGLE, DEFAULT_MODEL
    provider, model = parse_model_string(ms)
    return provider, model or DEFAULT_MODEL


def _flatten_content(content: Any) -> str | None:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for p in content:
            if isinstance(p, dict) and "text" in p:
                parts.append(p["text"])
            elif isinstance(p, str):
                parts.append(p)
            else:
                parts.append(str(p))
        return "\n".join(parts)
    return str(content) if content is not None else None


def _sanitize_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flatten array content parts to plain strings for Cloudflare compatibility."""
    sanitized = []
    for m in messages:
        if not isinstance(m, dict):
            sanitized.append(m)
            continue
        m_copy = dict(m)
        if "content" in m_copy:
            flat = _flatten_content(m_copy["content"])
            m_copy["content"] = flat if flat is not None else ""
        sanitized.append(m_copy)
    return sanitized


def make_model(
    model_string: str | None = None,
    temperature: float = 0.0,
    *,
    scanner: str = "unknown",
    phase: str = "unknown",
) -> ADKModel:
    """Return an ADK-compatible model for any provider."""
    provider, model = _resolve_model_string(model_string)

    if provider == PROVIDER_GOOGLE:
        return model or DEFAULT_MODEL

    # ``drop_params=True`` tells litellm to silently drop params a given model
    # rejects instead of raising, so a single provider quirk doesn't fail the
    # scan — e.g. GPT-5 reasoning models only accept ``temperature=1`` and error
    # on our ``temperature=0.0``. litellm consumes ``drop_params`` itself (it
    # never reaches the provider request body).
    #
    # ``reasoning_effort`` is set (only) for OpenAI gpt-5 reasoning models to
    # route their tool calls through the Responses API — see
    # ``_openai_reasoning_effort``. It rides along as an ``completion`` kwarg
    # (via ADK's ``_additional_args``) so litellm's Responses-API bridge sees it.
    name = model if provider == PROVIDER_LITELLM else f"{provider}/{model}"
    extra_args: dict[str, Any] = {}
    reasoning_effort = _openai_reasoning_effort(name)
    if reasoning_effort is not None:
        extra_args["reasoning_effort"] = reasoning_effort
    api_base = (
        os.getenv("OPENAI_BASE_URL")
        or os.getenv("OPENAI_API_BASE")
        or os.getenv("LITELLM_API_BASE")
    )
    if api_base:
        extra_args["api_base"] = api_base

    LiteLlm = _import_litellm()
    instance = LiteLlm(
       model=name,
       temperature=temperature,
       drop_params=True,
       **extra_args,
    )

    # Cloudflare Workers AI / OpenAI compatibility: ensure message contents are strings
    if hasattr(instance, "llm_client") and hasattr(instance.llm_client, "acompletion"):
        orig_acompletion = instance.llm_client.acompletion

        async def _acompletion_wrapper(**call_kwargs):
            if "messages" in call_kwargs and isinstance(call_kwargs["messages"], list):
                call_kwargs["messages"] = _sanitize_messages(call_kwargs["messages"])
            return await orig_acompletion(**call_kwargs)

        instance.llm_client.acompletion = _acompletion_wrapper

    return instance


def is_anthropic_model(model: ADKModel) -> bool:
    """Return True if *model* looks like an Anthropic / Claude model."""
    name = getattr(model, "model", str(model))
    return "anthropic" in name or "claude" in name


def is_openai_model(model: ADKModel) -> bool:
    """Return True if *model* looks like an OpenAI model."""
    name = getattr(model, "model", str(model))
    return "openai" in name or "gpt" in name


def apply_provider_limits(
    config: genai_types.GenerateContentConfig,
    model: ADKModel,
    top_p: float | None = None,
) -> None:
    """Adjust *config* in-place for provider-specific constraints.

    Anthropic models reject requests that set both ``temperature`` and
    ``top_p``.  This helper centralises that check so every scanner
    doesn't re-implement it.

    * If the model is **not** Anthropic and *top_p* is given, sets
      ``config.top_p``.
    * If the model **is** Anthropic, leaves ``top_p`` unset.
    """
    if not is_anthropic_model(model) and top_p is not None:
        config.top_p = top_p


def get_model_name(model_string: str | None = None) -> str:
    """Return the resolved model name for logging/metadata."""
    _, model = _resolve_model_string(model_string)
    return model


def _import_litellm() -> type[Any]:
    """Import and return the LiteLlm class from google-adk or a minimal shim."""
    try:
        from google.adk.models.lite_llm import (  # noqa: PLC0415 - deferred import cost
            LiteLlm,
        )

        return LiteLlm
    except ImportError:
        pass
    try:
        from google.adk.models import (  # noqa: PLC0415 - import fallback ladder
            LiteLlm,
        )

        return LiteLlm
    except ImportError:
        pass
    try:
        import litellm as _litellm  # noqa: F401, PLC0415

        class _LiteLlmShim:
            def __init__(self, model: str, **kwargs):
                self.model = model
                self._kwargs = kwargs

            def __repr__(self) -> str:
                return f"LiteLlm(model={self.model!r})"

        return _LiteLlmShim
    except ImportError as e:
        raise ImportError(
            "google-adk or litellm is required for non-Google providers. "
            "Run: pip install google-adk litellm"
        ) from e


# ── Single-pass completion ───────────────────────────────────────────────────


def complete_text(
    model: ADKModel,
    system_prompt: str,
    user_message: str,
    max_tokens: int = 8000,
    temperature: float = 0.0,
    top_p: float = 1.0,
) -> str | None:
    """Run a single-pass LLM completion via ``model.generate_content_async``.

    Bare model strings are still accepted (ADK allows them and callers outside
    ``make_model`` may pass one), but they bypass usage instrumentation, so
    ``make_model`` never produces one.
    """
    config = genai_types.GenerateContentConfig(
        system_instruction=system_prompt,
        temperature=temperature,
        max_output_tokens=max_tokens,
    )
    apply_provider_limits(config, model, top_p=top_p)
    contents = [
        genai_types.Content(
            role="user",
            parts=[genai_types.Part.from_text(text=user_message)],
        )
    ]

    if isinstance(model, str):
        model = Gemini(model=model)

    model_name = getattr(model, "model", str(model))

    async def _run() -> str | None:
        request = LlmRequest(
            model=model_name,
            contents=contents,
            config=config,
        )
        text = ""
        async for resp in model.generate_content_async(request):
            if resp.content and resp.content.parts:
                for part in resp.content.parts:
                    if hasattr(part, "text") and part.text:
                        text += part.text
        return text.strip() or None

    try:
        asyncio.get_running_loop()
        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, _run()).result(timeout=120)
    except RuntimeError:
        pass

    try:
        return asyncio.run(_run())
    except Exception as e:
        err_type = type(e).__name__
        safe_msg = _safe_error(e)
        # Show a concise one-liner; full details at DEBUG level.
        first_line = safe_msg.split("\n", 1)[0]
        logger.error("LLM call failed (%s): %s", err_type, first_line)
        logger.debug("LLM call failed (full): %s", safe_msg)
        return None
