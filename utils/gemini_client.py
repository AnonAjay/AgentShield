# utils/gemini_client.py

from typing import Optional
import os
import asyncio

from dotenv import load_dotenv
import google.genai as genai

load_dotenv()

DEFAULT_MODEL = "gemini-2.5-flash"

_client: Optional[genai.Client] = None


def get_client() -> genai.Client:
    """
    Returns a singleton Gemini client.
    Requires GEMINI_API_KEY to be set in the environment (or .env).
    """
    global _client
    if _client is None:
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY is not set. Put it in .env or env vars.")
        _client = genai.Client(api_key=api_key)
    return _client


async def generate_text(
    prompt: str,
    model: str = DEFAULT_MODEL,
) -> str:
    """
    Simple wrapper for free-form text generation.
    Uses thread offloading because SDK call is synchronous.
    """
    client = get_client()

    def _call():
        return client.models.generate_content(
            model=model,
            contents=[{"role": "user", "parts": [{"text": prompt}]}],
        )

    response = await asyncio.to_thread(_call)
    return response.text


async def call_agent_with_system_and_user(
    system_prompt: str,
    user_prompt: str,
    model: str = DEFAULT_MODEL,
) -> str:
    """
    Common helper for your agents:
    sends 'system_prompt' + 'user_prompt' together to Gemini.
    """
    client = get_client()
    combined = f"System Instructions: {system_prompt}\n\nUser Query: {user_prompt}"

    def _call():
        return client.models.generate_content(
            model=model,
            contents=[{"role": "user", "parts": [{"text": combined}]}],
        )

    response = await asyncio.to_thread(_call)
    return response.text
