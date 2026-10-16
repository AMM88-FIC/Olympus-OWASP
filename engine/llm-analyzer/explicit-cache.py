"""
Explicitly cache a system prompt + schema (each loaded from a file)
in the Gemini API.

Setup:
    pip install google-genai
    export GEMINI_API_KEY="your-key"

Usage:
    python gemini_cache.py system_prompt.txt schema.json
"""

import os
import sys
from google import genai
from google.genai import types

client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])

MODEL = "gemini-2.5-flash"


def load(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def create_cache(system_prompt: str, schema: str) -> str:
    """Create the explicit cache and return its handle (cache.name)."""
    cache = client.caches.create(
        model=MODEL,
        config=types.CreateCachedContentConfig(
            display_name="system_prompt_and_schema",
            system_instruction=system_prompt,   # cached as system instruction
            contents=[schema],                  # cached as content
            ttl="3600s",                         # keep alive 1 hour
        ),
    )
    print(f"Cache created: {cache.name}")
    print(f"Cached tokens: {cache.usage_metadata.total_token_count}")
    return cache.name


def ask(cache_name: str, user_input: str):
    """Send a request that reuses the cached content."""
    response = client.models.generate_content(
        model=MODEL,
        contents=user_input,
        config=types.GenerateContentConfig(cached_content=cache_name),
    )
    print(response.text)
    print(f"(cached tokens hit: {response.usage_metadata.cached_content_token_count})")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("Usage: python gemini_cache.py <system_prompt_file> <schema_file>")

    system_prompt = load(sys.argv[1])
    schema = load(sys.argv[2])

    name = create_cache(system_prompt, schema)
    ask(name, "Extract: Jane Doe, jane@example.com, interested in AI and biology.")