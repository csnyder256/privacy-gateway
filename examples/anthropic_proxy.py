"""Anthropic client example. The existing API key header is forwarded to the fixed upstream."""

from anthropic import Anthropic

client = Anthropic(base_url="http://127.0.0.1:8787/proxy/anthropic/v1")
response = client.messages.create(
    model="claude-sonnet-4-5", max_tokens=100, messages=[{"role": "user", "content": "Email test@example.com"}]
)
print(response.content[0].text)
