"""OpenAI-compatible client example. Use fake data until verification passes."""

from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:8787/proxy/openai/v1")
response = client.responses.create(model="gpt-4.1-mini", input="Email test@example.com")
print(response.output_text)
