FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m pip wheel --wheel-dir /wheels .

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PRIVACY_GATEWAY_DB=/data/privacy-gateway.db

RUN addgroup --system gateway && adduser --system --ingroup gateway gateway
COPY --from=builder /wheels /wheels
RUN python -m pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels
RUN mkdir /data && chown gateway:gateway /data

USER gateway
EXPOSE 8787
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/v1/health', timeout=2)"

CMD ["uvicorn", "privacy_gateway.api:app", "--host", "0.0.0.0", "--port", "8787", "--no-server-header"]
