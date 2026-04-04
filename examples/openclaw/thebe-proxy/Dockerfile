FROM python:3.12-slim

LABEL org.opencontainers.image.title="Thebe Proxy"
LABEL org.opencontainers.image.description="Agentic Guardian bridge service for OpenClaw"
LABEL org.opencontainers.image.source="https://github.com/delegant/agentic-guardian"

WORKDIR /app

# Install dependencies first (layer-cached unless requirements change).
COPY examples/openclaw/thebe-proxy/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy proxy source.
COPY examples/openclaw/thebe-proxy/main.py ./main.py

# Run as non-root user for defence-in-depth.
RUN useradd --no-create-home --shell /bin/false thebe
USER thebe

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
