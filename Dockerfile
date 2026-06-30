FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AGENTSHIELD_DB_PATH=/data/agentshield.db \
    AGENTSHIELD_OUTPUT_DIR=/data/reports \
    AGENTSHIELD_CORS_ORIGINS=http://127.0.0.1:5173,http://localhost:5173,http://127.0.0.1:8080,http://localhost:8080

WORKDIR /app

COPY pyproject.toml README.md ./
COPY agentshield ./agentshield
COPY benchmarks ./benchmarks

RUN pip install --no-cache-dir .

EXPOSE 8000

CMD ["uvicorn", "agentshield.web.app:app", "--host", "0.0.0.0", "--port", "8000"]
