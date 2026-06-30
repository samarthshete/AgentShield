FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AGENTSHIELD_DB_PATH=/data/agentshield.db \
    AGENTSHIELD_OUTPUT_DIR=/data/reports

WORKDIR /app

COPY pyproject.toml README.md ./
COPY agentshield ./agentshield
COPY benchmarks ./benchmarks

RUN pip install --no-cache-dir .

EXPOSE 8000

CMD ["uvicorn", "agentshield.web.app:app", "--host", "0.0.0.0", "--port", "8000"]
