# syntax=docker/dockerfile:1
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY pyproject.toml ./
COPY app ./app
COPY tests ./tests
COPY verify ./verify

EXPOSE 8080

# App service. The verify service reuses this image with a command override:
#   python -m verify.run
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
