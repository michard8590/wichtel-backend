FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd \
        --system \
        --gid 10001 \
        wichtel \
    && useradd \
        --system \
        --uid 10001 \
        --gid wichtel \
        --home-dir /app \
        --shell /usr/sbin/nologin \
        wichtel

WORKDIR /app

COPY requirements.txt .

RUN pip install \
        --no-cache-dir \
        --requirement requirements.txt

COPY --chown=wichtel:wichtel app ./app

RUN mkdir -p /app/data \
    && chown wichtel:wichtel /app/data

USER wichtel:wichtel

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
