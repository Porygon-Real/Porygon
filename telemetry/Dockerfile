FROM python:3.13.13-slim-bookworm

ARG SOURCE_COMMIT=unrecorded
ARG SOURCE_TREE_SHA256=unrecorded
ARG DEPENDENCY_LOCK_SHA256=unrecorded
LABEL org.opencontainers.image.revision=$SOURCE_COMMIT \
      com.porygon.source-tree-sha256=$SOURCE_TREE_SHA256 \
      com.porygon.dependency-lock-sha256=$DEPENDENCY_LOCK_SHA256

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN groupadd --gid 10003 porygon \
    && useradd --uid 10003 --gid porygon --create-home --shell /usr/sbin/nologin porygon

COPY pyproject.toml requirements.lock ./
COPY src ./src
COPY tests ./tests

RUN mkdir -p /var/lib/porygon /var/log/porygon \
    && pip install --no-cache-dir --require-hashes --only-binary=:all: -r requirements.lock \
    && pip install --no-cache-dir --no-deps --no-build-isolation ".[test]" \
    && pip check \
    && chown -R porygon:porygon /app /var/lib/porygon /var/log/porygon

USER 10003:10003

EXPOSE 8002

CMD ["uvicorn", "porygon_telemetry.main:app", "--host", "0.0.0.0", "--port", "8002", "--no-access-log"]
