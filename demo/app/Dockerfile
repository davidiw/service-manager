# Demo application image for the disposable local-ops kind cluster.
# Built by scripts/demo-cluster.sh in three flavours: v1, v2 and v2-broken.
FROM python:3.12-alpine

ARG VERSION=0.0.0
ARG BUILD=dev
ARG FAIL=0

LABEL org.opencontainers.image.title="local-ops demo-app" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${BUILD}" \
      org.opencontainers.image.source="file://demo/app"

ENV DEMO_VERSION=${VERSION} \
    DEMO_BUILD=${BUILD} \
    DEMO_CRASH_ON_START=${FAIL} \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY server.py /app/server.py

EXPOSE 8080
CMD ["python", "server.py"]
