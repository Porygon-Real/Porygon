# Porygon Training Workload Container Image
# Recipe for porygon-training-workload:latest
# Pinned Alpine base image by digest:
FROM alpine@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

RUN apk update && apk add --no-cache \
    bash \
    sudo \
    util-linux \
    libcap \
    gcc \
    musl-dev \
    netcat-openbsd \
    curl \
    wget \
    procps \
    coreutils

# Create non-root test user for privilege escalation canary scenarios
RUN adduser -D -s /bin/bash canary && \
    echo "canary ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

WORKDIR /app
CMD ["sleep", "infinity"]
