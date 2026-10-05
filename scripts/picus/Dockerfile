FROM ubuntu:24.04

ARG TARGETARCH
ARG PICUS_COMMIT=138b151d3a388e5b6c040c163e0a1db04f2ceda6
ARG CVC5_VERSION=1.4.1

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        racket git ca-certificates curl unzip libgmp10 libssl-dev python3 \
    && rm -rf /var/lib/apt/lists/*

RUN case "$TARGETARCH" in \
        arm64) cvc5_arch=arm64 ;; \
        amd64) cvc5_arch=x86_64 ;; \
        *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && curl -sL "https://github.com/cvc5/cvc5/releases/download/cvc5-${CVC5_VERSION}/cvc5-Linux-${cvc5_arch}-static.zip" -o /tmp/cvc5.zip \
    && unzip -q /tmp/cvc5.zip -d /tmp/cvc5 \
    && cp /tmp/cvc5/*/bin/cvc5 /usr/local/bin/cvc5 \
    && chmod +x /usr/local/bin/cvc5 \
    && rm -rf /tmp/cvc5 /tmp/cvc5.zip \
    && cvc5 --version | head -1

RUN raco pkg install --auto --no-docs rosette csv-reading graph

RUN git clone https://github.com/Veridise/Picus.git /Picus \
    && cd /Picus \
    && git checkout "$PICUS_COMMIT" \
    && raco make picus.rkt

WORKDIR /Picus
CMD ["/bin/bash"]
