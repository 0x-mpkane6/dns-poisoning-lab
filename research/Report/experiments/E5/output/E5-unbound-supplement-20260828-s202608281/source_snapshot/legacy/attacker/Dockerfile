FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-scapy python3-dnslib iproute2 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY sender.py /app/sender.py
CMD ["sleep", "infinity"]
