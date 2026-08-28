FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-scapy python3-dnslib dnsutils iproute2 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY auth_server.py /app/auth_server.py
CMD ["python3", "/app/auth_server.py"]
