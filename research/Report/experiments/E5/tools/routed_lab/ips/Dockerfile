FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential python3 python3-dev python3-pip python3-scapy \
    iptables iproute2 procps libnetfilter-queue1 libnetfilter-queue-dev \
    libnfnetlink0 libnfnetlink-dev tshark ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install --no-cache-dir NetfilterQueue
WORKDIR /app
COPY e5_v2_lib.py /app/e5_v2_lib.py
COPY wire.py /app/wire.py
COPY ips /app/ips
COPY ips/policy.py /app/policy.py
COPY ips/preflight.sh /app/preflight.sh
COPY ips/snapshot.sh /app/snapshot.sh
COPY ips/entrypoint.sh /app/entrypoint.sh
RUN find /app -type f -exec sed -i 's/\r$//' {} + \
    && chmod +x /app/*.sh /app/ips/*.sh \
    && mkdir -p /app/log /app/pcap
CMD ["/app/entrypoint.sh"]
