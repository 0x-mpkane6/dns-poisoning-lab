FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends dnsutils gawk \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY test.sh /app/test.sh
RUN sed -i 's/\r$//' /app/test.sh && chmod +x /app/test.sh
CMD ["sleep", "infinity"]
