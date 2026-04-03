FROM ubuntu:22.04
RUN apt update && apt install -y dnsutils
WORKDIR /app
COPY test.sh /app/
CMD ["sleep", "infinity"]