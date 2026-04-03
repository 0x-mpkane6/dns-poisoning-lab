FROM ubuntu:22.04
RUN apt update && apt install -y unbound
COPY unbound.conf /etc/unbound/unbound.conf
CMD ["unbound", "-d"]
