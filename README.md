# DNS OoB Poisoning Lab (Controlled Resolver + Rl3 Defense)

Lab nay tai hien tan cong DNS cache poisoning theo huong Out-of-Bailiwick (OoB), sau do bat/tat rule phong thu Rl3 de so sanh ket qua.

## 1) Topology

- `client` (`10.10.0.10`): gui DNS query de kich hoat resolver.
- `resolver` (`10.10.0.53`): resolver mo phong co cache va che do phong thu `Rl3` bat/tat duoc.
- `auth` (`10.10.0.100`): authoritative DNS cho zone `example.net`.
- `attacker` (`10.10.0.200`): blind flood spoofed DNS response kem additional OoB.

Network chung: `dnsnet` (`10.10.0.0/24`).

## 2) Chuan bi

```bash
docker compose up -d --build
```

Kiem tra container:

```bash
docker compose ps
```

## 3) Test baseline (khong co attacker)

Tat defense:

```bash
docker exec -it resolver bash /app/toggle_defense.sh off
```

Trigger query:

```bash
docker exec -it client bash /app/test.sh example.net 10
```

Do ket qua:

```bash
cd scripts
./measure.sh
```

Ky vong baseline: `bank.com` ra IP that (`203.0.113.80`), khong bi `6.6.6.6`.

## 4) Chay tan cong OoB (Defense OFF)

Terminal 1 (attacker):

```bash
docker exec -it attacker python3 /app/spoof.py
```

Terminal 2 (client trigger):

```bash
docker exec -it client bash /app/test.sh example.net 50
```

Do ket qua:

```bash
cd scripts
./measure.sh
```

Ky vong: ti le `6.6.6.6` cao khi defense OFF.

## 5) Bat Rl3 va test lai

Bat defense:

```bash
docker exec -it resolver bash /app/toggle_defense.sh on
```

Chay lai attacker + trigger:

```bash
docker exec -it client bash /app/test.sh example.net 50
cd scripts
./measure.sh
```

Ky vong: OoB records bi chan, ti le poison giam manh (ve gan 0).

## 6) Reset lab

```bash
cd scripts
./reset.sh
```

## 7) File chinh

Mo hinh co chu y de tai hien de dang:

- Resolver forward query bang source-port co dinh `33333`.
- TXID chi nam trong khong gian nho (`0..1023`).
- Attacker flood response gia mao cho TXID range de thang race.

- `resolver/resolver.py`: resolver co cache va logic Rl3.
- `resolver/toggle_defense.sh`: bat/tat Rl3 (`on` / `off`).
- `auth/auth_server.py`: authoritative DNS server cho `example.net`.
- `attacker/scripts/spoof.py`: inject additional OoB (`bank.com -> 6.6.6.6`).
- `client/test.sh`: trigger query va ghi ket qua `bank.com`.
- `scripts/measure.sh`: tinh tong so mau va success rate poison.
