# Lab S-Type (TXID / Port / Kaminsky / Rl1)

Lab nay mo phong nhom tan cong `S-type` trong POPS/DNS-CPM va cong tac phong thu `Rl1`.

## Noi dung bao phu

- `txid`: attacker brute-force TXID, source-port bi fix cung.
- `port`: attacker brute-force source-port va TXID trong khong gian nho.
- `kaminsky`: attacker brute-force TXID cho query ten con, source-port bi fix cung, va chen additional record cho `bank.com`.
- Cong tac phong thu: `Rl1` qua `toggle_defense.sh on|off`.
- Chi so do:
  - ASR tu `/app/result.txt`
  - do tre tu `/app/latency_ms.txt`

## Thiet ke do mac dinh

- Moi case chay `150` rounds neu khong truyen tham so khac.
- Truoc moi round, client gui query control `_flush.stype-control` de resolver clear cache, dam bao moi lan do la doc lap.
- Moi cua so attack dung ngan sach `RESPONSE_BUDGET=200` spoofed responses.
- `txid`:
  - brute-force: `TXID` tu `0..199`
  - fix cung: source-port resolver `33333`, qname `bank.com`
  - response/query window: `200 = 200 TXID x 1 port`
- `port`:
  - brute-force: source-port `33300..33319` va TXID `0..9`
  - fix cung: qname `bank.com`
  - response/query window: `200 = 20 port x 10 TXID`
- `kaminsky`:
  - brute-force: `TXID` tu `0..199`
  - fix cung: source-port resolver `33333`, trigger qname `victim.bank.com`
  - poison: additional record `bank.com -> 6.6.6.6`
  - response/query window: `200 = 200 TXID x 1 port`

## Chay nhanh

Mac dinh chay bien the `txid`:

```bash
docker info
bash ./scripts/run_case.sh baseline 150
bash ./scripts/run_case.sh attack-off 150
bash ./scripts/run_case.sh attack-on 150
```

Chon bien the tan cong:

```bash
ATTACK_VARIANT=txid bash ./scripts/run_case.sh attack-off 150
ATTACK_VARIANT=port bash ./scripts/run_case.sh attack-off 150
ATTACK_VARIANT=kaminsky bash ./scripts/run_case.sh attack-off 150
```

Chay defense:

```bash
ATTACK_VARIANT=kaminsky bash ./scripts/run_case.sh attack-on 150
```

Chay lan luot ca 3 bien the, moi bien the gom `baseline`, `attack-off`, `attack-on`:

```bash
bash ./scripts/run_all_cases.sh 150
```

Ket qua tung case duoc luu rieng trong:

```text
artifacts/<run_id>/<variant>/<case>/
```

## Giao dien chuan

- Runner: `./scripts/run_case.sh <baseline|attack-off|attack-on> [rounds]`
- Bien chinh: `ATTACK_VARIANT`, `RESPONSE_BUDGET`, `TXID_SPACE`, `PORT_BRUTE_BASE`, `PORT_BRUTE_SPACE`, `PORT_TXID_SPACE`, `ATTACK_RATE`, `POISON_IP`
- File ket qua trong client container:
  - `/app/result.txt`
  - `/app/latency_ms.txt`

## Ghi chu ve Rl1

Khi defense `off`, resolver co y su dung entropy yeu: TXID nho va/hoac port trong khong gian nho de attacker co the thang race.

Khi defense `on`, resolver mo phong Rl1 bang cach dung entropy day du hon cho request upstream va tra `TC=1` neu thay response khong khop voi truy van dang pending. Day la mo hinh lab de do tac dung defend on/off, khong phai mot trien khai IPS POPS doc lap.
