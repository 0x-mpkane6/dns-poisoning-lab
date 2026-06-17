# Lab R2 Entropy (Improved Fragment Defense)

Lab nay mo phong cai tien `Rl2`: thay vi thay fragment la chan ngay, resolver ghi nhan frag2 co `offset > 0`, luu vao bang JSONL, tinh entropy tren IPID trong cua so gan nhat, roi moi quyet dinh defend.

Muc tieu khong phai do `defense off`; lab nay tap trung chung minh `defense on` hoat dong nhu the nao va vi sao no tot hon R2 cu trong SFrag.

## Y tuong

- Frag1 duoc giu lai nhu response hop le tu auth server.
- Frag2 co `offset > 0` duoc luu vao `/app/frag2_events.jsonl`.
- Resolver tinh Shannon entropy theo IPID tren cap `src_ip -> dst_ip`.
- Neu sample du va entropy/unique-ratio cao, resolver coi do la flood doan IPID va tra `TC=1`.
- Neu chi co frag1 hop le va khong co frag2 flood, resolver `allow` thay vi block som.

## Cach chung minh tot hon R2 cu

R2 cu trong lab `sfrag/bfrag` block ngay khi thay frag1, nen phong thu duoc tan cong nhung de tao false positive voi luong fragmented hop le.

R2 entropy cai tien tao 2 bang chung:

- `benign-on`: co frag1 hop le, khong attacker. R2 cu se `tc_block_on_any_frag1`, R2 entropy ghi `new_r2_action=allow`.
- `attack-on`: attacker flood frag2 voi IPID hon loan. R2 entropy ghi entropy/unique-ratio cao va `new_r2_action=tc_block`.

Nhu vay minh chung duoc 2 y: van chan SFrag khi co dau hieu flood, nhung khong chan bua moi luong fragmentation.

## Chay nhanh

```bash
docker info
bash ./scripts/run_case.sh baseline 150
bash ./scripts/run_case.sh benign-on 150
bash ./scripts/run_case.sh attack-on 150
```

Chay ca 3 case lien tiep:

```bash
bash ./scripts/run_all_cases.sh 150
```

## Bien cau hinh

- `R2_MIN_SAMPLES`: so frag2 toi thieu truoc khi tinh nghi van.
- `R2_ENTROPY_THRESHOLD`: nguong Shannon entropy.
- `R2_UNIQUE_RATIO_THRESHOLD`: nguong ty le IPID unique.
- `FRAG2_WINDOW_SECONDS`: cua so thoi gian tinh entropy.
- `ATTACK_VARIANT=random`: flood IPID ngau nhien, phu hop de minh chung entropy defense.
- `ATTACK_VARIANT=fixed`: IPID co dinh, dung de cho thay entropy-only khong bat moi kieu tan cong.

## Artifacts

Sau moi case, ket qua duoc luu tai:

```text
artifacts/<run_id>/<case>/
```

Bao gom:

- `result.txt`: ket qua `bank.com` tung round.
- `latency_ms.txt`: latency tung round.
- `metrics.txt`: ASR va latency summary.
- `frag2_events.jsonl`: bang quan sat frag2.
- `r2_entropy_decisions.jsonl`: quyet dinh R2 entropy.
- `r2_entropy_summary.json`: snapshot tong hop cuoi case.
- `resolver.log`: log block/allow tu resolver.
- `attack.log`: log cua attacker neu case co attacker.

## Truong can trich trong bao cao

- `legacy_r2_action`: hanh vi cua R2 cu, mac dinh `tc_block_on_any_frag1`.
- `new_r2_action`: hanh vi cua R2 entropy, `allow` hoac `tc_block`.
- `samples`: so frag2 trong cua so quan sat.
- `unique_ipids`: so IPID khac nhau.
- `unique_ratio`: ty le IPID unique.
- `entropy`: Shannon entropy cua phan bo IPID.
- `avoids_legacy_false_positive`: true khi R2 entropy allow luong benign ma R2 cu se block.
- `blocks_entropy_flood`: true khi R2 entropy block flood co entropy cao.
