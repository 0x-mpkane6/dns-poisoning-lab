# E5 — Cách dựng routed lab

**Lab duy nhất của E5:** `tools/routed_lab`  
**Protocol đang freeze:** `E5-routed-s20260902-r001`  
**Resolver:** Unbound 1.26.1, build từ `tools/unbound/`

Đây là tài liệu dựng testbed. Số liệu confirmatory nằm ở
[`E5_report.md`](E5_report.md). Thứ tự chạy campaign nằm ở
[`E5_RUNBOOK.md`](E5_RUNBOOK.md). Hằng số khóa nằm ở
[`e5_protocol.json`](e5_protocol.json).

Không dùng lab Unbound cũ (resolver-local poisoner / marker C0–C4). Cây đó
đã xóa. Không pool E5 với E1–E4. Không retune `B5=(8, 6.0, 0.90)`.

## 1. Topology

Hai Docker bridge. IPS là router hai interface; mọi packet giữa resolver và
auth/attacker phải đi qua IPS.

```
frontnet 10.81.0.0/24                         upnet 10.82.0.0/24
gateway  10.81.0.254                          gateway  10.82.0.254

 client          resolver         IPS              auth           attacker
10.81.0.10      10.81.0.53     10.81.0.1          10.82.0.100     10.82.0.200
                                  |
                               10.82.0.1
```

Luồng một trial:

1. Client gửi query UDP tới Unbound (`10.81.0.53`).
2. Unbound query stub `bank.com.` tới auth (`10.82.0.100`) qua IPS.
3. Auth trả UDP fragmented (legitimate `203.0.113.80`), rồi notify attacker
   trên cổng `9999`. Auth không gửi forged packet.
4. Attacker là process duy nhất gửi forged tail (`6.6.6.6`), cùng IPID/port
   với first fragment, cũng phải đi qua IPS.
5. TCP/53 của auth luôn trả legitimate unfragmented answer; đó là đường
   fallback khi policy inject `TC=1`.

## 2. Thành phần

| Container | Vai trò | Không làm |
| --- | --- | --- |
| `client` | Unique qname, cache-before/after, deadline 2 s | Không gửi fragment |
| `resolver` | Unbound 1.26.1 + python module log + cache probe `:10053` | Không poison cache |
| `ips` | `ip_forward=1`, iptables `FORWARD` → NFQUEUE 5, AF_PACKET quan sát fragment trước defrag, PCAPNG hai phía | Không có fallback non-NFQUEUE |
| `auth` | UDP fragmented + TCP sạch + notify attacker | Không gửi poison |
| `attacker` | Một process forged-tail, replay schedule | Không đứng cạnh resolver |

Policy IPS khóa trong `tools/routed_lab/ips/policy.py`: `N=8`, `H=6.0`,
`U=0.90`, cửa sổ 2 s. Đây là hằng số, không đọc lại từ env để khỏi retune
nhầm E3.

Routing cố định khi container lên:

- resolver: `10.82.0.0/24 via 10.81.0.1`
- auth và attacker: `10.81.0.0/24 via 10.82.0.1`

## 3. Chuẩn bị máy

Cần Docker Engine/Desktop đang chạy, kernel container hỗ trợ NFQUEUE
(`libnetfilter_queue`). Preflight abort nếu bind queue thất bại; lab không
tự chuyển sang lọc trong Unbound.

Source Unbound **không** nằm trong Git (xem `.gitignore`). Đặt đúng bản
1.26.1 vào `research/Report/experiments/E5/tools/unbound/` sao cho
`configure.ac` có `VERSION_MAJOR/MINOR/MICRO = 1/26/1`. Compose mount cây
này qua build context `unbound_src`:

```powershell
git clone --branch release-1.26.1 --depth 1 https://github.com/NLnetLabs/unbound.git research/Report/experiments/E5/tools/unbound
```

Hash cây Unbound được ghi vào `registered.json` khi freeze. Đổi source sau
khi register thì runner từ chối chạy tiếp trên cùng run id.

Image resolver compile Unbound trong Docker (`--with-pythonmodule`). Image
IPS cài `NetfilterQueue` + Scapy. Build context là thư mục E5
(`research/Report/experiments/E5`), không phải repo root.

## 4. Cách dựng và chạy

Không `docker compose up` thủ công để lấy số liệu. Compose thiếu schedule
replay và mount artifact từng cell. File `compose.yaml` chỉ để debug image.

Từ **root repo `Code/`**:

```powershell
python research/Report/experiments/E5/run_e5.py --stage preflight
python research/Report/experiments/E5/run_e5.py --stage pilot
python research/Report/experiments/E5/run_e5.py --stage sanity
python research/Report/experiments/E5/run_e5.py --stage confirmatory
```

Runner làm các việc sau:

1. Snapshot source + hash Unbound + image digest vào `output/<run-id>/`.
2. Preflight: NFQUEUE bind, routing, packet counter.
3. Mỗi cell: recreate stack, mount schedule read-only, ghi raw, derive
   `metrics.json`, chạy validator.
4. Confirmatory chỉ mở khi pilot PASS, preflight PASS, sanity 16/16 PASS.

Campaign đã freeze dùng run id `E5-routed-s20260902-r001`. Chạy lại trên
đúng id đó sẽ fail source-guard vì cây live đã đổi tên module. Campaign mới
cần `--run-id` mới.

## 5. Ánh xạ file

| File | Việc gì |
| --- | --- |
| `tools/routed_lab/compose.yaml` | Năm service, hai mạng, địa chỉ IP |
| `tools/routed_lab/ips/` | NFQUEUE, B5, TC inject, preflight |
| `tools/routed_lab/resolver/` | Dockerfile Unbound, `unbound.conf`, `e5mod.py` |
| `tools/routed_lab/auth/auth_server.py` | Legitimate fragment + notify |
| `tools/routed_lab/attacker/attacker.py` | Forged tail |
| `tools/routed_lab/wire.py` | DNS/IPv4 fragment helpers |
| `run_e5.py` | Freeze, recreate, validate |
| `e5_lib.py` | Policy/decision thuần, không wire |
| `output/<run-id>/source_snapshot/` | Code đúng bản đã chạy (có thể còn tên module cũ) |
| `output/<run-id>/raw/` | Evidence từng run; không đưa lên Git |

Raw local gồm jsonl, pcapng, firewall rules. Git chỉ giữ JSON tóm tắt
(`registered.json`, `validation_*.json`, `aggregate_confirmatory.json`,
`metrics_confirmatory.json`) và `source_snapshot/`.
