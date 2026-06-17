```text
 ____  __ _  ____     ___   __    ___  _  _  ____    ____   __  __  ____   __   __ _  __  __ _   ___    __     __   ____ 
(    \(  ( \/ ___)   / __) / _\  / __)/ )( \(  __)  (  _ \ /  \(  )/ ___) /  \ (  ( \(  )(  ( \ / __)  (  )   / _\ (  _ \
 ) D (/    /\___ \  ( (__ /    \( (__ ) __ ( ) _)    ) __/(  O ))( \___ \(  O )/    / )( /    /( (_ \  / (_/\/    \ ) _ (
(____/\_)__)(____/   \___)\_/\_/ \___)\_)(_/(____)  (__)   \__/(__)(____/ \__/ \_)__)(__)\_)__) \___/  \____/\_/\_/(____/
```

# DNS CACHE POISONING LAB 

## 1. Tổng quan 
Repository này xây dựng một môi trường lab có kiểm soát nhằm mô phỏng lại các cuộc tấn công **DNS Cache Poisoning** kinh điển, đồng thời đánh giá khả năng phát hiện và phòng thủ của hệ thống **POPS (POisoning Prevention System)**.

POPS là một cơ chế phòng thủ được đề xuất trong bài báo [**“POPS: From History to Mitigation of DNS Cache Poisoning Attacks”**](https://www.usenix.org/conference/usenixsecurity25/presentation/afek) tại USENIX Security 2025. Hệ thống này tiếp cận bài toán DNS Cache Poisoning theo hướng nhận diện các dấu hiệu hành vi đặc trưng của từng nhóm tấn công, thay vì chỉ phụ thuộc vào chữ ký cố định của từng lỗ hổng riêng lẻ.

Trong phạm vi repository này, lab tập trung mô phỏng [**các nhóm tấn công DNS Cache Poisoning**](./docs/pops-attack.md) được đề cập trong bài báo:
* **S-type attacks**: nhóm tấn công thống kê dựa trên việc brute-force **TXID** hoặc **source port**, bao gồm TXID brute-force, source port brute-force và Kaminsky-style attack.
* **Fragmentation-based attacks**: nhóm tấn công lợi dụng cơ chế phân mảnh IP để chèn fragment độc hại vào DNS response.
* **Out-of-Bailiwick attacks**: nhóm tấn công chèn các bản ghi DNS nằm ngoài phạm vi thẩm quyền của name server được truy vấn.

Tương ứng với các nhóm tấn công trên, lab triển khai và đánh giá [**3 quy tắc phát hiện (Rℓ)**](./docs/pops-rules.md) trong Detection Module của POPS:

* **Rule 1 (R1)**: phát hiện hành vi đoán quá mức TXID hoặc source port thông qua số lượng DNS response bất thường trong một cửa sổ thời gian ngắn.
* **Rule 2 (Rℓ2)**: phát hiện và xử lý các DNS response bị phân mảnh nhằm ngăn tấn công dựa trên IP fragmentation.
* **Rule 3 (Rℓ3)**: phát hiện các DNS response chứa bản ghi vi phạm nguyên tắc bailiwick.


Ngoài việc mô phỏng các cơ chế trong bài báo, respontory cũng đề xuất một cải tiến cho **Rule 2 (Rℓ2)** đối với nhóm tấn công fragmentation. Thay vì chặn ngay mọi luồng DNS fragment, cơ chế cải tiến theo dõi các fragment có `offset > 0`, ghi nhận các đặc trưng như `địa chỉ nguồn, địa chỉ đích, IPID và offset`, sau đó tính entropy phân bố IPID trong một cửa sổ thời gian. 

Hướng tiếp cận này nhằm giảm false positive với các luồng fragment hợp lệ, đồng thời vẫn phát hiện được dấu hiệu flood IPID bất thường trong tấn công **SFrag**.


> Repository này chỉ phục vụ mục đích học thuật, nghiên cứu và mô phỏng trong môi trường local/isolated lab. Không sử dụng các script hoặc kỹ thuật trong repository để tấn công hệ thống thật.

## 2. Cấu trúc dự án

Repository được tổ chức thành ba nhóm chính: tài liệu tham khảo, mã nguồn lab mô phỏng và kết quả thực nghiệm.

```text
dns-poisoning-lab/
├── docs/        # Paper gốc, ghi chú POPS rules và mapping attack/rule
├── labs/        # Các lab mô phỏng DNS Cache Poisoning bằng Docker
├── artifacts/   # Kết quả thực nghiệm: metrics, log, latency, output
├── README.md    
```

Trong đó, thư mục `labs/` chứa các môi trường mô phỏng độc lập cho từng nhóm tấn công:

```text
labs/
├── base/        # Script dùng chung cho các lab
├── stype/       # TXID brute-force, source port brute-force, Kaminsky-style
├── sfrag/       # Fragmentation attack dạng SFrag
├── bfrag/       # Fragmentation attack dạng BFrag
├── oob/         # Out-of-bailiwick poisoning 
└── r2entropy/   # Cải tiến Rl2 dựa trên entropy IPID
```

Mỗi lab thường bao gồm các thành phần cơ bản như `client`, `resolver`, `auth`, `attacker` và `scripts`. Kết quả sau khi chạy được lưu trong `artifacts/`, bao gồm các file metrics, log, latency và kết quả truy vấn để phục vụ phân tích lại.

### 2.1. Topology chung của mỗi lab

Mỗi lab được triển khai trong một Docker bridge network riêng, nhưng đều dùng cùng mô hình 4 thành phần:

```text
                           DNS query
                    +-------------------+
                    |                   v
+----------+     +----------+     +------------+
|  client  | --> | resolver | --> |    auth    |
| .0.10    |     | .0.53    |     |   .0.100   |
+----------+     +----------+     +------------+
                      ^
                      |
                      | spoofed DNS response /
                      | forged frag2 / OoB record
                +------------+
                |  attacker  |
                |   .0.200   |
                +------------+
```

Vai trò của từng thành phần:

| Thành phần | Vai trò |
| --- | --- |
| `client` | Gửi DNS query để kích hoạt cache miss và ghi kết quả đo. |
| `resolver` | Resolver mô phỏng, có cache và logic bật/tắt rule phòng thủ. |
| `auth` | Authoritative DNS server hợp lệ, trả lời bản ghi DNS thật. |
| `attacker` | Gửi DNS response giả mạo hoặc fragment giả để thử poisoning. |

Các lab dùng subnet riêng để tránh xung đột khi chạy độc lập:

| Lab | Subnet | Client | Resolver | Auth | Attacker | Rule chính |
| --- | --- | --- | --- | --- | --- | --- |
| `oob` | `10.20.0.0/24` | `10.20.0.10` | `10.20.0.53` | `10.20.0.100` | `10.20.0.200` | `Rl3` |
| `sfrag` | `10.30.0.0/24` | `10.30.0.10` | `10.30.0.53` | `10.30.0.100` | `10.30.0.200` | `Rl2` |
| `bfrag` | `10.40.0.0/24` | `10.40.0.10` | `10.40.0.53` | `10.40.0.100` | `10.40.0.200` | `Rl2` |
| `stype` | `10.50.0.0/24` | `10.50.0.10` | `10.50.0.53` | `10.50.0.100` | `10.50.0.200` | `Rl1` |
| `r2entropy` | `10.60.0.0/24` | `10.60.0.10` | `10.60.0.53` | `10.60.0.100` | `10.60.0.200` | `Rl2` cải tiến |

Luồng đo cơ bản:

```text
1. client gửi truy vấn DNS đến resolver.
2. resolver tạo cache miss và hỏi auth.
3. attacker cố gửi response giả mạo để thắng race hoặc chèn dữ liệu độc.
4. resolver xử lý response theo trạng thái defense on/off.
5. client truy vấn lại bank.com và ghi nhận kết quả:
   - 203.0.113.80: kết quả hợp lệ
   - 6.6.6.6: kết quả bị poisoning
```

## 3. Quick Start

Yêu cầu môi trường:

```text
Docker / Docker Desktop
Docker Compose
Bash shell hoặc WSL/Linux
```

Chọn một lab cần chạy:

```bash
cd labs/<lab-name>
```

Ví dụ:

```bash
cd labs/stype
```

Nếu chạy trên WSL/Linux sau khi chỉnh file từ Windows, nên chuẩn hóa line ending:

```bash
dos2unix ../base/scripts/*.sh scripts/*.sh client/test.sh resolver/toggle_defense.sh
```

Build lại image:

```bash
docker-compose down -v --remove-orphans
docker-compose build
```

Chạy toàn bộ case của lab:

```bash
bash ./scripts/run_all_cases.sh
```

Hoặc chạy từng case riêng:

```bash
bash ./scripts/run_case.sh baseline
bash ./scripts/run_case.sh attack-off
bash ./scripts/run_case.sh attack-on
```

Với `r2entropy`, các case chính là:

```bash
bash ./scripts/run_case.sh baseline
bash ./scripts/run_case.sh benign-on
bash ./scripts/run_case.sh attack-on
```

Kết quả sau khi chạy được lưu trong:

```text
artifacts/
```

---

## TÀI LIỆU THAM KHẢO

[1] Y. Afek, H. Berger, and A. Bremler-Barr, “[POPS: From History to Mitigation of DNS Cache Poisoning Attacks](https://www.usenix.org/conference/usenixsecurity25/presentation/afek),” in *Proceedings of the 34th USENIX Security Symposium (USENIX Security 25)*, Seattle, WA, USA: USENIX Association, Aug. 2025, pp. 3537–3556.
