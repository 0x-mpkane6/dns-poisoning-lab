"""Generate a plain-Vietnamese E2 report from a validated confirmatory artifact."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def fmt(value: float) -> str:
    return f"{value:.3f}"


def effect_sentence(effect: dict) -> str:
    result = effect["result"]
    verdict = effect["verdict"]
    meanings = {
        "meaningful_added_discrimination": "B5 có thêm ích lợi rõ ràng theo cổng đã đăng ký trước.",
        "practical_equivalence_within_registered_margin": (
            "Trong dữ liệu này, B5 và B2 gần như tương đương trong biên ±0,05 đã đăng ký trước."
        ),
        "meaningful_degradation": "B5 kém hơn B2 rõ ràng theo cổng đã đăng ký trước.",
        "inconclusive": "Chưa đủ bằng chứng để kết luận B5 tốt hơn, tương đương hay kém hơn B2.",
    }
    return (
        f"ΔJ trung bình = {result['mean']:+.3f}, CI 95% [{result['ci95'][0]:+.3f}, "
        f"{result['ci95'][1]:+.3f}]. {meanings[verdict]}"
    )


def table_for(rows: list[dict], attack: str) -> list[str]:
    selected = sorted([row for row in rows if row["attack_condition"] == attack],
                      key=lambda row: int(row["level"]))
    lines = [
        "| Tải | B2: benign bị bật | B2: condition attack bị bật | B5: benign bị bật | B5: condition attack bị bật | ΔJ (B5−B2), 95% CI |",
        "|---:|---:|---:|---:|---:|---:|",
    ]
    for row in selected:
        b2 = row["variants"]["volume"]
        b5 = row["variants"]["combined"]
        delta = row["delta_j_combined_minus_volume"]
        lines.append(
            f"| {row['level']} | {fmt(b2['benign_trigger']['mean'])} | "
            f"{fmt(b2['attack_alert']['mean'])} | {fmt(b5['benign_trigger']['mean'])} | "
            f"{fmt(b5['attack_alert']['mean'])} | {fmt(delta['mean'])} "
            f"[{fmt(delta['ci95'][0])}, {fmt(delta['ci95'][1])}] |"
        )
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description="Write an easy-to-read E2 report")
    parser.add_argument("artifact_dir", type=Path)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    artifact_dir = args.artifact_dir.resolve()
    validation = json.loads((artifact_dir / "validation.json").read_text(encoding="utf-8"))
    if validation.get("status") != "PASS":
        raise RuntimeError("refusing to write a main E2 report before validation PASS")
    results = json.loads((artifact_dir / "e2_results.json").read_text(encoding="utf-8"))
    meta = results["meta"]
    analysis = results["analysis"]
    effects = {item["attack_condition"]: item for item in analysis["macro_effects"]}
    rows = analysis["test_cells"]
    output = (args.out or artifact_dir / "E2_BAO_CAO_CHINH_XAC_DE_HIEU.md").resolve()
    if output.exists() and not args.overwrite:
        raise FileExistsError(output)

    lines = [
        "# E2 — Kiểm tra B5 có hơn B2 khi cùng tải hay không",
        "",
        f"**Run ID:** `{meta['run_id']}`  ",
        f"**Trạng thái kiểm tra:** `{validation['status']}`  ",
        "**Phạm vi:** mô phỏng có kiểm soát theo thời điểm query. Đây không phải thí nghiệm IP fragment thật; "
        "không đo poisoning, ASR, độ trễ, CPU hay hiệu năng triển khai.",
        "",
        "## E2 đang trả lời câu hỏi gì?",
        "",
        "B2 chỉ nhìn vào **số fragment** trong 2 giây. B5 chỉ bật khi đồng thời đủ số fragment, entropy cao "
        "và tỉ lệ IPID khác nhau cao. E2 hỏi rất đơn giản: nếu benign và condition stress có đúng cùng lịch "
        "timestamp, hai dấu hiệu entropy/unique ratio có giúp B5 phân biệt tốt hơn B2 không?",
        "",
        "## Cách chạy dễ hiểu",
        "",
        f"- Có {meta['split_runs']['test']} lần chạy độc lập cho mỗi ô kết quả chính (test), mỗi lần "
        f"{meta['queries_per_run']} lần chấm điểm.",
        "- Mỗi benign/attack pair dùng chung hoàn toàn thời điểm FRAG2 và thời điểm query. Vì vậy số mẫu trong "
        "từng cửa sổ là như nhau; khác biệt nếu có chỉ đến từ IPID/origin chứ không phải tải.",
        "- Trước test có một split kiểm tra generator và một split validation riêng. Test không được dùng để chọn "
        "ngưỡng hay chỉnh tốc độ.",
        "- Mỗi run giữ raw JSONL: event FRAG2, IPID, origin, timestamp, feature và quyết định B1–B5. Validator "
        "đã đọc lại toàn bộ raw và tính lại các số trong bảng.",
        "",
        "## Cách đọc số",
        "",
        "- **Benign bị bật**: rule bật trên traffic benign control. Số thấp hơn là tốt hơn về mặt tránh TC/TCP không cần thiết.",
        "- **Condition attack bị bật**: rule bật trong condition stress tổng hợp. Đây chỉ là detector alert rate, **không phải** "
        "tỉ lệ ngăn poisoning thành công.",
        "- **J** = condition attack bị bật − benign bị bật. J càng cao thì rule càng tách được hai condition trong mô phỏng này.",
        "- **ΔJ (B5−B2)** dương nghĩa là B5 tách tốt hơn B2; âm nghĩa là kém hơn. Khoảng 95% cho biết độ dao động giữa các run pair.",
        "",
        "## Kết quả chính: sweep IPID liên tục",
        "",
        effect_sentence(effects["attack_sweep_continuous"]),
        "",
        *table_for(rows, "attack_sweep_continuous"),
        "",
        "## Kết quả hỗ trợ: sweep IPID bursty",
        "",
        effect_sentence(effects["attack_sweep_bursty"]),
        "",
        *table_for(rows, "attack_sweep_bursty"),
        "",
        "## Các trường hợp cần nhìn như giới hạn",
        "",
        "- `attack_random_continuous` là negative control: IPID random có thể giống benign về phân phối.",
        "- `attack_fixed_continuous` và `attack_dup_sweep_continuous` là failure probe của detector: chúng chỉ cho biết "
        "rule bật hay không trong dòng IPID tổng hợp. Không được suy ra ASR, BFrag coverage hay poisoning success.",
        "- Nếu B5 bằng B2 trong nhiều ô, kết quả đúng là: entropy và unique ratio chưa đóng góp thêm ở những regime đó. "
        "Đó là một kết quả nghiên cứu hữu ích, không phải lỗi cần che đi.",
        "",
        "## Điều E2 chưa thể kết luận",
        "",
        "E2 chưa chứng minh rule mới cải thiện hiệu năng hệ thống hoặc vẫn giữ nguyên độ an toàn của POPS Rℓ2. Muốn "
        "kết luận như vậy cần E5: IP fragmentation thật, resolver thật, TC→TCP đầy đủ, và đo attack outcome/latency/CPU.",
        "",
        "## File để kiểm tra lại",
        "",
        "- `e2_protocol.json`: thiết kế đã khóa trước khi chạy.",
        "- `e2_runs.csv`, `e2_decisions.csv.gz`, `raw_runs/`: số liệu gốc theo run/event.",
        "- `e2_results.json`, `e2_summary.csv`: tổng hợp chỉ từ test split.",
        "- `validation.json`: kết quả kiểm tra raw → bảng; phải là PASS trước khi dùng báo cáo này.",
    ]
    mode = "w" if args.overwrite else "x"
    with output.open(mode, encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines) + "\n")
    print(f"[+] wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
