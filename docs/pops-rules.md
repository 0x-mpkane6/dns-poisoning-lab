# POPS/DNS-CPM Rule Mapping

Tai lieu ngan nay dung de map cac lab trong repo voi nhom tan cong va rule phong thu trong paper POPS/DNS-CPM.

## Attack Families

| Paper family | Lab folder | Defense rule | Noi dung mo phong |
| --- | --- | --- | --- |
| `S` | `labs/stype` | `Rl1` | TXID brute-force, source-port brute-force, Kaminsky-style race |
| `SFrag` | `labs/sfrag` | `Rl2` | Doan IPID va chen frag2 gia |
| `BFrag` | `labs/bfrag` | `Rl2` | Biet truoc IPID muc tieu va chen frag2 gia |
| `SFrag/R2 variant` | `labs/r2entropy` | `Rl2 entropy` | Ghi nhan frag2 offset > 0, tinh entropy IPID, chi block khi co dau hieu flood hon loan |
| `SOoB` | `labs/oob` | `Rl3` | Out-of-bailiwick additional record poisoning |

## Rule Notes

- `Rl1`: phat hien race/spoofing trong nhom S-type. Lab `stype` mo phong bang cach so khop response voi truy van pending, TXID va qname; khi defense on thi dung entropy manh hon va tra `TC=1` neu thay response dang ngo.
- `Rl2`: phat hien luong fragmentation dang ngo. Cac lab `sfrag` va `bfrag` mo phong fragment bang marker `TYPE=FRAG1/FRAG2` va `IPID`, sau do tra `TC=1` khi defense on.
- `Rl3`: phat hien record ngoai bailiwick. Lab `oob` chi cache record nam trong bailiwick khi defense on va tra `TC=1` khi thay record ngoai bailiwick.

## Caveat

Day la cac lab mo phong co chu dich lam yeu entropy de do ASR va so sanh defend on/off. Code phong thu duoc nhung trong resolver cua tung lab, chua phai mot POPS/IPS doc lap quan sat traffic ben ngoai resolver.
