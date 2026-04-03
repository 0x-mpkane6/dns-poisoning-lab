#!/bin/bash

TARGET="example.com"
RESOLVER="10.10.0.53"

# xoá file cũ nếu có
rm -f result.txt

echo "[+] Start querying..."

for i in {1..100}
do
    dig @$RESOLVER $TARGET +short >> result.txt
done

echo "[+] Done. Saved to result.txt"